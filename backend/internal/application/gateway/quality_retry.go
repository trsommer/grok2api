package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/domain/audit"
	inferencedomain "github.com/chenyme/grok2api/backend/internal/domain/inference"
	modeldomain "github.com/chenyme/grok2api/backend/internal/domain/model"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
	neterrorpkg "github.com/chenyme/grok2api/backend/internal/pkg/neterror"
)

const (
	ErrorQualityDegraded             = "quality_degraded"
	qualityRetryFailOpen             = "fail_open"
	qualityRetryFailClosed           = "fail_closed"
	defaultQualityMaxAttempts        = 6
	defaultQualityHoldTimeout        = 30 * time.Second
	defaultQualityMinOutput          = int64(8)
	defaultMissingThinkingCooldown   = 12 * time.Hour
	lastErrorMissingThinking         = accountdomain.LastErrorMissingThinking
	lastErrorMissingThinkingDisabled = accountdomain.LastErrorMissingThinkingDisabled
	// An empty stream that idles while held is treated as an account-quality
	// failure: the request can still rotate before any bytes reach the client.
	qualityIdleAccountCooldown = 15 * time.Minute
)

var (
	errQualityDegraded    = errors.New("上游响应缺少推理")
	errQualityEmptyStream = errors.New("上游流式响应为空")
)

// QualityRetryRuntime is the isolated request-path withhold/retry policy.
// Zero Enabled leaves production behavior unchanged.
type QualityRetryRuntime struct {
	Enabled         bool
	MaxAttempts     int
	HoldTimeout     time.Duration
	MinOutputTokens int64
	OnExhausted     string
	AccountCooldown time.Duration
	// IdleAccountCooldown is applied to truly empty upstream streams
	// (idle timeout / empty peek). Missing-thinking still uses AccountCooldown.
	IdleAccountCooldown time.Duration
}

// QualityStreamSignals is the hold classifier input. Tests drive this
// directly and via ObserveQualityChunk on SSE fixtures.
type QualityStreamSignals struct {
	HasThinking bool
	// ReasoningStarted is an empty reasoning item or the Chat SSE stub
	// `: grok2api-reasoning-start`. That is not proof of thinking: 降智
	// still emits the stub, then dumps visible tokens with usage 0.
	ReasoningStarted bool
	VisibleTokens    int64
	ReasoningTokens  int64
	OutputTokens     int64
	Terminal         bool
	HoldExpired      bool
	// SemanticOutput reports that the stream carried a structured tool call
	// (or another non-text output item). A no-thinking mechanical tool call is
	// healthy agentic behavior; only text-without-thinking is the degradation
	// signature, so semantic turns must not be withheld on token counts alone.
	SemanticOutput bool
	// StreamedTextTokens counts only text observed directly on the stream,
	// excluding the usage-derived VisibleTokens fallback. Tool-call arguments
	// inflate usage.completion_tokens but are not chat text.
	StreamedTextTokens int64
}

// QualityVerdict is the hold decision for one upstream stream.
type QualityVerdict string

const (
	QualityWait     QualityVerdict = "wait"
	QualityDeliver  QualityVerdict = "deliver"
	QualityWithhold QualityVerdict = "withhold"
)

// QualityRetryAction is what the attempt loop does with a withhold verdict.
type QualityRetryAction string

const (
	QualityActionDeliver     QualityRetryAction = "deliver"
	QualityActionDeliverLast QualityRetryAction = "deliver_last"
	QualityActionRetry       QualityRetryAction = "retry"
	QualityActionReject      QualityRetryAction = "reject"
)

func normalizeQualityRetry(cfg QualityRetryRuntime) QualityRetryRuntime {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = defaultQualityMaxAttempts
	}
	if cfg.HoldTimeout <= 0 {
		cfg.HoldTimeout = defaultQualityHoldTimeout
	}
	if cfg.MinOutputTokens <= 0 {
		cfg.MinOutputTokens = defaultQualityMinOutput
	}
	if cfg.AccountCooldown <= 0 {
		cfg.AccountCooldown = defaultMissingThinkingCooldown
	}
	if cfg.IdleAccountCooldown <= 0 {
		cfg.IdleAccountCooldown = qualityIdleAccountCooldown
	}
	cfg.OnExhausted = normalizeQualityExhaustionPolicy(cfg.OnExhausted)
	return cfg
}

func (s *Service) UpdateQualityRetry(cfg QualityRetryRuntime) {
	normalized := normalizeQualityRetry(cfg)
	s.qualityRetry.Store(&normalized)
}

func (s *Service) qualityRetryConfig() QualityRetryRuntime {
	if s == nil {
		return normalizeQualityRetry(QualityRetryRuntime{})
	}
	if value := s.qualityRetry.Load(); value != nil {
		return *value
	}
	return normalizeQualityRetry(QualityRetryRuntime{})
}

// ClassifyQualityHold decides whether a held stream may be forwarded.
// Streamed thinking always delivers: reasoning/summary deltas, or a
// reasoning item with encrypted_content. Usage.reasoning_tokens alone
// does not — degraded upstreams fill that field without ciphertext or
// deltas. A finished sample with enough visible output and no streamed
// thinking is withheld.
// Short replies below minOutput are delivered so "ok"/"yes" is not retried.
// A hold timeout with no visible output is not fail-open: keep waiting for
// more bytes or a stream abort so an empty hang is not flushed as HTTP 200.
//
// An empty reasoning stub is not thinking. Before the hold deadline, wait for
// real evidence or a terminal event. If the deadline expires while the stream
// is still open and already has visible output, the result is inconclusive:
// release it without penalizing the account. A stub-only empty stream keeps
// waiting for idle/terminal handling. This keeps HoldTimeout a real latency
// bound without reopening the empty-stream 200 response path.
func ClassifyQualityHold(sig QualityStreamSignals, minOutput int64) QualityVerdict {
	if minOutput <= 0 {
		minOutput = defaultQualityMinOutput
	}
	if sig.HasThinking {
		return QualityDeliver
	}
	// A structured tool call is the healthy shape of a mechanical agentic turn.
	// Grok Build legitimately skips streamed reasoning before routine tool
	// calls, and usage.completion_tokens counts the call arguments, so token
	// counts cannot separate those turns from degraded ones. Withhold only
	// text-without-thinking: that is the observed degradation signature (code
	// and parameter markup dumped as chat text). If a no-thinking turn also
	// carries substantial streamed plain text, it stays subject to the
	// withhold below.
	if sig.SemanticOutput && sig.StreamedTextTokens < minOutput {
		return QualityDeliver
	}
	// Prefer observed/derived visible output. Total output includes reasoning
	// tokens, which are deliberately not trusted as quality evidence above. If
	// the stream exposed no visible count at all, retain OutputTokens as a
	// compatibility fallback for terminal usage-only responses.
	output := sig.VisibleTokens
	if output <= 0 {
		output = sig.OutputTokens
	}
	enough := output >= minOutput
	if sig.ReasoningStarted && !sig.Terminal {
		if sig.HoldExpired && output > 0 {
			return QualityDeliver
		}
		return QualityWait
	}
	if sig.Terminal {
		if output <= 0 {
			return QualityWait
		}
		if enough {
			return QualityWithhold
		}
		return QualityDeliver
	}
	if enough {
		return QualityWithhold
	}
	if sig.HoldExpired {
		if output <= 0 {
			return QualityWait
		}
		if enough {
			return QualityWithhold
		}
		return QualityDeliver
	}
	return QualityWait
}

// qualityPeekAbortError prefers the idle-timeout cause over a plain
// context.Canceled so the attempt loop can retry instead of treating the
// abort as a client 499.
func qualityPeekAbortError(ctx context.Context, err error) error {
	if ctx != nil {
		if cause := context.Cause(ctx); neterrorpkg.IsUpstreamStreamIdleTimeout(cause) {
			return cause
		}
	}
	if neterrorpkg.IsUpstreamStreamIdleTimeout(err) {
		return err
	}
	if err != nil {
		return err
	}
	if ctx != nil {
		return ctx.Err()
	}
	return nil
}

// isClientRequestCancel reports a real client disconnect. Upstream idle
// timeouts cancel the same context and must not be classified as 499.
func isClientRequestCancel(ctx context.Context, err error) bool {
	if neterrorpkg.IsUpstreamStreamIdleTimeout(err) {
		return false
	}
	if ctx != nil && neterrorpkg.IsUpstreamStreamIdleTimeout(context.Cause(ctx)) {
		return false
	}
	if ctx != nil && ctx.Err() != nil {
		return true
	}
	return errors.Is(err, context.Canceled)
}

// DecideQualityRetry caps withhold recovery at maxAttempts (default 6:
// original + five extra accounts). The last withhold
// (attemptIndex == maxAttempts-1) is fail-open unless OnExhausted is fail_closed.
func DecideQualityRetry(verdict QualityVerdict, attemptIndex, maxAttempts int, onExhausted string) QualityRetryAction {
	if verdict != QualityWithhold {
		return QualityActionDeliver
	}
	if maxAttempts <= 0 {
		maxAttempts = defaultQualityMaxAttempts
	}
	if attemptIndex < 0 {
		attemptIndex = 0
	}
	if attemptIndex < maxAttempts-1 {
		return QualityActionRetry
	}
	// attemptIndex == maxAttempts-1 (or past it): do not retry again.
	if normalizeQualityExhaustionPolicy(onExhausted) == qualityRetryFailClosed {
		return QualityActionReject
	}
	return QualityActionDeliverLast
}

// BoundQualityRetry turns a Retry into DeliverLast/Reject when the routing
// loop has no remaining account slot, so the already-held body is not dropped
// on continue-into-exhausted-loop.
func BoundQualityRetry(action QualityRetryAction, hasNextRoutingAttempt bool, onExhausted string) QualityRetryAction {
	if action != QualityActionRetry || hasNextRoutingAttempt {
		return action
	}
	if normalizeQualityExhaustionPolicy(onExhausted) == qualityRetryFailClosed {
		return QualityActionReject
	}
	return QualityActionDeliverLast
}

func normalizeQualityExhaustionPolicy(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), qualityRetryFailOpen) {
		return qualityRetryFailOpen
	}
	return qualityRetryFailClosed
}

// QualityCommit is the single attempt-loop decision for a held stream.
type QualityCommit struct {
	Action   QualityRetryAction
	Audit    bool
	KeepBody bool
}

// CommitQualityHold is the shipped withhold/retry/commit unit. The attempt
// loop must not re-derive this from Decide+Bound+switch.
func CommitQualityHold(verdict QualityVerdict, qualityAttempt, maxAttempts int, hasNextRouting bool, onExhausted string) QualityCommit {
	action := BoundQualityRetry(
		DecideQualityRetry(verdict, qualityAttempt, maxAttempts, onExhausted),
		hasNextRouting,
		onExhausted,
	)
	switch action {
	case QualityActionRetry, QualityActionReject:
		return QualityCommit{Action: action, Audit: true, KeepBody: false}
	case QualityActionDeliverLast:
		return QualityCommit{Action: action, Audit: false, KeepBody: true}
	default:
		return QualityCommit{Action: QualityActionDeliver, Audit: false, KeepBody: true}
	}
}

func shouldHoldQualityStream(input Input, ownership *inferencedomain.ResponseOwnership, route modeldomain.Route, operation audit.Operation, cfg QualityRetryRuntime) bool {
	if !cfg.Enabled || !input.Streaming || input.ForcedEgressNodeID != 0 || ownership != nil || input.skipQualityHold {
		return false
	}
	switch operation {
	case audit.OperationChat, audit.OperationResponses, audit.OperationMessages, "":
	default:
		return false
	}
	// TUI compaction is a normal /v1/responses body (no compaction_trigger).
	// Keep this defensive body check in addition to skipQualityHold so a caller
	// that bypasses CreateResponse cannot withhold a 100s+ summary as missing-thinking.
	if isResponsesCompactionRequest(input.Body) {
		return false
	}
	if route.Provider != accountdomain.ProviderBuild && route.Provider != accountdomain.ProviderConsole {
		return false
	}
	// Client-executed tools are safe to hold: their calls have not reached the
	// client yet, and completed results in the next request are immutable input.
	// Hosted tools are different. Retrying them can repeat an upstream search,
	// sandbox run, image job, or remote MCP call, so retain the old no-replay
	// safety boundary for any request that declares one.
	if qualityRequestHasReplayUnsafeHostedTools(input.Body) {
		return false
	}
	// Tool-less utility prompts (session titles, summaries, one-shot Q&A)
	// legitimately finish without streamed reasoning, and withholding them
	// only burns accounts from rotation. Degradation protection targets
	// agentic turns: requests that declare tools or continue a tool loop.
	if !qualityRequestIsAgentic(input.Body) {
		return false
	}
	// Aliases are rewritten before this gate, so inspect the effective request
	// body instead of only the reasoning-capable base model. In particular,
	// grok-4.3-none becomes grok-4.3 plus an explicit disabled setting.
	if qualityRequestDisablesReasoning(input.Body) {
		return false
	}
	if modeldomain.SupportsReasoningForProvider(route.Provider, input.PublicModel) {
		return true
	}
	return modeldomain.SupportsReasoningForProvider(route.Provider, route.UpstreamModel)
}

// qualityRequestIsAgentic reports whether the request belongs to a tool-using
// agent: it declares tools (any supported schema) or carries tool results /
// tool calls in its input, i.e. it continues an existing tool loop.
func qualityRequestIsAgentic(body []byte) bool {
	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil || payload == nil {
		return false
	}
	for _, key := range []string{"tools", "functions"} {
		if raw, ok := payload[key]; ok && jsonRawArrayNonEmpty(raw) {
			return true
		}
	}
	if jsonRawArrayHasToolContinuation(payload["messages"]) || jsonRawArrayHasToolContinuation(payload["input"]) {
		return true
	}
	return false
}

func jsonRawArrayNonEmpty(raw json.RawMessage) bool {
	var arr []any
	return json.Unmarshal(raw, &arr) == nil && len(arr) > 0
}

func jsonRawArrayHasToolContinuation(raw json.RawMessage) bool {
	var arr []map[string]any
	if json.Unmarshal(raw, &arr) != nil {
		return false
	}
	for _, item := range arr {
		switch jsonNodeString(item["type"]) {
		case "function_call_output", "tool_result":
			return true
		case "function_call", "tool_use":
			return true
		}
		if role, _ := item["role"].(string); strings.EqualFold(role, "tool") {
			return true
		}
		if _, ok := item["tool_calls"]; ok {
			return true
		}
	}
	return false
}

func qualityRequestHasReplayUnsafeHostedTools(body []byte) bool {
	var payload map[string]any
	if json.Unmarshal(body, &payload) != nil || payload == nil {
		return false
	}
	if raw, exists := payload["web_search_options"]; exists && raw != nil {
		return true
	}
	if raw, exists := payload["mcp_servers"]; exists && raw != nil {
		servers, ok := raw.([]any)
		if !ok || len(servers) > 0 {
			return true
		}
	}
	if qualityToolListHasReplayUnsafeHostedTool(payload["tools"]) {
		return true
	}
	// Responses Tool Search can load declarations later in the request. Only
	// inspect additional_tools items; arbitrary user/schema objects may also
	// contain a field named "tools" and must not affect the retry policy.
	items, _ := payload["input"].([]any)
	for _, rawItem := range items {
		item, ok := rawItem.(map[string]any)
		if !ok || jsonNodeString(item["type"]) != "additional_tools" {
			continue
		}
		if qualityToolListHasReplayUnsafeHostedTool(item["tools"]) {
			return true
		}
	}
	return false
}

func qualityToolListHasReplayUnsafeHostedTool(value any) bool {
	tools, ok := value.([]any)
	if !ok {
		return false
	}
	for _, rawTool := range tools {
		tool, ok := rawTool.(map[string]any)
		if !ok {
			continue
		}
		kind := jsonNodeString(tool["type"])
		switch kind {
		case "", "function", "custom", "local_shell", "apply_patch", "tool_search":
			// These declarations only ask the model to return a call. Execution
			// happens in the client after the held response is committed.
			continue
		case "shell":
			environment, _ := tool["environment"].(map[string]any)
			if jsonNodeString(environment["type"]) != "local" {
				return true
			}
		case "namespace":
			if qualityToolListHasReplayUnsafeHostedTool(tool["tools"]) {
				return true
			}
		default:
			// Default to no replay for every server/native tool, including types
			// added by future protocol versions that this gateway does not know yet.
			return true
		}
	}
	return false
}

func jsonNodeString(value any) string {
	text, _ := value.(string)
	return strings.ToLower(strings.TrimSpace(text))
}

func qualityRequestDisablesReasoning(body []byte) bool {
	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil {
		return false
	}
	if jsonStringEquals(payload["reasoning_effort"], modeldomain.ReasoningEffortNone) {
		return true
	}
	for _, key := range []string{"reasoning", "output_config", "thinking"} {
		var nested map[string]json.RawMessage
		if json.Unmarshal(payload[key], &nested) != nil {
			continue
		}
		if jsonStringEquals(nested["effort"], modeldomain.ReasoningEffortNone) || jsonStringEquals(nested["type"], "disabled") {
			return true
		}
		var budget int64
		if raw, ok := nested["budget_tokens"]; ok && json.Unmarshal(raw, &budget) == nil && budget == 0 {
			return true
		}
	}
	return jsonStringEquals(payload["thinking"], "disabled")
}

func jsonStringEquals(raw json.RawMessage, want string) bool {
	var value string
	return json.Unmarshal(raw, &value) == nil && strings.EqualFold(strings.TrimSpace(value), want)
}

func (s *Service) applyMissingThinkingPenalty(ctx context.Context, requestID string, credential accountdomain.Credential, cooldown time.Duration) {
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalizationTimeout)
	defer cancel()
	action, err := s.selector.markMissingThinking(writeCtx, credential, cooldown)
	if err != nil {
		s.logger.Error("quality_degraded_penalty_failed", "request_id", requestID, "account_id", credential.ID, "action", action, "error", err)
		return
	}
	switch action {
	case missingThinkingPenaltyDisabled:
		s.logger.Info("quality_degraded_disabled", "request_id", requestID, "account_id", credential.ID)
	case missingThinkingPenaltyCooled:
		s.logger.Info("quality_degraded_cooldown", "request_id", requestID, "account_id", credential.ID, "cooldown", cooldown.String())
	}
}

// qualityRejectMemoryTTL bounds how long a fail-closed conversation reject
// suppresses the full retry ladder for follow-up retries of the same
// conversation. Client backoff loops typically retry within minutes; the
// memory only needs to outlast one storm window.
const qualityRejectMemoryTTL = 10 * time.Minute

// rememberQualityReject records that a conversation's quality-retry ladder
// ended in fail-closed rejection, so immediate client retries fail fast
// instead of re-walking the account pool.
func (s *Service) rememberQualityReject(conversationKey string) {
	if conversationKey == "" {
		return
	}
	now := time.Now()
	s.qualityRejectMu.Lock()
	defer s.qualityRejectMu.Unlock()
	if len(s.qualityRejectRecent) >= 4096 {
		for key, expiry := range s.qualityRejectRecent {
			if expiry.Before(now) {
				delete(s.qualityRejectRecent, key)
			}
		}
		if len(s.qualityRejectRecent) >= 4096 {
			s.qualityRejectRecent = make(map[string]time.Time)
		}
	}
	s.qualityRejectRecent[conversationKey] = now.Add(qualityRejectMemoryTTL)
}

// qualityRejectLadderSuppressed reports whether this conversation was
// fail-closed rejected recently. When true the request runs a single
// quality attempt: no sticky retry, no account rotation, no cooldowns.
func (s *Service) qualityRejectLadderSuppressed(conversationKey string) bool {
	if conversationKey == "" {
		return false
	}
	now := time.Now()
	s.qualityRejectMu.Lock()
	defer s.qualityRejectMu.Unlock()
	expiry, ok := s.qualityRejectRecent[conversationKey]
	if !ok {
		return false
	}
	if expiry.Before(now) {
		delete(s.qualityRejectRecent, conversationKey)
		return false
	}
	return true
}

func (s *Service) recordQualityDegraded(ctx context.Context, base audit.Record, credential accountdomain.Credential, usage Usage, startedAt time.Time, trace *infraegress.Trace, provider accountdomain.Provider) {
	record := base
	record.EventID = newAuditEventID()
	accountID := credential.ID
	record.AccountID = &accountID
	record.AccountName = credential.Name
	record.StatusCode = http.StatusOK
	record.ErrorCode = ErrorQualityDegraded
	record.OutputTokens = usage.OutputTokens
	record.ReasoningTokens = usage.ReasoningTokens
	record.TotalTokens = usage.TotalTokens
	record.InputTokens = usage.InputTokens
	if usage.Reported {
		record.UsageSource = audit.UsageSourceUpstream
	}
	record.DurationMS = time.Since(startedAt).Milliseconds()
	record.CreatedAt = time.Now().UTC()
	applyAuditEgress(&record, trace, provider)
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finalizationTimeout)
	defer cancel()
	if err := s.audits.Create(writeCtx, record); err != nil {
		s.logger.Error("quality_degraded_audit_failed", "event_id", record.EventID, "request_id", record.RequestID, "error", err)
	}
}
