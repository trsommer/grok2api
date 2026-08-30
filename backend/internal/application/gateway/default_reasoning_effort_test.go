package gateway

import (
	"encoding/json"
	"testing"

	modeldomain "github.com/chenyme/grok2api/backend/internal/domain/model"
)

func TestRouteDefaultReasoningEffort(t *testing.T) {
	service := &Service{}
	service.UpdateDefaultReasoningEffort("high")
	buildRoute := modeldomain.Route{PublicID: "grok-4.6", UpstreamModel: "grok-4.6"}
	if got := service.routeDefaultReasoningEffort(buildRoute); got != "high" {
		t.Fatalf("configured high on grok-4.6 = %q, want high", got)
	}

	// xhigh falls back to high on models without an xhigh wire contract.
	service.UpdateDefaultReasoningEffort("xhigh")
	fixedRoute := modeldomain.Route{PublicID: "grok-4.5", UpstreamModel: "grok-4.5"}
	if got := service.routeDefaultReasoningEffort(fixedRoute); got != "high" {
		t.Fatalf("xhigh on grok-4.5 = %q, want high fallback", got)
	}
	xhighRoute := modeldomain.Route{PublicID: "grok-4.6", UpstreamModel: "grok-4.6"}
	if got := service.routeDefaultReasoningEffort(xhighRoute); got != "xhigh" {
		t.Fatalf("xhigh on grok-4.6 = %q, want xhigh", got)
	}

	// Empty or none disables injection.
	service.UpdateDefaultReasoningEffort("")
	if got := service.routeDefaultReasoningEffort(buildRoute); got != "" {
		t.Fatalf("empty config = %q, want empty", got)
	}
	service.UpdateDefaultReasoningEffort("none")
	if got := service.routeDefaultReasoningEffort(buildRoute); got != "" {
		t.Fatalf("none config = %q, want empty", got)
	}
	service.UpdateDefaultReasoningEffort("bogus")
	if got := service.routeDefaultReasoningEffort(buildRoute); got != "" {
		t.Fatalf("bogus config = %q, want empty", got)
	}
}

func TestShouldApplyDefaultReasoningEffort(t *testing.T) {
	agentic := `{"model":"grok-4.6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"bash"}}]}`
	if !shouldApplyDefaultReasoningEffort([]byte(agentic)) {
		t.Fatal("agentic request without effort should apply default")
	}
	// Tool-loop continuation (function_call_output) without tool declarations.
	continuation := `{"model":"grok-4.6","messages":[{"role":"tool","tool_call_id":"1","content":"ok"}]}`
	if !shouldApplyDefaultReasoningEffort([]byte(continuation)) {
		t.Fatal("tool continuation without effort should apply default")
	}
	// Non-agentic utility prompt.
	utility := `{"model":"grok-4.6","messages":[{"role":"user","content":"title this"}]}`
	if shouldApplyDefaultReasoningEffort([]byte(utility)) {
		t.Fatal("non-agentic request must keep upstream auto behavior")
	}
	// Explicit chat reasoning_effort.
	explicitChat := `{"model":"grok-4.6","reasoning_effort":"low","messages":[{"role":"user","content":"hi"}],"tools":[]}`
	if shouldApplyDefaultReasoningEffort([]byte(explicitChat)) {
		t.Fatal("explicit reasoning_effort must not be overridden")
	}
	// Explicit nested reasoning effort.
	explicitNested := `{"model":"grok-4.6","reasoning":{"effort":"medium"},"input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}],"tools":[]}`
	if shouldApplyDefaultReasoningEffort([]byte(explicitNested)) {
		t.Fatal("explicit nested effort must not be overridden")
	}
	// Explicitly disabled thinking.
	disabled := `{"model":"grok-4.6","reasoning_effort":"none","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"bash"}}]}`
	if shouldApplyDefaultReasoningEffort([]byte(disabled)) {
		t.Fatal("disabled thinking must not be overridden")
	}
}

func TestRewriteAliasedModelInjectsDefaultEffort(t *testing.T) {
	body := []byte(`{"model":"grok-4.6","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"bash"}}]}`)
	rewritten, err := rewriteAliasedModel(body, "grok-4.6", "high", "chat")
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(rewritten, &payload); err != nil {
		t.Fatalf("rewritten body is not JSON: %v", err)
	}
	if payload["reasoning_effort"] != "high" {
		t.Fatalf("chat rewrite missing reasoning_effort=high: %s", rewritten)
	}
}
