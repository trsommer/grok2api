package gateway

import (
	"net/http"
	"testing"
)

func TestSessionStateRejectionClassification(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "compaction blob rejection",
			body: `{"code":"invalid-argument","error":"Could not decode the compaction blob. Ensure it is unmodified from the compact response."}`,
			want: true,
		},
		{
			name: "encrypted content rejection",
			body: `{"error":"Could not decrypt the provided encrypted_content"}`,
			want: true,
		},
		{
			name: "generic invalid argument",
			body: `{"code":"invalid-argument","error":"messages must be non-empty"}`,
			want: false,
		},
		{
			name: "empty body",
			body: ``,
			want: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			failure := newHTTPUpstreamFailure(http.StatusBadRequest, []byte(test.body), 1, "acct")
			if got := failure.SessionStateRejected; got != test.want {
				t.Fatalf("SessionStateRejected = %v, want %v (body: %s)", got, test.want, test.body)
			}
			if test.want {
				if failure.Code != "upstream_session_state_rejected" {
					t.Fatalf("Code = %q, want upstream_session_state_rejected", failure.Code)
				}
				if failure.AccountScoped {
					t.Fatal("session-state rejection must not be account-scoped")
				}
			}
		})
	}
}

func TestSessionStateRejectionNotTriggeredOnOtherStatuses(t *testing.T) {
	// The same marker text on a 500 must not be classified as session-state
	// rejection; only the explicit 400 contract applies.
	body := []byte(`{"error":"Could not decode the compaction blob"}`)
	failure := newHTTPUpstreamFailure(http.StatusInternalServerError, body, 1, "acct")
	if failure.SessionStateRejected {
		t.Fatal("500 with marker text must not set SessionStateRejected")
	}
}
