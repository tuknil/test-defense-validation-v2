package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func resolvedOutcome() RunOutcome {
	return RunOutcome{
		RunID: "dv-run-1", ResultID: resultIDPrefix + "abc",
		RequestID: "janus-dv-request-1", CorrelationID: "correlation-1",
		TerminalState: stateRuleResolved,
		Candidate: &CandidateSpec{
			Kind: "waf-rule", Engine: "akamai-waf",
			RuleID: "control-candidate:demo", Action: "block",
			Rule: `{"configurationType":"akamai-custom-rule-set","combinationOperation":"OR","rules":[{"name":"a","operation":"AND","sourceAction":"block","conditions":[{"type":"pathMatch","matchOperator":"exact","positiveMatch":true,"value":["/a"]}]}]}`,
		},
	}
}

const demoEnforcementJSON = `{
  "cve": "CVE-2026-77392",
  "policy_id": "policy-1",
  "rule_id": 60022381,
  "policy_version": 43,
  "control_instance_id": "control-instance:akamai-production",
  "protected_hostname": "afo.example.com",
  "target_scope_id": "population-scope:prod-web",
  "change_ref": "servicenow-change:CHG0123456"
}`

// stubXSIAM points the environment at a local server and returns the last body it
// received. The client forces https, so the test drives the seam through
// IssueForEnforcement + an explicit client rather than the env-configured path.
func stubXSIAM(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	t.Setenv("XSIAM_HOST", strings.TrimPrefix(server.URL, "http://"))
	t.Setenv("XSIAM_API_KEY", "secret-key")
	t.Setenv("XDR_AUTH_ID", "42")
	return server
}

// TestPostEnforcementIssueSkipsWithoutOptIn: no enforcement object means no
// hand-off, and nothing recorded — omitting it is how a caller opts out.
func TestPostEnforcementIssueSkipsWithoutOptIn(t *testing.T) {
	out := postEnforcementIssue(context.Background(), SubmitDefenseValidationRequest{}, resolvedOutcome(), true)
	if len(out.Limitations) != 0 || len(out.Steps) != 0 {
		t.Errorf("opting out should be silent: limitations=%v steps=%v", out.Limitations, out.Steps)
	}
}

// TestPostEnforcementIssueRequiresTheRuleRow is the ordering gate: an issue names
// a candidate the execution seam looks up, so it must not be posted when the row
// was never written.
func TestPostEnforcementIssueRequiresTheRuleRow(t *testing.T) {
	var called bool
	stubXSIAM(t, func(w http.ResponseWriter, r *http.Request) { called = true })

	req := SubmitDefenseValidationRequest{Enforcement: json.RawMessage(demoEnforcementJSON)}
	out := postEnforcementIssue(context.Background(), req, resolvedOutcome(), false)

	if called {
		t.Error("an issue was posted although the rule row was not written")
	}
	if !strings.Contains(strings.Join(out.Limitations, " "), "rule row was not written") {
		t.Errorf("the skip must be recorded: %v", out.Limitations)
	}
}

func TestPostEnforcementIssueSkipsRunsWithoutARule(t *testing.T) {
	req := SubmitDefenseValidationRequest{Enforcement: json.RawMessage(demoEnforcementJSON)}
	failed := resolvedOutcome()
	failed.TerminalState = stateFailed
	if out := postEnforcementIssue(context.Background(), req, failed, true); len(out.Limitations) != 0 {
		t.Errorf("a failed run has nothing to hand off: %v", out.Limitations)
	}
}

// TestPostEnforcementIssueRecordsAFailureWithoutFailingTheRun: the rule is
// already resolved, verified and written, so a delivery problem must not be
// reported as a failed run — but it must not vanish either.
func TestPostEnforcementIssueRecordsAFailureWithoutFailingTheRun(t *testing.T) {
	stubXSIAM(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	req := SubmitDefenseValidationRequest{Enforcement: json.RawMessage(demoEnforcementJSON)}

	out := postEnforcementIssue(context.Background(), req, resolvedOutcome(), true)
	if out.TerminalState != stateRuleResolved {
		t.Errorf("a delivery failure must not change the run's outcome: %q", out.TerminalState)
	}
	if len(out.Limitations) == 0 {
		t.Error("a delivery failure must be recorded, not swallowed")
	}
}

func TestParseEnforcementInputRejectsBadInput(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"not an object", `[]`, "enforcement"},
		{"missing cve", `{"policy_id":"p"}`, "enforcement.cve is required"},
		{"blank cve", `{"cve":"   "}`, "enforcement.cve is required"},
		{"unknown field", `{"cve":"CVE-1","polcy_id":"typo"}`, "unknown field"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseEnforcementInput(json.RawMessage(tc.in))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestParseEnforcementInputReadsEveryField(t *testing.T) {
	input, err := parseEnforcementInput(json.RawMessage(demoEnforcementJSON))
	if err != nil {
		t.Fatal(err)
	}
	if input.CVE != "CVE-2026-77392" || input.PolicyID != "policy-1" || input.RuleID != 60022381 ||
		input.PolicyVersion != 43 {
		t.Errorf("payload options = %+v", input.JanusPayloadOptions)
	}
	if input.ControlInstanceID != "control-instance:akamai-production" ||
		input.ProtectedHostname != "afo.example.com" ||
		input.TargetScopeID != "population-scope:prod-web" {
		t.Errorf("target = %+v", input.JanusPayloadOptions)
	}
	if input.ChangeRef != "servicenow-change:CHG0123456" {
		t.Errorf("change_ref = %q", input.ChangeRef)
	}
}

// TestIssueForEnforcementCarriesRunIdentity checks the lineage: the issue's
// identity comes from the run, and the idempotency key is the result id so a
// replayed run cannot create a second issue.
func TestIssueForEnforcementCarriesRunIdentity(t *testing.T) {
	input, err := parseEnforcementInput(json.RawMessage(demoEnforcementJSON))
	if err != nil {
		t.Fatal(err)
	}
	identity := IssueIdentity{
		RequestID: "janus-dv-request-1", CorrelationID: "correlation-1",
		CausationID: "dv-run-1", IdempotencyKey: resultIDPrefix + "abc",
	}
	rule := CustomWAFRule{
		Technology: "akamai-waf", CandidateID: "control-candidate:demo",
		Content: []byte(resolvedOutcome().Candidate.Rule),
	}
	issue, err := IssueForEnforcement(rule, input, identity)
	if err != nil {
		t.Fatal(err)
	}

	fields := issue.CustomFields
	if fields.RequestID != identity.RequestID || fields.CorrelationID != identity.CorrelationID ||
		fields.CausationID != identity.CausationID {
		t.Errorf("identity = %+v", fields)
	}
	if fields.IdempotencyKey != identity.IdempotencyKey {
		t.Errorf("idempotency key = %q, want the result id", fields.IdempotencyKey)
	}
	if fields.CRRef != "servicenow-change:CHG0123456" {
		t.Errorf("change ref = %q", fields.CRRef)
	}
	// prod-web is a production scope; anything unrecognised stays blank rather
	// than being guessed.
	if fields.TargetEnvironment != "production" {
		t.Errorf("target environment = %q", fields.TargetEnvironment)
	}

	// The identity must survive into the embedded request context too.
	var requestContext JanusRequestContext
	if err := json.Unmarshal([]byte(fields.RequestContext), &requestContext); err != nil {
		t.Fatal(err)
	}
	if requestContext.CorrelationID != identity.CorrelationID || requestContext.RequestID != identity.RequestID {
		t.Errorf("embedded request context identity = %+v", requestContext)
	}
}

func TestTargetEnvironmentIsNeverGuessed(t *testing.T) {
	for scope, want := range map[string]string{
		"population-scope:prod-web":    "production",
		"population-scope:staging-api": "staging",
		"population-scope:dev-1":       "development",
		"population-scope:ring-4":      "",
		"no-colon":                     "",
		"":                             "",
	} {
		if got := targetEnvironmentFor(scope); got != want {
			t.Errorf("targetEnvironmentFor(%q) = %q, want %q", scope, got, want)
		}
	}
}

// TestPostEnforcementIssuePostsTheResolvedRule drives the seam end to end and
// checks what arrives is the rule from the outcome.
func TestPostEnforcementIssuePostsTheResolvedRule(t *testing.T) {
	var posted []byte
	server := stubXSIAM(t, func(w http.ResponseWriter, r *http.Request) {
		posted, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"reply":{"issue_id":"ISSUE-9"}}`))
	})

	input, err := parseEnforcementInput(json.RawMessage(demoEnforcementJSON))
	if err != nil {
		t.Fatal(err)
	}
	out := resolvedOutcome()
	rule := CustomWAFRule{
		Technology: out.Candidate.Engine, CandidateID: out.Candidate.RuleID,
		Content: []byte(out.Candidate.Rule), ContentHash: sha256Prefixed([]byte(out.Candidate.Rule)),
	}
	issue, err := IssueForEnforcement(rule, input, IssueIdentity{
		RequestID: out.RequestID, CorrelationID: out.CorrelationID,
		CausationID: out.RunID, IdempotencyKey: out.ResultID,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := XSIAMConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg.scheme = "http"
	cfg.HTTPClient = server.Client()
	if _, err := NewXSIAMClient(cfg).CreateIssue(context.Background(), issue); err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}

	fields := decodeIssueBody(t, posted)["custom_fields"].(map[string]any)
	if fields["januscorrelationid"] != "correlation-1" {
		t.Errorf("posted correlation id = %v", fields["januscorrelationid"])
	}
	if fields["janusidempotencykey"] != out.ResultID {
		t.Errorf("posted idempotency key = %v", fields["janusidempotencykey"])
	}
	var payload JanusPayload
	if err := json.Unmarshal([]byte(fields["januspayload"].(string)), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.NativeBinding.PolicyID != "policy-1" || payload.NativeBinding.RuleID != 60022381 {
		t.Errorf("native binding came from the enforcement JSON: %+v", payload.NativeBinding)
	}
}
