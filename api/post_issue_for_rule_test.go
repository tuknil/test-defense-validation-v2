package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestIssueFromCustomWAFRuleCarriesTheRule covers the chain from a resolved rule
// to a postable issue: the rule's identity and its mapped payload both land in
// custom_fields.
func TestIssueFromCustomWAFRuleCarriesTheRule(t *testing.T) {
	rule := fixtureCustomWAFRule(t)
	issue, err := IssueFromCustomWAFRule(rule, demoPayloadOptions())
	if err != nil {
		t.Fatalf("build issue: %v", err)
	}

	if issue.Name != "JANUS | AKAMAI_WAF | DEPLOY | CVE-2025-64446" {
		t.Errorf("name = %q", issue.Name)
	}
	if issue.CustomFields.ControlPlane != "akamai-waf" || issue.CustomFields.Enforcement != "ENFORCING" {
		t.Errorf("control plane / enforcement = %q / %q",
			issue.CustomFields.ControlPlane, issue.CustomFields.Enforcement)
	}
	if issue.CustomFields.CandidateDigest != rule.ContentHash {
		t.Errorf("candidate digest = %q, want the rule's verified hash %q",
			issue.CustomFields.CandidateDigest, rule.ContentHash)
	}

	// The payload must be the one built from this rule, not a placeholder.
	var payload JanusPayload
	if err := json.Unmarshal([]byte(issue.CustomFields.Payload), &payload); err != nil {
		t.Fatalf("januspayload does not parse: %v", err)
	}
	if len(payload.StructuredRule.Conditions) != 3 {
		t.Errorf("structured rule should carry the rule's 3 conditions, got %d",
			len(payload.StructuredRule.Conditions))
	}
	if payload.DesiredPolicyAction.Action != "deny" {
		t.Errorf("desired action = %q", payload.DesiredPolicyAction.Action)
	}

	// Orchestrator identity is left empty rather than invented: a fabricated
	// correlation id would break the lineage the issue exists to carry.
	if issue.CustomFields.CorrelationID != "" || issue.CustomFields.RequestID != "" {
		t.Errorf("orchestrator identity should not be generated here: request=%q correlation=%q",
			issue.CustomFields.RequestID, issue.CustomFields.CorrelationID)
	}
}

// TestPostIssueForRulePostsTheResolvedRule exercises the full chain against a
// stub server: rule -> payload -> issue -> POST.
func TestPostIssueForRulePostsTheResolvedRule(t *testing.T) {
	var posted []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posted, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{"reply":{"issue_id":"ISSUE-7"}}`))
	}))
	defer server.Close()

	t.Setenv("XSIAM_HOST", strings.TrimPrefix(server.URL, "http://"))
	t.Setenv("XSIAM_API_KEY", "secret-key")
	t.Setenv("XDR_AUTH_ID", "42")

	// PostIssueForRule builds its own client from the environment, so the scheme
	// is exercised here by building the same way and overriding only the scheme.
	issue, err := IssueFromCustomWAFRule(fixtureCustomWAFRule(t), demoPayloadOptions())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := XSIAMConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg.scheme = "http"
	cfg.HTTPClient = server.Client()

	res, err := NewXSIAMClient(cfg).CreateIssue(t.Context(), issue)
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	reply, _ := res["reply"].(map[string]any)
	if reply["issue_id"] != "ISSUE-7" {
		t.Errorf("response = %v", res)
	}

	// What arrived must be the rule that was resolved, all the way through.
	fields := decodeIssueBody(t, posted)["custom_fields"].(map[string]any)
	var payload JanusPayload
	if err := json.Unmarshal([]byte(fields["januspayload"].(string)), &payload); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, condition := range payload.StructuredRule.Conditions {
		for _, value := range condition.Value {
			if value == `person\[0\]\[\]=malicious` {
				found = true
			}
		}
	}
	if !found {
		t.Error("the posted payload does not carry the rule's second alternative")
	}
}

// TestPostIssueForRuleFailsBeforeSendingOnABadMapping checks the ordering: the
// payload is built first, so a rule that cannot be mapped never reaches the
// network and cannot half-create anything.
func TestPostIssueForRuleFailsBeforeSendingOnABadMapping(t *testing.T) {
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	t.Setenv("XSIAM_HOST", strings.TrimPrefix(server.URL, "http://"))
	t.Setenv("XSIAM_API_KEY", "secret-key")
	t.Setenv("XDR_AUTH_ID", "42")

	// No CVE: the mapping refuses, so nothing should be posted.
	_, err := PostIssueForRule(t.Context(), fixtureCustomWAFRule(t), JanusPayloadOptions{})
	if err == nil {
		t.Fatal("an unmappable rule must not be posted")
	}
	if called {
		t.Error("the request was sent despite the mapping failing")
	}
}

// TestWriteCustomWAFRuleTakesAnExtractedRule is the "print then reuse" shape: the
// rule is resolved once and printed, and the same value goes on to the issue.
func TestWriteCustomWAFRuleTakesAnExtractedRule(t *testing.T) {
	rule := fixtureCustomWAFRule(t)
	var printed bytes.Buffer
	if err := WriteCustomWAFRule(&printed, rule); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(printed.String(), "(verified)") {
		t.Error("the printed header should report the verified hash")
	}
	if !strings.Contains(printed.String(), `"configurationType": "akamai-custom-rule-set"`) {
		t.Error("the rule body should be printed decoded")
	}

	// PrintCustomWAFRule stays a thin wrapper over the same writer.
	var viaRaw bytes.Buffer
	if err := PrintCustomWAFRule(&viaRaw, controlTranslationFixture(t)); err != nil {
		t.Fatalf("print: %v", err)
	}
	if viaRaw.String() != printed.String() {
		t.Error("printing from raw bytes and from an extracted rule must agree")
	}
}
