package main

// enforcement.go is the hand-off from a resolved rule to an XSIAM enforcement
// issue, inside a run.
//
// The order is deliberate: the rule row is written to Databricks first, and the
// issue is posted only if that write succeeded. The issue names a candidate the
// execution seam is expected to be able to look up, so handing one off before the
// row exists would point at nothing.
//
// Split of inputs:
//
//	XSIAM tenant + credentials   environment (XSIAM_HOST, XSIAM_API_KEY,
//	                             XDR_AUTH_ID)
//	everything else              the request's `enforcement` JSON object
//	identity                     the run itself (request_id, correlation_id)
//
// Credentials stay in the environment because they are deployment state, not
// per-request data: a caller should never be able to redirect a hand-off to
// another tenant by changing a request body.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
)

// EnforcementInput is the request's `enforcement` object: everything the rule
// artifact cannot supply.
type EnforcementInput struct {
	JanusPayloadOptions

	// Severity defaults to HIGH.
	Severity string `json:"severity,omitempty"`
	// ChangeRef is the external change record, e.g. servicenow-change:CHG0123456.
	ChangeRef string `json:"change_ref,omitempty"`
	// Justification is prose for whoever reviews the issue.
	Justification string `json:"justification,omitempty"`

	// The authorization chain, when the caller has one.
	AuthorizationID         string `json:"authorization_id,omitempty"`
	AuthorizationArtifactID string `json:"authorization_artifact_id,omitempty"`
	AuthorizationStatus     string `json:"authorization_status,omitempty"`
	RecoveryAuthorized      bool   `json:"recovery_authorized,omitempty"`

	// ExpiresAt bounds how long the requested action stays actionable.
	ExpiresAt string `json:"expires_at,omitempty"`
}

// IssueIdentity is the lineage the run already knows. It is taken from the run
// rather than the request body so the issue's correlation always matches the run
// that produced the rule.
type IssueIdentity struct {
	RequestID      string
	CorrelationID  string
	CausationID    string
	IdempotencyKey string
}

// parseEnforcementInput decodes the request's `enforcement` object. Unknown
// fields are refused: a mistyped key would otherwise be dropped and the issue
// posted with that value missing.
func parseEnforcementInput(raw json.RawMessage) (EnforcementInput, error) {
	var input EnforcementInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return EnforcementInput{}, fmt.Errorf("enforcement: %w", err)
	}
	if strings.TrimSpace(input.CVE) == "" {
		return EnforcementInput{}, fmt.Errorf("enforcement.cve is required")
	}
	return input, nil
}

// postEnforcementIssue posts the issue for a resolved rule.
//
// It is a no-op unless the run resolved a rule, the rule row was written, and the
// request carried an `enforcement` object — posting is opt-in per request, so a
// run that only wants the rule reported never reaches XSIAM.
//
// A posting failure does not fail the run. The rule is already resolved, verified
// and durably written; losing the hand-off is a delivery problem, and reporting
// the run as failed would misdescribe what actually happened. It is recorded on
// the result instead, never swallowed.
func postEnforcementIssue(ctx context.Context, req SubmitDefenseValidationRequest, out RunOutcome, ruleWritten bool) RunOutcome {
	if out.TerminalState != stateRuleResolved || out.Candidate == nil {
		return out
	}
	if len(req.Enforcement) == 0 {
		return out
	}
	if !ruleWritten {
		out.Limitations = append(out.Limitations,
			"No enforcement issue was posted: the rule row was not written, and an issue must not name a candidate that cannot be looked up.")
		return out
	}

	input, err := parseEnforcementInput(req.Enforcement)
	if err != nil {
		return recordPostFailure(out, err)
	}

	rule := CustomWAFRule{
		ArtifactType: out.Candidate.Kind,
		CandidateID:  out.Candidate.RuleID,
		Technology:   out.Candidate.Engine,
		ControlClass: strings.TrimSuffix(out.Candidate.Kind, "-rule"),
		Content:      []byte(out.Candidate.Rule),
		ContentHash:  sha256Prefixed([]byte(out.Candidate.Rule)),
	}
	identity := IssueIdentity{
		RequestID:     out.RequestID,
		CorrelationID: out.CorrelationID,
		CausationID:   out.RunID,
		// The run's own result id makes a stable idempotency key: a replayed run
		// resolves the same result and must not create a second issue.
		IdempotencyKey: out.ResultID,
	}

	res, err := PostEnforcementIssue(ctx, rule, input, identity)
	if err != nil {
		return recordPostFailure(out, err)
	}
	logLifecycle("enforcement_issue_posted", DurableRun{RunStatus: RunStatus{
		RequestID: out.RequestID, CorrelationID: out.CorrelationID, RunID: out.RunID,
	}}, map[string]any{"cve": input.CVE, "reply": issueIDFrom(res)})
	out.Steps = append(out.Steps, "posted enforcement issue to XSIAM for "+input.CVE)
	return out
}

func recordPostFailure(out RunOutcome, err error) RunOutcome {
	log.Printf("enforcement_issue_post_failed run_id=%q result_id=%q error=%q",
		out.RunID, out.ResultID, err.Error())
	out.Limitations = append(out.Limitations,
		"The rule was resolved and written but no enforcement issue was posted: "+err.Error())
	return out
}

// issueIDFrom digs the created issue's id out of the reply for the log, without
// assuming a shape: an unexpected reply must not panic a successful run.
func issueIDFrom(res map[string]any) any {
	reply, ok := res["reply"].(map[string]any)
	if !ok {
		return res["reply"]
	}
	return reply["issue_id"]
}
