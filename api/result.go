package main

// result.go holds the result envelope this capability publishes.
//
// The service resolves a defensive control candidate from a verified producer
// result and reports it. It does not execute the rule, send attack or benign
// traffic, or decide whether the rule blocks anything — pushing the rule to a
// third-party control plane is the next stage, and any pass/fail judgement
// belongs to that plane, not here. So there is no verdict on this envelope:
// no expected/actual, no match, no substrate.

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// RunOutcome is the result of one run: the envelope, the resolved rule, and how
// it was obtained.
type RunOutcome struct {
	Capability      string             `json:"capability"`
	ContractID      string             `json:"contract_id"`
	RequestID       string             `json:"request_id"`
	RunID           string             `json:"run_id"`
	ResultID        string             `json:"result_id"`
	TerminalState   string             `json:"terminal_state"`
	Status          string             `json:"status"`
	CorrelationID   string             `json:"correlation_id,omitempty"`
	ResultRef       *ResultRef         `json:"result_ref,omitempty"`
	EvidenceRefs    []string           `json:"evidence_refs"`
	RequestSHA256   string             `json:"request_sha256"`
	UpstreamInputs  json.RawMessage    `json:"upstream_inputs,omitempty"`
	InputProvenance *LocatorProvenance `json:"input_provenance,omitempty"`
	ProfileID       string             `json:"profile_id,omitempty"`
	// ApplicationUnit records which artifact set was read back for the shared-contract
	// path. It is provenance for the rule, not a judgement about it.
	ApplicationUnit *AppliedApplicationUnit `json:"application_unit,omitempty"`

	// Candidate is the resolved rule. It stays in the exact canonical result
	// persisted to Databricks (reachable by a consumer via result_ref) but is
	// stripped from the API result response — see apiResultKeysToHide.
	Candidate *CandidateSpec `json:"candidate,omitempty"`
	// Detail explains a failure, or how the rule was obtained on success.
	Detail        string    `json:"detail,omitempty"`
	Steps         []string  `json:"steps"`
	ProseSummary  string    `json:"prose_summary"`
	Limitations   []string  `json:"limitations,omitempty"`
	ContentSHA256 string    `json:"content_sha256,omitempty"`
	SizeBytes     int64     `json:"size_bytes,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// CandidateSpec is the defensive control candidate — the rule this capability
// resolves and reports. Kind and Engine say what control plane it targets
// ("waf-rule" / "akamai-waf", "firewall-rule" / "iptables"), which is what a push
// integration needs in order to route it.
type CandidateSpec struct {
	Kind   string `json:"kind"`
	Engine string `json:"engine"`
	RuleID string `json:"rule_id"`
	Rule   string `json:"rule"`
	Action string `json:"action"`
}

// ResultRef points at where the full result row is stored so another service can
// query it. key is the result_id value itself — the same string written to the
// table's result_id column and reported as the top-level result_id — so the
// consumer queries WHERE result_id = <key>.
type ResultRef struct {
	System  string `json:"system"`
	Catalog string `json:"catalog"`
	Schema  string `json:"schema"`
	Table   string `json:"table"`
	Key     string `json:"key"`
	// Placeholder marks a reference that names where the row WOULD live rather
	// than a row known to exist. It is set only when no authoritative sink is
	// configured, and it is carried in the JSON so a consumer can never mistake a
	// stand-in for a published result.
	Placeholder bool `json:"placeholder,omitempty"`
}

// resultIDPrefix is the prefix on the run's result_id (so result_id looks like
// "defense-validation-result:<hex>"). The full result_id — prefix included — is what
// is written to the Databricks result_id column and placed in result_ref.key.
const resultIDPrefix = "defense-validation-result:"

// Terminal states. There is no blocked/not-blocked: this capability reports the
// rule it resolved, it does not judge the rule.
const (
	// stateRuleResolved means the rule was read from a verified producer result
	// and reported. It says nothing about whether the rule is effective.
	stateRuleResolved = "rule-resolved"
	// stateFailed means the rule could not be resolved or reported.
	stateFailed = "failed"
	// stateMalfunction is reserved for an internal fault, not a bad input.
	stateMalfunction = "malfunction"
)

// placeholderResultRef builds a stand-in reference from the same environment the
// real sinks read, for running without Databricks configured. It is always marked
// Placeholder: nothing has been written at this address.
func placeholderResultRef(resultID string) *ResultRef {
	return &ResultRef{
		System:      "databricks",
		Catalog:     firstNonEmpty(strings.TrimSpace(os.Getenv("DATABRICKS_CATALOG")), "unset-catalog"),
		Schema:      firstNonEmpty(strings.TrimSpace(os.Getenv("DATABRICKS_SCHEMA")), "defense_validation"),
		Table:       firstNonEmpty(strings.TrimSpace(os.Getenv("DATABRICKS_TABLE")), "defense_validation"),
		Key:         resultID,
		Placeholder: true,
	}
}

// resolutionFailed marks a run that could not produce a rule. It is the single
// sink for every resolution error, so a failure is never reported as a success.
func resolutionFailed(out RunOutcome, reason string) RunOutcome {
	out.TerminalState = stateFailed
	out.Detail = reason
	out.Steps = append(out.Steps, "failed: "+reason)
	out.ProseSummary = "Could not resolve a defensive control candidate: " + reason
	return out
}

// nonNil returns an empty JSON object for a nil raw message so the canonical
// result never carries a bare null where an object is expected.
func nonNil(r json.RawMessage) json.RawMessage {
	if len(r) == 0 {
		return json.RawMessage(`{}`)
	}
	return r
}

// firstNonEmpty returns the first non-empty value, or "".
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// reportResolvedRule writes the resolved rule to w and returns the run outcome
// for it. The rule is reported, not executed: no traffic is sent and no
// effectiveness claim is made, so the outcome carries the rule and its
// provenance and nothing that reads as a verdict. source names the capability the
// rule came from and sourceDetail where it was read from.
func reportResolvedRule(out RunOutcome, cand CandidateSpec, source, sourceDetail string, w io.Writer) RunOutcome {
	fmt.Fprintf(w, "%s rule (%s / %s) read from %s:\n%s\n",
		source, cand.Kind, cand.Engine, sourceDetail, CustomWAFRule{Content: []byte(cand.Rule)}.Pretty())

	out.Candidate = &cand
	out.TerminalState = stateRuleResolved
	out.Detail = "resolved from " + source + ": " + sourceDetail
	out.Steps = append(out.Steps, fmt.Sprintf("read %s (%s) from %s", cand.Kind, cand.Engine, sourceDetail))
	out.ProseSummary = fmt.Sprintf("Resolved the %s %s from the verified %s result and reported it.",
		cand.Engine, cand.Kind, source)
	out.Limitations = append(out.Limitations,
		"The rule was not executed and no traffic was run: this service reports the candidate, it does not judge it.")
	return out
}
