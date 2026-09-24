package main

// executor_upstream.go is a SEPARATE executor selected by the env condition
// variable DV_INPUT_UPSTREAM (truthy). It serves the same POST endpoint but takes
// the new input contract: instead of inline artifacts, the request carries
// upstream_inputs whose result_refs point at Databricks rows. Entries are selected
// by capability:
//   - "defense-generation": the mitigation rule is read from result_json
//     (primary_candidate.artifact_content);
//   - "control-translation": the fallback rule source when there is no
//     defense-generation entry. Its primary_candidate holds no content; the rule
//     is the artifacts-map entry named by artifact_id, resolved and hash-verified
//     by ExtractCustomWAFRule (see control_translation.go);
//   - "check-generation": the test is derived from result_json.run_result via the
//     standalone stimulus converter (parseStimulus -> TestBasisFromStimulus).
//
// An inline test_basis in the request wins over the check-generation entry. The
// resolved rule/test are fed to the shared executor via the inline candidate /
// test_basis slots, so bring-up / WAF / verdict logic is reused unchanged.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	capDefenseGeneration  = "defense-generation"
	capCheckGeneration    = "check-generation"
	capControlTranslation = "control-translation"
)

// upstreamRef is the result_ref inside an upstream_inputs entry.
type upstreamRef struct {
	System  string `json:"system"`
	Catalog string `json:"catalog"`
	Schema  string `json:"schema"`
	Table   string `json:"table"`
	Key     string `json:"key"`
}

// qualified is the backtick-quoted `catalog`.`schema`.`table` for SQL.
func (r upstreamRef) qualified() string {
	q := backtick(r.Table)
	if r.Schema != "" {
		q = backtick(r.Schema) + "." + q
	}
	if r.Catalog != "" {
		q = backtick(r.Catalog) + "." + q
	}
	return q
}

type upstreamInput struct {
	Capability   string      `json:"capability"`
	ContractID   string      `json:"contract_id"`
	ResultID     string      `json:"result_id"`
	ResultRef    upstreamRef `json:"result_ref"`
	EvidenceRefs []string    `json:"evidence_refs"`
}

// executeScenarioUpstream resolves the rule (and, when needed, the test) from
// Databricks and delegates the run to the shared executor. Any resolution failure
// is a could-not-test (never a fabricated verdict).
func executeScenarioUpstream(ctx context.Context, req SubmitDefenseValidationRequest, runID, resultID string) RunOutcome {
	base := RunOutcome{RunID: runID, ResultID: resultID}

	entries, err := parseUpstreamInputs(req.UpstreamInputs)
	if err != nil {
		return couldNotTest(base, "upstream_inputs: "+err.Error())
	}
	if dbxReader == nil {
		return couldNotTest(base, "Databricks reader not configured (DATABRICKS_DSN unset)")
	}

	// Rule comes from the defense-generation entry, or from a control-translation
	// entry when there is no defense-generation one. defense-generation keeps
	// precedence so existing requests resolve to the same row as before; the
	// fallback exists because a control-translation result carries the same rule
	// after translation to a vendor syntax.
	ruleEntry := selectByCapability(entries, capDefenseGeneration)
	if ruleEntry == nil {
		ruleEntry = selectByCapability(entries, capControlTranslation)
	}
	if ruleEntry == nil {
		return couldNotTest(base,
			"no defense-generation or control-translation entry in upstream_inputs (need the rule)")
	}
	pc, err := dbxReader.ReadCandidate(ctx, ruleEntry.ResultRef)
	if err != nil {
		return couldNotTest(base, "could not read rule from Databricks "+ruleEntry.ResultRef.qualified()+
			" where result_id="+ruleEntry.ResultRef.Key+": "+err.Error())
	}
	rule := strings.TrimSpace(pc.ArtifactContent)
	cand := CandidateSpec{
		Kind:   candidateKind(pc, rule),
		Engine: candidateEngine(pc, rule),
		Rule:   rule,
		Action: deriveRuleAction(rule),
	}
	if b, e := json.Marshal(cand); e == nil {
		req.Candidate = b
	}
	logLifecycle("upstream_candidate_resolved", lifecycleIdentity(req, runID, resultID), map[string]any{
		"candidate_kind": cand.Kind, "candidate_engine": cand.Engine, "candidate_action": cand.Action, "candidate_id": pc.CandidateID,
	})
	// A firewall candidate runs on the separate firewall evaluator, not the WAF path.
	if cand.Kind == "firewall-rule" && req.ExecutionMode != execFirewall {
		req.ExecutionMode = execFirewall
	}
	steps := []string{
		"read " + cand.Kind + " from Databricks " + ruleEntry.ResultRef.qualified() +
			" where result_id=" + ruleEntry.ResultRef.Key,
	}

	// Test: an inline test_basis wins; otherwise derive it from the check-generation
	// entry's run_result via the standalone stimulus converter.
	if len(req.TestBasis) == 0 {
		if checkEntry := selectByCapability(entries, capCheckGeneration); checkEntry != nil {
			runResult, err := dbxReader.ReadRunResult(ctx, checkEntry.ResultRef)
			if err != nil {
				return couldNotTest(base, "could not read run_result from Databricks "+checkEntry.ResultRef.qualified()+
					" where result_id="+checkEntry.ResultRef.Key+": "+err.Error())
			}
			stim, err := parseStimulus(runResult)
			if err != nil {
				return couldNotTest(base, "check-generation run_result: "+err.Error())
			}
			tb, err := TestBasisFromStimulus(stim)
			if err != nil {
				return couldNotTest(base, "convert stimulus to test_basis: "+err.Error())
			}
			if b, e := json.Marshal(tb); e == nil {
				req.TestBasis = b
				logLifecycle("upstream_test_basis_resolved", lifecycleIdentity(req, runID, resultID), nil)
			}
			steps = append(steps, "derived test_basis from check-generation run_result "+
				checkEntry.ResultRef.qualified()+" where result_id="+checkEntry.ResultRef.Key)
		}
	}

	out := executeScenario(ctx, req, runID, resultID)
	out.Steps = append(steps, out.Steps...)
	return out
}

func lifecycleIdentity(req SubmitDefenseValidationRequest, runID, resultID string) DurableRun {
	return DurableRun{RunStatus: RunStatus{RequestID: req.RequestID, CorrelationID: req.CorrelationID, RunID: runID, ResultID: &resultID, Status: statusRunning}}
}

// candidateKind classifies the rule as "waf-rule" or "firewall-rule" from the
// upstream selected_control_class, falling back to the rule string's shape.
func candidateKind(pc PrimaryCandidate, rule string) string {
	switch strings.ToLower(strings.TrimSpace(pc.SelectedControlClass)) {
	case "firewall":
		return "firewall-rule"
	case "waf":
		return "waf-rule"
	}
	if strings.HasPrefix(strings.TrimSpace(rule), "SecRule") || strings.Contains(rule, "@rx") {
		return "waf-rule"
	}
	return "firewall-rule"
}

// candidateEngine derives the engine from artifact_type (e.g. "modsecurity-rule"
// -> "modsecurity", "iptables-rule" -> "iptables"), else infers from the rule.
func candidateEngine(pc PrimaryCandidate, rule string) string {
	if at := strings.ToLower(strings.TrimSpace(pc.ArtifactType)); at != "" {
		// "-rule-set" is checked first: control-translation emits types like
		// "akamai-waf-rule-set", where trimming only "-rule" would leave "-set".
		at = strings.TrimSuffix(at, "-rule-set")
		return strings.TrimSuffix(at, "-rule")
	}
	switch {
	case strings.HasPrefix(strings.TrimSpace(rule), "SecRule") || strings.Contains(rule, "@rx"):
		return "modsecurity"
	case strings.Contains(rule, "-j ") || strings.Contains(rule, "iptables"):
		return "iptables"
	}
	return ""
}

// reRuleAction matches a disruptive/allow action token as a whole word.
var reRuleAction = regexp.MustCompile(`\b(deny|drop|block|pass|allow|reject|accept)\b`)

// deriveRuleAction extracts the action from the rule string: the iptables target
// (-j DROP/REJECT/ACCEPT), else the SecRule action list (last quoted segment),
// else anywhere in the rule (firewall compact syntax).
func deriveRuleAction(rule string) string {
	low := strings.ToLower(rule)
	if i := strings.Index(low, "-j "); i >= 0 {
		if f := strings.Fields(low[i+3:]); len(f) > 0 {
			switch f[0] {
			case "drop", "reject", "accept":
				return f[0]
			}
		}
	}
	if seg, ok := lastQuoted(rule); ok {
		if m := reRuleAction.FindString(strings.ToLower(seg)); m != "" {
			return m
		}
	}
	if m := reRuleAction.FindString(low); m != "" {
		return m
	}
	return ""
}

// lastQuoted returns the content of the last double-quoted segment.
func lastQuoted(s string) (string, bool) {
	end := strings.LastIndex(s, `"`)
	if end <= 0 {
		return "", false
	}
	start := strings.LastIndex(s[:end], `"`)
	if start < 0 {
		return "", false
	}
	return s[start+1 : end], true
}

// parseUpstreamInputs decodes the upstream_inputs array.
func parseUpstreamInputs(raw json.RawMessage) ([]upstreamInput, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("no upstream_inputs provided")
	}
	var entries []upstreamInput
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("not a valid array: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("array is empty")
	}
	return entries, nil
}

// selectByCapability returns the first entry with the given capability that has a
// usable result_ref key, or nil.
func selectByCapability(entries []upstreamInput, capability string) *upstreamInput {
	for i := range entries {
		if strings.EqualFold(strings.TrimSpace(entries[i].Capability), capability) &&
			strings.TrimSpace(entries[i].ResultRef.Key) != "" {
			return &entries[i]
		}
	}
	return nil
}

// DatabricksReader reads upstream result_json rows from Databricks.
type DatabricksReader struct {
	db *sql.DB
}

// NewDatabricksReader returns nil when DATABRICKS_DSN is unset.
func NewDatabricksReader() *DatabricksReader {
	dsn := os.Getenv("DATABRICKS_DSN")
	if strings.TrimSpace(dsn) == "" {
		log.Printf("databricks reader: disabled (DATABRICKS_DSN unset)")
		return nil
	}
	db, err := sql.Open("databricks", normalizeDatabricksDSN(dsn))
	if err != nil {
		log.Printf("databricks reader: disabled (open failed: %v)", err)
		return nil
	}
	db.SetMaxOpenConns(4)
	log.Printf("databricks reader: enabled")
	return &DatabricksReader{db: db}
}

// ReadCandidate reads result_json for ref.Key from the referenced table and
// returns the rule to apply as a PrimaryCandidate. The row may hold either
// producer shape; see primaryCandidateFromResultJSON.
func (r *DatabricksReader) ReadCandidate(ctx context.Context, ref upstreamRef) (PrimaryCandidate, error) {
	if r == nil || r.db == nil {
		return PrimaryCandidate{}, fmt.Errorf("reader not configured")
	}
	q := "SELECT result_json FROM " + ref.qualified() + " WHERE result_id = ? LIMIT 1"
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	start := time.Now()

	var js string
	if err := r.db.QueryRowContext(c, q, ref.Key).Scan(&js); err != nil {
		log.Printf("databricks reader: READ FAILED (result_id=%s) after %s: %v",
			ref.Key, time.Since(start).Round(time.Millisecond), err)
		return PrimaryCandidate{}, err
	}

	pc, err := primaryCandidateFromResultJSON([]byte(js))
	if err != nil {
		return PrimaryCandidate{}, err
	}
	log.Printf("databricks reader: READ OK (result_id=%s) in %s",
		ref.Key, time.Since(start).Round(time.Millisecond))
	return pc, nil
}

// primaryCandidateFromResultJSON adapts a producer's result_json to the
// PrimaryCandidate the upstream executor consumes. Two shapes occur:
//
//   - defense-generation: primary_candidate.artifact_content carries the rule
//     inline (a ModSecurity SecRule).
//   - control-translation: primary_candidate carries no content at all. Its
//     artifact_id names an entry in the flat artifacts map, and that entry's
//     content — a JSON string — is the vendor rule. ExtractCustomWAFRule resolves
//     it and verifies content_hash, so a tampered or swapped artifact is refused
//     here rather than applied.
//
// Dispatch is by capability, which both producers set. A row with neither the
// inline content nor a resolvable artifact is an error, never a silent empty rule.
func primaryCandidateFromResultJSON(js []byte) (PrimaryCandidate, error) {
	var probe struct {
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal(js, &probe); err != nil {
		return PrimaryCandidate{}, fmt.Errorf("result_json parse: %w", err)
	}

	if probe.Capability == capControlTranslation {
		rule, err := ExtractCustomWAFRule(js)
		if err != nil {
			return PrimaryCandidate{}, fmt.Errorf("control-translation result: %w", err)
		}
		// The vendor rule set becomes the candidate content. target_control_class
		// feeds candidateKind, and artifact_type feeds candidateEngine, so both are
		// carried across rather than re-derived from the rule text.
		return PrimaryCandidate{
			ArtifactContent:      string(rule.Content),
			ArtifactType:         rule.ArtifactType,
			CandidateID:          rule.CandidateID,
			SelectedControlClass: rule.ControlClass,
		}, nil
	}

	var res struct {
		PrimaryCandidate PrimaryCandidate `json:"primary_candidate"`
	}
	if err := json.Unmarshal(js, &res); err != nil {
		return PrimaryCandidate{}, fmt.Errorf("result_json parse: %w", err)
	}
	if strings.TrimSpace(res.PrimaryCandidate.ArtifactContent) == "" {
		return PrimaryCandidate{}, fmt.Errorf("primary_candidate.artifact_content is empty")
	}
	return res.PrimaryCandidate, nil
}

// ReadRunResult reads result_json for ref.Key from the referenced table and returns
// its run_result object — the standalone stimulus converter's input.
func (r *DatabricksReader) ReadRunResult(ctx context.Context, ref upstreamRef) (json.RawMessage, error) {
	if r == nil || r.db == nil {
		return nil, fmt.Errorf("reader not configured")
	}
	q := "SELECT result_json FROM " + ref.qualified() + " WHERE result_id = ? LIMIT 1"
	c, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	start := time.Now()

	var js string
	if err := r.db.QueryRowContext(c, q, ref.Key).Scan(&js); err != nil {
		log.Printf("databricks reader: READ FAILED (result_id=%s) after %s: %v",
			ref.Key, time.Since(start).Round(time.Millisecond), err)
		return nil, err
	}
	rr, err := extractRunResult([]byte(js))
	if err != nil {
		return nil, err
	}
	log.Printf("databricks reader: READ OK run_result (result_id=%s) in %s",
		ref.Key, time.Since(start).Round(time.Millisecond))
	return rr, nil
}

// extractRunResult pulls the run_result object out of a result_json document.
func extractRunResult(js []byte) (json.RawMessage, error) {
	var res struct {
		RunResult json.RawMessage `json:"run_result"`
	}
	if err := json.Unmarshal(js, &res); err != nil {
		return nil, fmt.Errorf("result_json parse: %w", err)
	}
	if len(res.RunResult) == 0 || string(bytes.TrimSpace(res.RunResult)) == "null" {
		return nil, fmt.Errorf("result_json.run_result is missing")
	}
	return res.RunResult, nil
}

func (r *DatabricksReader) Close() {
	if r != nil && r.db != nil {
		_ = r.db.Close()
	}
}
