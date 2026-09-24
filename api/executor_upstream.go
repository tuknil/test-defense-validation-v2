package main

// executor_upstream.go resolves the defensive control candidate named by the
// request's upstream_inputs, whose result_refs point at Databricks rows, and
// reports it.
//
// upstream_inputs carries exactly one kind of producer result here:
// "control-translation". Its primary_candidate holds no content; the rule is the
// artifacts-map entry named by artifact_id, resolved and hash-verified by
// ExtractCustomWAFRule (see control_translation.go). Any other producer shape is
// rejected rather than guessed at.
//
// Nothing is executed. The resolved rule is printed and carried on the result;
// pushing it to a third-party control plane is the next stage, and any pass/fail
// judgement about the rule belongs to that plane.

import (
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

// executeScenarioUpstream resolves the rule from Databricks and reports it. Any
// resolution failure terminates the run as failed rather than reporting a rule
// that was not verified.
func executeScenarioUpstream(ctx context.Context, req SubmitDefenseValidationRequest, runID, resultID string) RunOutcome {
	base := RunOutcome{RunID: runID, ResultID: resultID}

	entries, err := parseUpstreamInputs(req.UpstreamInputs)
	if err != nil {
		return resolutionFailed(base, "upstream_inputs: "+err.Error())
	}
	if dbxReader == nil {
		return resolutionFailed(base, "Databricks reader not configured (DATABRICKS_DSN unset)")
	}

	ruleEntry := selectByCapability(entries, capControlTranslation)
	if ruleEntry == nil {
		return resolutionFailed(base, "no control-translation entry in upstream_inputs (need the rule)")
	}
	pc, err := dbxReader.ReadCandidate(ctx, ruleEntry.ResultRef)
	if err != nil {
		return resolutionFailed(base, "could not read rule from Databricks "+ruleEntry.ResultRef.qualified()+
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
		"candidate_kind": cand.Kind, "candidate_engine": cand.Engine, "candidate_action": cand.Action,
		"candidate_id": pc.CandidateID, "source_capability": capControlTranslation,
	})

	return reportResolvedRule(base, cand, capControlTranslation,
		"Databricks "+ruleEntry.ResultRef.qualified()+" where result_id="+ruleEntry.ResultRef.Key, os.Stdout)
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
// returns the rule it carries; see primaryCandidateFromResultJSON.
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

// primaryCandidateFromResultJSON adapts a control-translation result_json to the
// PrimaryCandidate the upstream executor consumes.
//
// A control-translation primary_candidate carries no content of its own: its
// artifact_id names an entry in the flat artifacts map, and that entry's content —
// a JSON string — is the vendor rule. ExtractCustomWAFRule resolves it and verifies
// content_hash, so a tampered or swapped artifact is refused here rather than
// reported.
//
// Any other capability is an error. Reading a different producer's result would
// mean guessing at where its rule lives, and a wrong guess reports a rule that was
// never verified.
func primaryCandidateFromResultJSON(js []byte) (PrimaryCandidate, error) {
	var probe struct {
		Capability string `json:"capability"`
	}
	if err := json.Unmarshal(js, &probe); err != nil {
		return PrimaryCandidate{}, fmt.Errorf("result_json parse: %w", err)
	}
	if probe.Capability != capControlTranslation {
		return PrimaryCandidate{}, fmt.Errorf(
			"upstream_inputs must reference a %s result, got %q", capControlTranslation, probe.Capability)
	}

	rule, err := ExtractCustomWAFRule(js)
	if err != nil {
		return PrimaryCandidate{}, fmt.Errorf("control-translation result: %w", err)
	}
	// target_control_class feeds candidateKind and artifact_type feeds
	// candidateEngine, so both come from producer metadata rather than being
	// re-derived from the rule text.
	return PrimaryCandidate{
		ArtifactContent:      string(rule.Content),
		ArtifactType:         rule.ArtifactType,
		CandidateID:          rule.CandidateID,
		SelectedControlClass: rule.ControlClass,
	}, nil
}

func (r *DatabricksReader) Close() {
	if r != nil && r.db != nil {
		_ = r.db.Close()
	}
}
