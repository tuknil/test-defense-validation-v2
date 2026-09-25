package main

import (
	"context"
	"strings"
	"testing"
)

// TestRuleMergeIsInsertOnly pins that a rule already handed off is never
// rewritten: the statement must have no WHEN MATCHED branch, so a re-run under a
// new lease cannot change what a downstream push already read.
func TestRuleMergeIsInsertOnly(t *testing.T) {
	statement := ruleMergeSQL("`catalog`.`schema`.`rules`")
	if strings.Contains(strings.ToUpper(statement), "WHEN MATCHED") {
		t.Fatalf("rule MERGE must not update an existing row: %s", statement)
	}
	if !strings.Contains(statement, "WHEN NOT MATCHED THEN INSERT") {
		t.Fatalf("rule MERGE must insert when absent: %s", statement)
	}
	if !strings.Contains(statement, "ON target.result_id = source.result_id") {
		t.Fatalf("rule MERGE must key on result_id: %s", statement)
	}
	// Every value is a bound parameter; the table is the only interpolation.
	if got := strings.Count(statement, "?"); got != 10 {
		t.Errorf("expected 10 bound parameters, got %d: %s", got, statement)
	}
}

// TestNilRuleSinkIsAQuietNoOp lets callers skip a configuration check: a disabled
// sink must not error, because "not configured" is not a write failure.
func TestNilRuleSinkIsAQuietNoOp(t *testing.T) {
	var sink *DatabricksRuleSink
	if err := sink.WriteRule(context.Background(), RunOutcome{
		Candidate: &CandidateSpec{Rule: "SecRule ARGS \"@rx x\" \"id:1,deny\""},
	}); err != nil {
		t.Fatalf("disabled sink should not error: %v", err)
	}
	if ref := sink.RuleRef("defense-validation-result:one"); ref != nil {
		t.Errorf("disabled sink should have no rule ref, got %+v", ref)
	}
	sink.Close() // must not panic
}

// TestRuleSinkRefNamesTheConfiguredRuleTable checks the rule table is separate
// from the result table, since the push integration reads the rule table.
func TestRuleSinkRefNamesTheConfiguredRuleTable(t *testing.T) {
	sink := &DatabricksRuleSink{catalog: "cat", schema: "sch", name: "defense_validation_rules"}
	ref := sink.RuleRef("defense-validation-result:abc")
	if ref == nil {
		t.Fatal("configured sink must produce a rule ref")
	}
	if ref.Table != "defense_validation_rules" || ref.Catalog != "cat" || ref.Schema != "sch" {
		t.Errorf("rule ref = %+v", ref)
	}
	if ref.Key != "defense-validation-result:abc" {
		t.Errorf("rule rows are keyed by result_id, got %q", ref.Key)
	}
	if ref.Placeholder {
		t.Error("a configured rule ref is not a placeholder")
	}
}

// TestPersistResolvedRuleRecordsAMissingSink makes the miss visible on the
// result. Silently skipping the write would leave the push integration with
// nothing to read and no indication that anything was wrong.
func TestPersistResolvedRuleRecordsAMissingSink(t *testing.T) {
	previous := ruleSink
	ruleSink = nil
	t.Cleanup(func() { ruleSink = previous })

	out, written := persistResolvedRule(context.Background(), RunOutcome{
		RunID: "dv-run-1", ResultID: resultIDPrefix + "one", TerminalState: stateRuleResolved,
		Candidate: &CandidateSpec{Kind: "waf-rule", Engine: "akamai-waf", Rule: "{}"},
	})
	if written {
		t.Error("no sink is configured, so nothing was written")
	}
	if len(out.Limitations) == 0 || !strings.Contains(strings.Join(out.Limitations, " "), "not written to Databricks") {
		t.Errorf("a skipped rule write must be recorded: %+v", out.Limitations)
	}
	// The rule itself is still reported: the write is a hand-off, not a gate.
	if out.TerminalState != stateRuleResolved {
		t.Errorf("terminal_state = %q, want %q", out.TerminalState, stateRuleResolved)
	}
}

// TestPersistResolvedRuleSkipsRunsWithoutARule guards the two cases where there
// is nothing to hand off.
func TestPersistResolvedRuleSkipsRunsWithoutARule(t *testing.T) {
	previous := ruleSink
	ruleSink = nil
	t.Cleanup(func() { ruleSink = previous })

	failed, _ := persistResolvedRule(context.Background(), RunOutcome{TerminalState: stateFailed})
	if len(failed.Limitations) != 0 {
		t.Errorf("a failed run has no rule to write: %+v", failed.Limitations)
	}
	noRule, _ := persistResolvedRule(context.Background(), RunOutcome{TerminalState: stateRuleResolved})
	if len(noRule.Limitations) != 0 {
		t.Errorf("a run with no candidate has no rule to write: %+v", noRule.Limitations)
	}
}
