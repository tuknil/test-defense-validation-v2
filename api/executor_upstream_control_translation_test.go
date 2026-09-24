package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// TestReadCandidateAcceptsAControlTranslationResultJSON covers the shape
// ReadCandidate now resolves through ExtractCustomWAFRule: a control-translation
// result whose primary_candidate has no artifact_content, only an artifact_id
// pointing into the artifacts map.
func TestReadCandidateAcceptsAControlTranslationResultJSON(t *testing.T) {
	pc, err := primaryCandidateFromResultJSON(controlTranslationFixture(t))
	if err != nil {
		t.Fatalf("resolve control-translation candidate: %v", err)
	}

	if pc.CandidateID != "control-candidate:CVE-2026-77392:akamai-waf:e6fcf665eb9f311e" {
		t.Errorf("candidate_id = %q", pc.CandidateID)
	}
	if pc.ArtifactType != "akamai-waf-rule-set" {
		t.Errorf("artifact_type = %q", pc.ArtifactType)
	}
	if pc.SelectedControlClass != "waf" {
		t.Errorf("selected_control_class = %q, want waf (from target_control_class)", pc.SelectedControlClass)
	}

	// The content is the resolved Akamai rule set, not the empty string the old
	// inline-only path would have produced.
	var ruleSet struct {
		ConfigurationType string `json:"configurationType"`
		Rules             []any  `json:"rules"`
	}
	if err := json.Unmarshal([]byte(pc.ArtifactContent), &ruleSet); err != nil {
		t.Fatalf("artifact_content is not the rule set: %v", err)
	}
	if ruleSet.ConfigurationType != "akamai-custom-rule-set" || len(ruleSet.Rules) != 2 {
		t.Errorf("resolved content = %q with %d rules", ruleSet.ConfigurationType, len(ruleSet.Rules))
	}
}

// TestControlTranslationCandidateClassification pins how the resolved candidate
// is classified before it reaches the evaluator.
func TestControlTranslationCandidateClassification(t *testing.T) {
	pc, err := primaryCandidateFromResultJSON(controlTranslationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	rule := strings.TrimSpace(pc.ArtifactContent)

	if kind := candidateKind(pc, rule); kind != "waf-rule" {
		t.Errorf("candidateKind = %q, want waf-rule", kind)
	}
	// "akamai-waf-rule-set" must reduce to the vendor, not leave a dangling "-set".
	if engine := candidateEngine(pc, rule); engine != "akamai-waf" {
		t.Errorf("candidateEngine = %q, want akamai-waf", engine)
	}
}

// TestReportResolvedRulePrintsTheRuleAndClaimsNoVerdict covers the reporting
// step: the resolved rule is printed and the run ends there, with no verdict of
// any kind on the outcome.
func TestReportResolvedRulePrintsTheRuleAndClaimsNoVerdict(t *testing.T) {
	pc, err := primaryCandidateFromResultJSON(controlTranslationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	rule := strings.TrimSpace(pc.ArtifactContent)
	cand := CandidateSpec{
		Kind:   candidateKind(pc, rule),
		Engine: candidateEngine(pc, rule),
		Rule:   rule,
		Action: deriveRuleAction(rule),
	}
	const sourceDetail = "Databricks `control_translation`.`control_translation_results` " +
		"where result_id=control-translation-result:e0b7e5cf"

	var printed bytes.Buffer
	out := reportResolvedRule(RunOutcome{RunID: "dv-run-1", ResultID: "r"}, cand,
		capControlTranslation, sourceDetail, &printed)

	// The rule is printed, decoded and indented.
	text := printed.String()
	if !strings.Contains(text, `"configurationType": "akamai-custom-rule-set"`) {
		t.Error("the rule set was not printed in decoded, indented form")
	}
	if !strings.Contains(text, "control-translation-result:e0b7e5cf") {
		t.Error("printed output should name the row it was read from")
	}

	// The run resolved a rule; it made no claim about the rule.
	if out.TerminalState != stateRuleResolved {
		t.Errorf("terminal_state = %q, want %q", out.TerminalState, stateRuleResolved)
	}
	if len(out.Limitations) == 0 {
		t.Error("the outcome must record that nothing was executed")
	}

	// The rule itself is carried on the outcome.
	if out.Candidate == nil || out.Candidate.Rule != rule {
		t.Error("the reported rule must be carried on the outcome")
	}
}

// TestRunOutcomeCarriesNoVerdictFields is a structural guard: the result envelope
// must not regrow a verdict. Anything that judges the rule belongs to the control
// plane the rule is pushed to, not to this capability.
func TestRunOutcomeCarriesNoVerdictFields(t *testing.T) {
	encoded, err := json.Marshal(RunOutcome{})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, banned := range []string{"match", "expected", "actual", "substrate", "test_basis",
		"obligation_results", "accounting"} {
		if _, present := fields[banned]; present {
			t.Errorf("RunOutcome must not carry the verdict field %q", banned)
		}
	}
	for _, state := range []string{stateRuleResolved, stateFailed, stateMalfunction} {
		if state == "blocked" || state == "not-blocked" || state == "could-not-test" {
			t.Errorf("terminal state %q is a verdict", state)
		}
	}
}

// TestPrimaryCandidateFromResultJSONRejectsOtherProducers pins that only a
// control-translation result is read here. A defense-generation row carries its
// rule somewhere else entirely, so accepting it would mean guessing.
func TestPrimaryCandidateFromResultJSONRejectsOtherProducers(t *testing.T) {
	js := []byte(`{
		"capability":"defense-generation",
		"primary_candidate":{
			"artifact_content":"SecRule ARGS \"@rx select\" \"id:1,deny,status:403\"",
			"artifact_type":"modsecurity-rule",
			"candidate_id":"cand-1",
			"selected_control_class":"waf"}}`)
	_, err := primaryCandidateFromResultJSON(js)
	if err == nil {
		t.Fatal("a defense-generation result must not be accepted from upstream_inputs")
	}
	if !strings.Contains(err.Error(), "must reference a control-translation result") {
		t.Errorf("error = %q", err)
	}
}

func TestPrimaryCandidateFromResultJSONRejectsUnusableRows(t *testing.T) {
	for _, tc := range []struct {
		name string
		js   string
		want string
	}{
		{"malformed", `{`, "result_json parse"},
		{"another producer", `{"capability":"defense-generation","primary_candidate":{}}`,
			"must reference a control-translation result"},
		{"control-translation with no artifacts", `{"capability":"control-translation","terminal_state":"translated",
			"primary_candidate":{"artifact_id":"missing"}}`, "is not present in artifacts"},
		{"control-translation that did not translate", `{"capability":"control-translation",
			"terminal_state":"untranslatable","primary_candidate":{"artifact_id":"x"}}`,
			"translation did not complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := primaryCandidateFromResultJSON([]byte(tc.js))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestRuleEntrySelectionTakesOnlyControlTranslation pins that the upstream rule
// entry is the control-translation one and nothing else: a defense-generation
// entry alongside it is not a fallback and must not be selected.
func TestRuleEntrySelectionTakesOnlyControlTranslation(t *testing.T) {
	dg := upstreamInput{Capability: capDefenseGeneration, ResultRef: upstreamRef{Key: "dg-1"}}
	ct := upstreamInput{Capability: capControlTranslation, ResultRef: upstreamRef{Key: "ct-1"}}

	if got := selectByCapability([]upstreamInput{dg, ct}, capControlTranslation); got == nil || got.ResultRef.Key != "ct-1" {
		t.Error("the control-translation entry must be selected even when another entry precedes it")
	}
	if got := selectByCapability([]upstreamInput{dg}, capControlTranslation); got != nil {
		t.Error("a defense-generation entry must not satisfy the control-translation lookup")
	}
}
