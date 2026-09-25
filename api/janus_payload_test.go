package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func fixtureCustomWAFRule(t *testing.T) CustomWAFRule {
	t.Helper()
	rule, err := ExtractCustomWAFRule(controlTranslationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func demoPayloadOptions() JanusPayloadOptions {
	return JanusPayloadOptions{
		CVE:               "CVE-2025-64446",
		PolicyVersion:     43,
		PolicyID:          "policy-1",
		RuleID:            60022381,
		ControlInstanceID: "control-instance:akamai-production",
		ProtectedHostname: "afo.example.com",
		TargetScopeID:     "population-scope:prod-web",
		RecoverySpecRef:   "recovery-spec:550e8400-e29b-41d4-a716-446655440007",
	}
}

// ruleSetWith builds a two-alternative OR set whose second alternative is
// produced by mutating the first, so a test can vary exactly one thing.
func ruleSetWith(t *testing.T, mutate func(alt *akamaiAlternative)) CustomWAFRule {
	t.Helper()
	base := akamaiAlternative{
		Name: "alt-0", Operation: "AND", SourceAction: "block",
		Conditions: []akamaiCondition{
			{Type: "pathMatch", MatchOperator: "exact", PositiveMatch: true, Value: []string{"/a"}},
			{Type: "argsPostMatch", MatchOperator: "regex", PositiveMatch: true, Value: []string{"x=1"}, SourceCarrier: "body"},
		},
	}
	second := akamaiAlternative{
		Name: "alt-1", Operation: "AND", SourceAction: "block",
		Conditions: []akamaiCondition{
			{Type: "pathMatch", MatchOperator: "exact", PositiveMatch: true, Value: []string{"/a"}},
			{Type: "argsPostMatch", MatchOperator: "regex", PositiveMatch: true, Value: []string{"x=2"}, SourceCarrier: "body"},
		},
	}
	mutate(&second)
	encoded, err := json.Marshal(akamaiRuleSet{
		ConfigurationType: "akamai-custom-rule-set", CombinationOperation: "OR",
		Rules: []akamaiAlternative{base, second},
	})
	if err != nil {
		t.Fatal(err)
	}
	return CustomWAFRule{Content: encoded, ContentHash: "sha256:" + strings.Repeat("a", 64)}
}

// TestJanusPayloadFromTheFixtureRule builds the payload from the real
// control-translation artifact and checks every mapped field.
func TestJanusPayloadFromTheFixtureRule(t *testing.T) {
	payload, err := JanusPayloadFromCustomWAFRule(fixtureCustomWAFRule(t), demoPayloadOptions())
	if err != nil {
		t.Fatalf("build payload: %v", err)
	}

	if payload.ArtifactSchema != "akamai-appsec-compound-realization@0.2" || payload.Operation != "set-policy-action" {
		t.Errorf("schema/operation = %q / %q", payload.ArtifactSchema, payload.Operation)
	}
	if payload.NativeBinding.Version != 43 || payload.NativeBinding.PolicyID != "policy-1" || payload.NativeBinding.RuleID != 60022381 {
		t.Errorf("native_binding = %+v", payload.NativeBinding)
	}
	// sourceAction "block" is an Akamai policy "deny"; the shadow state it is
	// promoted from is "alert".
	if payload.ExpectedCurrentPolicyAction.Action != "alert" || payload.DesiredPolicyAction.Action != "deny" {
		t.Errorf("action transition = %q -> %q",
			payload.ExpectedCurrentPolicyAction.Action, payload.DesiredPolicyAction.Action)
	}

	rule := payload.StructuredRule
	if rule.Name != "Janus-Block-CVE-2025-64446" || rule.Operation != "AND" || !rule.Structured {
		t.Errorf("structured_rule head = %+v", rule)
	}
	if len(rule.Tag) != 2 || rule.Tag[0] != "janus" || rule.Tag[1] != "CVE-2025-64446" {
		t.Errorf("tag = %v", rule.Tag)
	}

	// The fixture's two alternatives share path and method and differ only in the
	// body pattern, so the collapse keeps three conditions and unions that one.
	if len(rule.Conditions) != 3 {
		t.Fatalf("expected 3 conditions, got %d: %+v", len(rule.Conditions), rule.Conditions)
	}
	byType := map[string][]string{}
	for _, c := range rule.Conditions {
		byType[c.Type] = c.Value
	}
	if got := byType["pathMatch"]; len(got) != 1 || got[0] != "/public/submit.php" {
		t.Errorf("pathMatch = %v, want the single shared route", got)
	}
	if got := byType["requestMethodMatch"]; len(got) != 1 || got[0] != "POST" {
		t.Errorf("requestMethodMatch = %v", got)
	}
	body := byType["argsPostMatch"]
	if len(body) != 2 {
		t.Fatalf("argsPostMatch should carry both alternatives' patterns, got %v", body)
	}
	for _, want := range []string{`saveUser=1&Researcher='`, `person\[0\]\[\]=malicious`} {
		found := false
		for _, got := range body {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("argsPostMatch is missing %q (got %v)", want, body)
		}
	}

	binding := payload.JanusBinding
	if binding.CandidateID != "control-candidate:CVE-2026-77392:akamai-waf:e6fcf665eb9f311e" {
		t.Errorf("candidate_id = %q", binding.CandidateID)
	}
	if binding.CandidateDigest != fixtureCustomWAFRule(t).ContentHash {
		t.Errorf("candidate_digest = %q", binding.CandidateDigest)
	}
	if !strings.HasPrefix(binding.RealizedArtifactDigest, "sha256:") || len(binding.RealizedArtifactDigest) != 71 {
		t.Errorf("realized_artifact_digest = %q", binding.RealizedArtifactDigest)
	}
	if binding.ControlInstanceID != "control-instance:akamai-production" || binding.ProtectedHostname != "afo.example.com" {
		t.Errorf("binding target = %+v", binding)
	}
	// Live state was not read, so the hash stays empty rather than invented.
	if binding.ExpectedLiveStateHash != "" {
		t.Errorf("expected_live_state_hash should be empty when not supplied, got %q", binding.ExpectedLiveStateHash)
	}
}

// TestRealizedArtifactDigestCoversTheEmittedRule checks the digest describes the
// structured rule actually carried, so it cannot drift from it.
func TestRealizedArtifactDigestCoversTheEmittedRule(t *testing.T) {
	payload, err := JanusPayloadFromCustomWAFRule(fixtureCustomWAFRule(t), demoPayloadOptions())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(payload.StructuredRule)
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256Prefixed(encoded); payload.JanusBinding.RealizedArtifactDigest != want {
		t.Errorf("realized_artifact_digest = %q, want %q", payload.JanusBinding.RealizedArtifactDigest, want)
	}
}

// TestMergeRefusesWhenTwoPositionsVary is the correctness case that matters most.
// Unioning both positions would also match /a with x=2 and /b with x=1 — traffic
// the validated rule set never covered — so it must be refused, not widened.
func TestMergeRefusesWhenTwoPositionsVary(t *testing.T) {
	rule := ruleSetWith(t, func(alt *akamaiAlternative) {
		alt.Conditions[0].Value = []string{"/b"} // path AND body both differ
	})
	_, err := JanusPayloadFromCustomWAFRule(rule, demoPayloadOptions())
	if err == nil {
		t.Fatal("collapsing two varying positions silently widens the rule and must be refused")
	}
	if !strings.Contains(err.Error(), "one issue per alternative") {
		t.Errorf("error should say what to do instead: %v", err)
	}
}

func TestMergeRefusesMismatchedStructure(t *testing.T) {
	t.Run("different condition count", func(t *testing.T) {
		rule := ruleSetWith(t, func(alt *akamaiAlternative) {
			alt.Conditions = alt.Conditions[:1]
		})
		if _, err := JanusPayloadFromCustomWAFRule(rule, demoPayloadOptions()); err == nil {
			t.Fatal("alternatives with different condition counts must be refused")
		}
	})
	t.Run("different condition shape", func(t *testing.T) {
		rule := ruleSetWith(t, func(alt *akamaiAlternative) {
			alt.Conditions[1].MatchOperator = "exact" // regex vs exact is not the same match
		})
		if _, err := JanusPayloadFromCustomWAFRule(rule, demoPayloadOptions()); err == nil {
			t.Fatal("alternatives whose conditions match differently must be refused")
		}
	})
	t.Run("negated vs positive", func(t *testing.T) {
		rule := ruleSetWith(t, func(alt *akamaiAlternative) {
			alt.Conditions[1].PositiveMatch = false
		})
		if _, err := JanusPayloadFromCustomWAFRule(rule, demoPayloadOptions()); err == nil {
			t.Fatal("a negated condition must not merge with a positive one")
		}
	})
}

func TestPolicyActionRequiresAgreement(t *testing.T) {
	rule := ruleSetWith(t, func(alt *akamaiAlternative) {
		alt.SourceAction = "alert" // one blocks, one alerts
	})
	_, err := JanusPayloadFromCustomWAFRule(rule, demoPayloadOptions())
	if err == nil {
		t.Fatal("alternatives that disagree on action have no single policy action")
	}
	if !strings.Contains(err.Error(), "sourceAction") {
		t.Errorf("error should name the disagreement: %v", err)
	}
}

func TestJanusPayloadRejectsUnusableInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		rule CustomWAFRule
		opts JanusPayloadOptions
		want string
	}{
		{"no CVE", fixtureCustomWAFRule(&testing.T{}), JanusPayloadOptions{}, "CVE is required"},
		{"empty rule", CustomWAFRule{}, demoPayloadOptions(), "no content"},
		{"not JSON", CustomWAFRule{Content: []byte("SecRule ARGS \"@rx x\"")}, demoPayloadOptions(), "not an Akamai custom rule set"},
		{
			"wrong configuration type",
			CustomWAFRule{Content: []byte(`{"configurationType":"akamai-carrier-bindings"}`)},
			demoPayloadOptions(), "unsupported configurationType",
		},
		{
			"no rules",
			CustomWAFRule{Content: []byte(`{"configurationType":"akamai-custom-rule-set","rules":[]}`)},
			demoPayloadOptions(), "no rules",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := JanusPayloadFromCustomWAFRule(tc.rule, tc.opts)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestSingleAlternativePassesThrough: nothing to collapse, so the conditions are
// carried across exactly.
func TestSingleAlternativePassesThrough(t *testing.T) {
	encoded, err := json.Marshal(akamaiRuleSet{
		ConfigurationType: "akamai-custom-rule-set", CombinationOperation: "OR",
		Rules: []akamaiAlternative{{
			Name: "only", Operation: "AND", SourceAction: "block",
			Conditions: []akamaiCondition{
				{Type: "pathMatch", MatchOperator: "exact", PositiveMatch: true, Value: []string{"/a", "/b"}, ValueWildcard: true},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := JanusPayloadFromCustomWAFRule(CustomWAFRule{Content: encoded}, demoPayloadOptions())
	if err != nil {
		t.Fatalf("single alternative: %v", err)
	}
	conditions := payload.StructuredRule.Conditions
	if len(conditions) != 1 || len(conditions[0].Value) != 2 || !conditions[0].ValueWildcard {
		t.Errorf("conditions = %+v", conditions)
	}
}

// TestPayloadEmbedsCleanlyInAnIssue ties the two halves together: the payload
// built from a rule must survive the double encoding into custom_fields.
func TestPayloadEmbedsCleanlyInAnIssue(t *testing.T) {
	payload, err := JanusPayloadFromCustomWAFRule(fixtureCustomWAFRule(t), demoPayloadOptions())
	if err != nil {
		t.Fatal(err)
	}
	var fields JanusCustomFields
	if err := fields.SetPayload(payload); err != nil {
		t.Fatalf("embed payload: %v", err)
	}
	var round JanusPayload
	if err := json.Unmarshal([]byte(fields.Payload), &round); err != nil {
		t.Fatalf("embedded payload does not parse: %v", err)
	}
	if round.StructuredRule.Name != payload.StructuredRule.Name ||
		len(round.StructuredRule.Conditions) != len(payload.StructuredRule.Conditions) {
		t.Errorf("payload did not survive embedding: %+v", round.StructuredRule)
	}
	if fields.PayloadHash != sha256Prefixed([]byte(fields.Payload)) {
		t.Error("januspayloadhash must cover the embedded bytes")
	}
}
