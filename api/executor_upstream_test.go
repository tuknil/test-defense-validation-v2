package main

import (
	"testing"
)

// The rule entry is the control-translation one. A lineage entry alongside it must
// not be mistaken for the rule.
const controlTranslationUpstream = `[
  {
    "capability": "defense-generation",
    "contract_id": "defense-generation-result@1.0",
    "result_id": "defense-generation-result:c3b02e61c65fb24b3fa16aaf",
    "result_ref": {
      "system": "databricks", "catalog": "36889_janus_dev", "schema": "defense_generation",
      "table": "defense_generation_results", "key": "defense-generation-result:c3b02e61c65fb24b3fa16aaf"
    }
  },
  {
    "capability": "control-translation",
    "contract_id": "control-translation-result@2.0",
    "result_id": "control-translation-result:e0b7e5cf",
    "result_ref": {
      "system": "databricks", "catalog": "36889_janus_dev", "schema": "control_translation",
      "table": "control_translation_results", "key": "control-translation-result:e0b7e5cf"
    }
  }
]`

func TestSelectByCapability(t *testing.T) {
	entries, err := parseUpstreamInputs([]byte(controlTranslationUpstream))
	if err != nil {
		t.Fatalf("parseUpstreamInputs: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	rule := selectByCapability(entries, capControlTranslation)
	if rule == nil || rule.ResultRef.Table != "control_translation_results" ||
		rule.ResultRef.Key != "control-translation-result:e0b7e5cf" {
		t.Errorf("control-translation selection wrong: %+v", rule)
	}
	if got := selectByCapability(entries, "vuln-research"); got != nil {
		t.Errorf("absent capability should be nil, got %+v", got)
	}
}

func TestSelectByCapabilitySkipsEmptyKey(t *testing.T) {
	entries := []upstreamInput{
		{Capability: "control-translation", ResultRef: upstreamRef{Key: ""}}, // no key -> skipped
		{Capability: "control-translation", ResultRef: upstreamRef{Key: "k2", Table: "t"}},
	}
	got := selectByCapability(entries, capControlTranslation)
	if got == nil || got.ResultRef.Key != "k2" {
		t.Errorf("should skip empty-key entry, got %+v", got)
	}
}

func TestParseUpstreamInputsErrors(t *testing.T) {
	for _, in := range []string{"", "[]", "{}", "not json"} {
		if _, err := parseUpstreamInputs([]byte(in)); err == nil {
			t.Errorf("input %q: expected error", in)
		}
	}
}
