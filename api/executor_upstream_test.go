package main

import (
	"testing"
)

// Two upstream_inputs entries: defense-generation (rule) + check-generation (test).
const twoEntryUpstream = `[
  {
    "capability": "defense-generation",
    "contract_id": "defense-generation@1.0",
    "result_id": "defense-generation-result:c3b02e61c65fb24b3fa16aaf",
    "result_ref": {
      "system": "databricks", "catalog": "36889_janus_dev", "schema": "defense_generation",
      "table": "defense_generation_results", "key": "defense-generation-result:c3b02e61c65fb24b3fa16aaf"
    }
  },
  {
    "capability": "check-generation",
    "contract_id": "check-generation@1.0",
    "result_id": "check-generation-run-result:sha256:6f02",
    "result_ref": {
      "system": "databricks", "catalog": "36889_janus_dev", "schema": "check_generation",
      "table": "check_generation_results", "key": "check-generation-run-result:sha256:6f02"
    }
  }
]`

func TestSelectByCapability(t *testing.T) {
	entries, err := parseUpstreamInputs([]byte(twoEntryUpstream))
	if err != nil {
		t.Fatalf("parseUpstreamInputs: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}

	rule := selectByCapability(entries, capDefenseGeneration)
	if rule == nil || rule.ResultRef.Table != "defense_generation_results" ||
		rule.ResultRef.Key != "defense-generation-result:c3b02e61c65fb24b3fa16aaf" {
		t.Errorf("defense-generation selection wrong: %+v", rule)
	}
	check := selectByCapability(entries, capCheckGeneration)
	if check == nil || check.ResultRef.Table != "check_generation_results" {
		t.Errorf("check-generation selection wrong: %+v", check)
	}
	if got := selectByCapability(entries, "vuln-research"); got != nil {
		t.Errorf("absent capability should be nil, got %+v", got)
	}
}

func TestSelectByCapabilitySkipsEmptyKey(t *testing.T) {
	entries := []upstreamInput{
		{Capability: "defense-generation", ResultRef: upstreamRef{Key: ""}}, // no key -> skipped
		{Capability: "defense-generation", ResultRef: upstreamRef{Key: "k2", Table: "t"}},
	}
	got := selectByCapability(entries, capDefenseGeneration)
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
