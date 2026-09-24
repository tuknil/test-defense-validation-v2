package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const sharedFixtureDir = "testdata/shared-attack-contracts-v2"

func loadSharedFixture(t *testing.T, name string) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(sharedFixtureDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func loadSharedMap(t *testing.T, name string) map[string]any {
	t.Helper()
	var value any
	if err := decodeStrictJSON(loadSharedFixture(t, name), &value); err != nil {
		t.Fatal(err)
	}
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatal("fixture is not an object")
	}
	return result
}

func loadSharedSemantics(t *testing.T) (map[string]any, sharedSemantics) {
	t.Helper()
	cg := loadSharedMap(t, "check-generation-complete-result.json")
	semantics, err := validateSharedCGDocument(cg)
	if err != nil {
		t.Fatalf("validate authoritative CG fixture: %v", err)
	}
	return cg, semantics
}

func TestSharedContractCatalogAndFixtureProvenanceAreImmutable(t *testing.T) {
	if embeddedSharedCatalogErr != nil {
		t.Fatal(embeddedSharedCatalogErr)
	}
	if embeddedRouteProfileErr != nil {
		t.Fatal(embeddedRouteProfileErr)
	}
	var provenance struct {
		ManifestVersion  int               `json:"manifest_version"`
		SourceRepository string            `json:"source_repository"`
		SourceCommit     string            `json:"source_commit"`
		SourcePath       string            `json:"source_path"`
		ProducerCommits  map[string]string `json:"producer_commits"`
		Files            map[string]struct {
			SHA256     string `json:"sha256"`
			ByteLength int64  `json:"byte_length"`
		} `json:"files"`
		Models     bool `json:"models"`
		Network    bool `json:"network"`
		Databricks bool `json:"databricks"`
	}
	if err := decodeStrictJSON(loadSharedFixture(t, "provenance.json"), &provenance); err != nil {
		t.Fatal(err)
	}
	for name, expected := range provenance.Files {
		content := loadSharedFixture(t, name)
		if sha256Value(content) != expected.SHA256 || int64(len(content)) != expected.ByteLength {
			t.Fatalf("fixture %s differs from provenance", name)
		}
	}
}

func TestAuthoritativeCGAndCandidateFixturesPassPublishedSchemas(t *testing.T) {
	cg, _ := loadSharedSemantics(t)
	if cg["content_digest"] == nil {
		t.Fatal("authoritative fixture did not exercise outer content digest")
	}
	bundle := loadSharedMap(t, "waf-atomic-v2.candidate-bundle.json")
	if err := validateSharedSchema(candidateBundleSchemaID, bundle); err != nil {
		t.Fatalf("candidate schema: %v", err)
	}
}

func TestStrictJSONRejectsDuplicateKeysAndTrailingData(t *testing.T) {
	for _, content := range []string{`{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `{} {}`} {
		var value any
		if err := decodeStrictJSON([]byte(content), &value); err == nil {
			t.Fatalf("accepted malformed JSON %s", content)
		}
	}
}

func TestSharedCGRejectsDigestAncestryAssignmentAndPartitionTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"content digest", func(cg map[string]any) { cg["content_digest"] = "sha256:" + strings.Repeat("0", 64) }},
		{"semantics digest", func(cg map[string]any) {
			delete(cg, "content_digest")
			delete(cg, "digest_profile")
			mapValue(cg["attack_match_semantics"])["semantics_digest"] = "sha256:" + strings.Repeat("0", 64)
		}},
		{"source projection", func(cg map[string]any) {
			delete(cg, "content_digest")
			delete(cg, "digest_profile")
			semantics := mapValue(cg["attack_match_semantics"])
			mapValue(mapValue(semantics["source_binding"])["check_generation"])["source_projection_digest"] = "sha256:" + strings.Repeat("0", 64)
			resignSemantics(t, semantics)
		}},
		{"member ancestry", func(cg map[string]any) {
			member := mapValue(anySlice(cg["member_results"])[0])
			member["signal_id"] = "invented"
			resignCG(t, cg)
		}},
		{"duplicate assignment", func(cg map[string]any) {
			semantics := mapValue(cg["attack_match_semantics"])
			obligation := mapValue(anySlice(semantics["obligations"])[0])
			refs := anySlice(obligation["required_input_refs"])
			obligation["required_input_refs"] = append(refs, refs[0])
			resignCG(t, cg)
		}},
		{"incomplete partition", func(cg map[string]any) {
			semantics := mapValue(cg["attack_match_semantics"])
			unsupported := anySlice(semantics["unsupported_dimensions"])
			semantics["unsupported_dimensions"] = unsupported[:2]
			resignCG(t, cg)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cg := loadSharedMap(t, "check-generation-complete-result.json")
			test.mutate(cg)
			if _, err := validateSharedCGDocument(cg); err == nil {
				t.Fatal("tampered CG document accepted")
			}
		})
	}
}

func resignSemantics(t *testing.T, semantics map[string]any) {
	t.Helper()
	preimage := cloneMap(semantics)
	delete(preimage, "semantics_digest")
	semantics["semantics_digest"] = digestAny(preimage)
}
func resignCG(t *testing.T, cg map[string]any) {
	t.Helper()
	delete(cg, "content_digest")
	delete(cg, "digest_profile")
	semantics := mapValue(cg["attack_match_semantics"])
	projection := map[string]any{}
	for _, key := range []string{"artifacts", "input_membership", "member_results", "test_inputs"} {
		projection[key] = cg[key]
	}
	mapValue(mapValue(semantics["source_binding"])["check_generation"])["source_projection_digest"] = digestAny(projection)
	resignSemantics(t, semantics)
}

// architectureBundle loads the authoritative candidate bundle and reads its
// complete artifact set back, returning the bundle and the rule that readback
// produced.
func architectureBundle(t *testing.T) (sharedCandidateBundle, CandidateSpec) {
	t.Helper()
	bundleBytes := loadSharedFixture(t, "waf-atomic-v2.candidate-bundle.json")
	var bundle sharedCandidateBundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatal(err)
	}
	contents := map[string][]byte{"artifact-main": loadSharedFixture(t, "waf-rule-main.json"), "artifact-carriers": loadSharedFixture(t, "waf-rule-carriers.json")}
	cand, applied, err := sharedV2ApplicationUnit(bundle, contents)
	if err != nil {
		t.Fatalf("read back complete application unit: %v", err)
	}
	if !applied.ReadbackVerified || len(applied.ArtifactIDs) != 2 {
		t.Fatalf("application unit = %#v", applied)
	}
	return bundle, cand
}

// TestApplicationUnitReadbackYieldsTheRuleItself confirms the readback reports
// the match-rule document's own bytes as the rule to push, rather than anything
// derived from executing it.
func TestApplicationUnitReadbackYieldsTheRuleItself(t *testing.T) {
	_, cand := architectureBundle(t)
	if cand.Kind != "waf-rule" || cand.Action != "block" {
		t.Errorf("candidate = %+v", cand)
	}
	if cand.RuleID == "" {
		t.Error("candidate must carry the bundle's candidate_id")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(cand.Rule), &doc); err != nil {
		t.Fatalf("rule is not the match-rule document: %v", err)
	}
	if doc["rules"] == nil {
		t.Error("the reported rule must be the match-rule document")
	}
}

func TestApplicationUnitRejectsOmittedAndInventedArtifacts(t *testing.T) {
	bundle, _ := architectureBundle(t)
	contents := map[string][]byte{"artifact-main": loadSharedFixture(t, "waf-rule-main.json")}
	if _, _, err := sharedV2ApplicationUnit(bundle, contents); err == nil {
		t.Fatal("omitted supporting artifact accepted")
	}
	contents["artifact-carriers"] = loadSharedFixture(t, "waf-rule-carriers.json")
	contents["invented"] = []byte(`{}`)
	if _, _, err := sharedV2ApplicationUnit(bundle, contents); err == nil {
		t.Fatal("invented artifact accepted")
	}
}

func validLocalBundle(t *testing.T) (map[string]any, sharedCandidateBundle, map[string][]byte, ImmutableResultLocator, map[string]any, sharedSemantics) {
	t.Helper()
	cg, semantics := loadSharedSemantics(t)
	check := ImmutableResultLocator{ResultRef: upstreamRef{Catalog: locatorCatalog, Schema: checkSchema, Table: checkTable, Key: "check-generation-result:test"}}
	cgBytes, _ := marshalRFC8785(cg)
	bundleDoc := loadSharedMap(t, "waf-atomic-v2.candidate-bundle.json")
	binding := mapValue(bundleDoc["semantics_binding"])
	binding["locator"] = map[string]any{"uri": "databricks-result:///36889_janus_dev/check_generation/check_generation_results/check-generation-result:test", "digest": sha256Value(cgBytes), "media_type": "application/json", "byte_length": len(cgBytes), "immutable": true}
	contents := map[string][]byte{}
	for _, name := range []string{"waf-rule-main.json", "waf-rule-carriers.json"} {
		var value any
		if err := decodeStrictJSON(loadSharedFixture(t, name), &value); err != nil {
			t.Fatal(err)
		}
		content, _ := marshalRFC8785(value)
		id := map[string]string{"waf-rule-main.json": "artifact-main", "waf-rule-carriers.json": "artifact-carriers"}[name]
		contents[id] = content
	}
	resultID := "defense-generation-result:test"
	artifacts := anySlice(mapValue(bundleDoc["primary_candidate"])["artifacts"])
	for _, raw := range artifacts {
		artifact := mapValue(raw)
		id := stringValue(artifact["artifact_id"])
		content := contents[id]
		artifact["content"] = map[string]any{"uri": "janus-result-internal:defense-generation-result%3Atest#/candidate_artifact_contents/" + id, "digest": sha256Value(content), "media_type": "application/json", "byte_length": len(content), "immutable": true}
	}
	resignBundle(bundleDoc)
	encoded, _ := json.Marshal(bundleDoc)
	var bundle sharedCandidateBundle
	if err := json.Unmarshal(encoded, &bundle); err != nil {
		t.Fatal(err)
	}
	if err := validateSharedBundle(bundleDoc, bundle, contents, resultID, check, cg, semantics); err != nil {
		t.Fatalf("valid local bundle: %v", err)
	}
	return bundleDoc, bundle, contents, check, cg, semantics
}

func resignBundle(bundle map[string]any) {
	candidate := mapValue(bundle["primary_candidate"])
	candidatePreimage := cloneMap(candidate)
	delete(candidatePreimage, "candidate_digest")
	candidate["candidate_digest"] = digestAny(candidatePreimage)
	bundlePreimage := cloneMap(bundle)
	delete(bundlePreimage, "bundle_digest")
	delete(mapValue(bundlePreimage["primary_candidate"]), "candidate_digest")
	bundle["bundle_digest"] = digestAny(bundlePreimage)
}

func TestCandidateBundleRejectsMappingsLocatorsAncestryAndApplicationTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any, map[string][]byte)
	}{
		{"duplicate mapping", func(bundle map[string]any, _ map[string][]byte) {
			candidate := mapValue(bundle["primary_candidate"])
			mappings := anySlice(candidate["obligation_mappings"])
			candidate["obligation_mappings"] = append(mappings, mappings[0])
		}},
		{"mapping ancestry", func(bundle map[string]any, _ map[string][]byte) {
			mapping := mapValue(anySlice(mapValue(bundle["primary_candidate"])["obligation_mappings"])[0])
			refs := anySlice(mapping["source_member_refs"])
			mapping["source_member_refs"] = refs[:1]
		}},
		{"application omission", func(bundle map[string]any, _ map[string][]byte) {
			unit := mapValue(bundle["application_unit"])
			unit["artifact_refs"] = anySlice(unit["artifact_refs"])[:1]
		}},
		{"candidate locator", func(bundle map[string]any, _ map[string][]byte) {
			artifact := mapValue(anySlice(mapValue(bundle["primary_candidate"])["artifacts"])[0])
			mapValue(artifact["content"])["uri"] = "janus-result-internal:wrong#/candidate_artifact_contents/artifact-main"
		}},
		{"artifact bytes", func(_ map[string]any, contents map[string][]byte) {
			contents["artifact-main"] = []byte(`{"changed":true}`)
		}},
		{"semantics binding", func(bundle map[string]any, _ map[string][]byte) {
			mapValue(bundle["semantics_binding"])["semantics_digest"] = "sha256:" + strings.Repeat("0", 64)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bundleDoc, _, contents, check, cg, semantics := validLocalBundle(t)
			test.mutate(bundleDoc, contents)
			resignBundle(bundleDoc)
			encoded, _ := json.Marshal(bundleDoc)
			var bundle sharedCandidateBundle
			_ = json.Unmarshal(encoded, &bundle)
			if err := validateSharedBundle(bundleDoc, bundle, contents, "defense-generation-result:test", check, cg, semantics); err == nil {
				t.Fatal("tampered candidate bundle accepted")
			}
		})
	}
}

func regexpMust(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	value, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestV2RequestIsCompactAndLegacyReplayRemainsValid(t *testing.T) {
	_, defense, check, _ := locatorFixture(t, false)
	check.ContractID = "check-generation@2.1"
	request := SubmitDefenseValidationRequest{ContractID: contractID, RequestID: "request", CorrelationID: defense.CorrelationID, RoutePolicy: sharedV2RoutePolicy, ProfileID: sharedV2ProfileID, DefenseResult: &defense, CheckResult: &check}
	if fields := validate(request); len(fields) != 0 {
		t.Fatalf("valid v2 request: %v", fields)
	}
	legacyCheck := check
	legacyCheck.ContractID = "check-generation-result@1.0"
	request.CheckResult = &legacyCheck
	if fields := validate(request); !hasField(fields, "check_result") {
		t.Fatalf("shared v2 request accepted legacy Check Generation locator: %v", fields)
	}
	request.CheckResult = &check
	request.Candidate = json.RawMessage(`{}`)
	if fields := validate(request); !hasField(fields, "inline_content") {
		t.Fatalf("hydrated body accepted: %v", fields)
	}
	request.Candidate = nil
	if fields := validate(validLifecycleRequest("legacy-v2-regression")); len(fields) != 0 {
		t.Fatalf("legacy replay changed: %v", fields)
	}
}

func TestOpenAPIV2SchemaReferencesAreSynchronized(t *testing.T) {
	spec := string(openapiSpec)
	for _, required := range []string{"shared-attack-contracts-v2", "profile_id:", "AppliedApplicationUnit:"} {
		if !strings.Contains(spec, required) {
			t.Fatalf("OpenAPI is missing %q", required)
		}
	}
	definitions := map[string]bool{}
	definitionPattern := regexp.MustCompile(`(?m)^    ([A-Za-z][A-Za-z0-9]*):\s*$`)
	for _, match := range definitionPattern.FindAllStringSubmatch(spec, -1) {
		definitions[match[1]] = true
	}
	referencePattern := regexp.MustCompile(`#/components/schemas/([A-Za-z][A-Za-z0-9]*)`)
	for _, match := range referencePattern.FindAllStringSubmatch(spec, -1) {
		if !definitions[match[1]] {
			t.Fatalf("OpenAPI reference %s has no schema definition", match[1])
		}
	}
}
