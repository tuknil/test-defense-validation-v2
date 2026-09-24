package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func controlTranslationFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/control-translation-result.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// reserialize rewrites the fixture through a generic map so a test can mutate one
// field without hand-editing the document.
func mutateControlTranslation(t *testing.T, raw []byte, edit func(doc map[string]any)) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestExtractCustomWAFRuleReturnsThePrimaryCandidateArtifact(t *testing.T) {
	rule, err := ExtractCustomWAFRule(controlTranslationFixture(t))
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	const wantID = "akamai-rule-set-e6fcf665eb9f311ecc8a569707b67a7ca9b6fd6a49a899511513d2e1c4796a1b"
	if rule.ArtifactID != wantID {
		t.Errorf("artifact_id = %q, want %q", rule.ArtifactID, wantID)
	}
	if rule.ArtifactType != "akamai-waf-rule-set" {
		t.Errorf("artifact_type = %q", rule.ArtifactType)
	}
	if rule.Technology != "akamai-waf" || rule.ControlClass != "waf" {
		t.Errorf("technology/control class = %q/%q", rule.Technology, rule.ControlClass)
	}

	// It must be the rule SET, not one of the three supporting fragments.
	var ruleSet struct {
		ConfigurationType    string `json:"configurationType"`
		CombinationOperation string `json:"combinationOperation"`
		Rules                []struct {
			Name         string `json:"name"`
			SourceAction string `json:"sourceAction"`
			Conditions   []struct {
				Type  string   `json:"type"`
				Value []string `json:"value"`
			} `json:"conditions"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(rule.Content, &ruleSet); err != nil {
		t.Fatalf("rule content is not a rule set: %v", err)
	}
	if ruleSet.ConfigurationType != "akamai-custom-rule-set" {
		t.Errorf("configurationType = %q", ruleSet.ConfigurationType)
	}
	if ruleSet.CombinationOperation != "OR" {
		t.Errorf("combinationOperation = %q", ruleSet.CombinationOperation)
	}
	if len(ruleSet.Rules) != 2 {
		t.Fatalf("expected 2 alternatives, got %d", len(ruleSet.Rules))
	}
	for _, r := range ruleSet.Rules {
		if r.SourceAction != "block" {
			t.Errorf("rule %q action = %q, want block", r.Name, r.SourceAction)
		}
		if len(r.Conditions) != 3 {
			t.Errorf("rule %q has %d conditions, want 3", r.Name, len(r.Conditions))
		}
	}

	// Content is returned as the exact hashed bytes, so a caller can re-verify.
	sum := sha256.Sum256(rule.Content)
	if got := "sha256:" + hex.EncodeToString(sum[:]); got != rule.ContentHash {
		t.Errorf("returned content does not match reported hash: %s vs %s", got, rule.ContentHash)
	}

	// The deployment caveats survive, since they gate whether this can be applied.
	if rule.Metadata.SyntaxProfile.ValidationLevel != "shape-only" {
		t.Errorf("validation_level = %q", rule.Metadata.SyntaxProfile.ValidationLevel)
	}
	if rule.Metadata.SyntaxProfile.DeploymentReady {
		t.Error("deployment_ready should be false in this fixture")
	}
	if rule.Metadata.RecommendedPolicyBinding.Action != "deny" {
		t.Errorf("binding action = %q", rule.Metadata.RecommendedPolicyBinding.Action)
	}
	if rule.Metadata.RecommendedPolicyBinding.EmbeddedInArtifact {
		t.Error("the artifact does not embed its own action; binding must be applied separately")
	}
}

func TestPrintCustomWAFRuleEmitsHeaderAndIndentedRule(t *testing.T) {
	var out bytes.Buffer
	if err := PrintCustomWAFRule(&out, controlTranslationFixture(t)); err != nil {
		t.Fatalf("print: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"// artifact_id:   akamai-rule-set-e6fcf665",
		"// technology:    akamai-waf (control class waf)",
		"(verified)",
		"validation_level=shape-only",
		`"configurationType": "akamai-custom-rule-set"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output is missing %q", want)
		}
	}
	// The rule body must be the indented form, not the escaped one-line string.
	if strings.Contains(text, `\"configurationType\"`) {
		t.Error("rule was printed still escaped rather than decoded")
	}

	// Everything after the comment header must parse as the rule on its own.
	body := text[strings.Index(text, "{"):]
	if !json.Valid([]byte(body)) {
		t.Error("the non-comment portion of the output is not valid JSON")
	}
}

func TestExtractCustomWAFRuleRejectsUnusableDocuments(t *testing.T) {
	fixture := controlTranslationFixture(t)

	for _, tc := range []struct {
		name string
		raw  []byte
		want string
	}{
		{"not json", []byte(`{`), "parse control-translation result"},
		{
			"wrong capability",
			mutateControlTranslation(t, fixture, func(d map[string]any) {
				d["capability"] = "defense-generation"
			}),
			"not a control-translation result",
		},
		{
			"did not translate",
			mutateControlTranslation(t, fixture, func(d map[string]any) {
				d["terminal_state"] = "untranslatable"
			}),
			"translation did not complete",
		},
		{
			"no artifact id",
			mutateControlTranslation(t, fixture, func(d map[string]any) {
				d["primary_candidate"].(map[string]any)["artifact_id"] = ""
			}),
			"primary_candidate.artifact_id is missing",
		},
		{
			"artifact id not in map",
			mutateControlTranslation(t, fixture, func(d map[string]any) {
				d["primary_candidate"].(map[string]any)["artifact_id"] = "akamai-rule-set-absent"
			}),
			"is not present in artifacts",
		},
		{
			"candidate and artifact hashes disagree",
			mutateControlTranslation(t, fixture, func(d map[string]any) {
				d["primary_candidate"].(map[string]any)["content_hash"] = "sha256:" + strings.Repeat("0", 64)
			}),
			"content_hash disagrees",
		},
		{
			"content tampered",
			mutateControlTranslation(t, fixture, func(d map[string]any) {
				pc := d["primary_candidate"].(map[string]any)
				id := pc["artifact_id"].(string)
				artifacts := d["artifacts"].(map[string]any)
				a := artifacts[id].(map[string]any)
				// Flip the blocking action; the hash no longer covers the content.
				// The content is already decoded here, so match the unescaped form.
				content := a["content"].(string)
				tampered := strings.Replace(content, `"sourceAction":"block"`,
					`"sourceAction":"allow"`, 1)
				if tampered == content {
					t.Fatal("tamper edit matched nothing — the test would not prove anything")
				}
				a["content"] = tampered
			}),
			"does not match its content_hash",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExtractCustomWAFRule(tc.raw)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

// A silently substituted rule is the failure that matters most here: the caller
// would deploy a control that does not block what it claims to.
func TestExtractCustomWAFRuleRefusesASwappedSupportingArtifact(t *testing.T) {
	raw := mutateControlTranslation(t, controlTranslationFixture(t), func(d map[string]any) {
		pc := d["primary_candidate"].(map[string]any)
		// Point the candidate at a supporting carrier-configuration fragment while
		// leaving its declared hash alone.
		pc["artifact_id"] = "akamai-artifact-sha256-f6b3b9cb21374a656a7ccfd82c756c02128b22a201b4efbc9365e843b2ebaf4b"
	})
	if _, err := ExtractCustomWAFRule(raw); err == nil {
		t.Fatal("a candidate whose hash does not match the named artifact must be rejected")
	}
}
