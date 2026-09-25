package main

// janus_payload.go turns a resolved custom WAF rule into the januspayload
// document an XSIAM enforcement issue carries.
//
// The shapes do not line up on their own. A control-translation
// akamai-custom-rule-set is a disjunction: `combinationOperation: OR` over
// alternatives that are each a conjunction of conditions. XSIAM's structured_rule
// is a single rule with one operation over one list of conditions. Collapsing an
// OR of ANDs into a single AND is only sound in one case, and getting it wrong
// changes what the control blocks — so the collapse is checked rather than
// assumed. See mergeAlternatives.
//
// The rule supplies WHAT to enforce. It does not carry WHERE: the Akamai policy
// coordinates, the target identifiers and the live-state hash come from the
// caller via JanusPayloadOptions, because nothing in the artifact knows them and
// inventing them would produce an issue that targets the wrong control.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// akamaiRuleSet is the control-translation primary artifact.
type akamaiRuleSet struct {
	ConfigurationType    string              `json:"configurationType"`
	CombinationOperation string              `json:"combinationOperation"`
	Description          string              `json:"description"`
	Rules                []akamaiAlternative `json:"rules"`
	SourceCandidateID    string              `json:"sourceCandidateId"`
}

// akamaiAlternative is one route-bound conjunction.
type akamaiAlternative struct {
	Name         string            `json:"name"`
	Operation    string            `json:"operation"`
	SourceAction string            `json:"sourceAction"`
	Conditions   []akamaiCondition `json:"conditions"`
}

// akamaiCondition is one match. The fields other than Value make up the
// condition's shape: two conditions with the same shape differ only in what they
// match, which is what makes a merge decidable.
type akamaiCondition struct {
	Type            string   `json:"type"`
	MatchOperator   string   `json:"matchOperator"`
	PositiveMatch   bool     `json:"positiveMatch"`
	Value           []string `json:"value"`
	ValueCase       bool     `json:"valueCase"`
	ValueWildcard   bool     `json:"valueWildcard"`
	SourceCarrier   string   `json:"sourceCarrier,omitempty"`
	SourceSelector  string   `json:"sourceSelector,omitempty"`
	Transformations []string `json:"transformations,omitempty"`
}

// shape is everything about a condition except the values it matches.
func (c akamaiCondition) shape() string {
	return strings.Join([]string{
		c.Type, c.MatchOperator, fmt.Sprint(c.PositiveMatch), fmt.Sprint(c.ValueCase),
		fmt.Sprint(c.ValueWildcard), c.SourceCarrier, c.SourceSelector,
		strings.Join(c.Transformations, "|"),
	}, "\x00")
}

// JanusPayloadOptions carries what the rule itself cannot know.
type JanusPayloadOptions struct {
	// CVE labels the rule and tags it. Required: it is not derivable from the
	// artifact, and a wrong or missing threat id makes the issue untriageable.
	CVE string `json:"cve"`

	// Akamai policy coordinates for the rule being changed.
	PolicyVersion int    `json:"policy_version"`
	PolicyID      string `json:"policy_id"`
	RuleID        int64  `json:"rule_id"`

	// Where the control lives.
	ControlInstanceID string `json:"control_instance_id"`
	ProtectedHostname string `json:"protected_hostname"`
	TargetScopeID     string `json:"target_scope_id"`

	// ExpectedCurrentAction is the action the policy is expected to be in now, so
	// the execution seam can refuse a change it did not plan for. Defaults to
	// "alert" — the shadow state a validated candidate is promoted from.
	ExpectedCurrentAction string `json:"expected_current_action,omitempty"`

	// ExpectedLiveStateHash is the caller's hash of current live state. Left empty
	// when the caller has not read live state; it is never invented here.
	ExpectedLiveStateHash string `json:"expected_live_state_hash,omitempty"`

	RecoverySpecRef string `json:"recovery_spec_ref,omitempty"`
}

// JanusPayloadFromCustomWAFRule builds the januspayload document from a resolved
// rule. It fails rather than emitting a payload that would enforce something
// other than what the rule set expresses.
func JanusPayloadFromCustomWAFRule(rule CustomWAFRule, opts JanusPayloadOptions) (JanusPayload, error) {
	if strings.TrimSpace(opts.CVE) == "" {
		return JanusPayload{}, fmt.Errorf("CVE is required: it is not carried by the rule artifact")
	}
	if len(rule.Content) == 0 {
		return JanusPayload{}, fmt.Errorf("rule has no content")
	}

	var set akamaiRuleSet
	if err := json.Unmarshal(rule.Content, &set); err != nil {
		return JanusPayload{}, fmt.Errorf("rule is not an Akamai custom rule set: %w", err)
	}
	if set.ConfigurationType != "akamai-custom-rule-set" {
		return JanusPayload{}, fmt.Errorf(
			"unsupported configurationType %q: this mapping handles akamai-custom-rule-set", set.ConfigurationType)
	}
	if len(set.Rules) == 0 {
		return JanusPayload{}, fmt.Errorf("rule set contains no rules")
	}

	merged, err := mergeAlternatives(set)
	if err != nil {
		return JanusPayload{}, err
	}

	action, err := policyActionFor(set)
	if err != nil {
		return JanusPayload{}, err
	}

	structured := JanusStructuredRule{
		Name:       "Janus-Block-" + opts.CVE,
		Operation:  "AND",
		Structured: true,
		Conditions: merged,
		Tag:        []string{"janus", opts.CVE},
	}

	var payload JanusPayload
	payload.ArtifactSchema = "akamai-appsec-compound-realization@0.2"
	payload.Operation = "set-policy-action"
	payload.NativeBinding.Version = opts.PolicyVersion
	payload.NativeBinding.PolicyID = opts.PolicyID
	payload.NativeBinding.RuleID = opts.RuleID
	payload.StructuredRule = structured
	payload.ExpectedCurrentPolicyAction.Action = firstNonEmpty(opts.ExpectedCurrentAction, "alert")
	payload.DesiredPolicyAction.Action = action

	// The realized artifact is the structured rule this payload carries, so its
	// digest is computed from exactly those bytes rather than supplied.
	realized, err := json.Marshal(structured)
	if err != nil {
		return JanusPayload{}, fmt.Errorf("digest realized artifact: %w", err)
	}
	sum := sha256.Sum256(realized)

	payload.JanusBinding = JanusBinding{
		CandidateID:            firstNonEmpty(rule.CandidateID, set.SourceCandidateID),
		CandidateRevision:      "",
		CandidateDigest:        rule.ContentHash,
		RealizedArtifactDigest: "sha256:" + hex.EncodeToString(sum[:]),
		ControlInstanceID:      opts.ControlInstanceID,
		ProtectedHostname:      opts.ProtectedHostname,
		TargetScopeID:          opts.TargetScopeID,
		ExpectedLiveStateHash:  opts.ExpectedLiveStateHash,
		RecoverySpecRef:        opts.RecoverySpecRef,
	}
	return payload, nil
}

// mergeAlternatives collapses the rule set's OR of AND alternatives into the one
// AND list XSIAM's structured_rule takes.
//
// With a single alternative there is nothing to collapse. With several, the
// collapse is sound only when every alternative has the same condition shapes and
// they differ in AT MOST ONE position:
//
//	(A ∧ B₁) ∨ (A ∧ B₂)  ==  A ∧ (B₁ ∨ B₂)        one position differs — exact
//	(A₁ ∧ B₁) ∨ (A₂ ∧ B₂) ≠ (A₁ ∨ A₂) ∧ (B₁ ∨ B₂)  two differ — the right side
//	                                                also matches A₁ ∧ B₂
//
// That second form would silently widen the rule and block traffic the validated
// candidate never covered, so it is refused. Such a set needs one issue per
// alternative, which is the caller's decision to make.
func mergeAlternatives(set akamaiRuleSet) ([]JanusStructuredCondition, error) {
	for _, alternative := range set.Rules {
		if op := strings.ToUpper(strings.TrimSpace(alternative.Operation)); op != "AND" && op != "" {
			return nil, fmt.Errorf("alternative %q uses operation %q: only AND alternatives can be collapsed",
				alternative.Name, alternative.Operation)
		}
		if len(alternative.Conditions) == 0 {
			return nil, fmt.Errorf("alternative %q has no conditions", alternative.Name)
		}
	}

	base := set.Rules[0]
	if len(set.Rules) == 1 {
		return toStructuredConditions(base.Conditions), nil
	}
	if op := strings.ToUpper(strings.TrimSpace(set.CombinationOperation)); op != "OR" {
		return nil, fmt.Errorf("combinationOperation %q over %d alternatives is not supported",
			set.CombinationOperation, len(set.Rules))
	}

	// Every alternative must line up position by position with the first.
	for _, alternative := range set.Rules[1:] {
		if len(alternative.Conditions) != len(base.Conditions) {
			return nil, fmt.Errorf(
				"alternatives differ in structure (%d conditions vs %d): the set cannot be expressed as one AND rule, so it needs one issue per alternative",
				len(alternative.Conditions), len(base.Conditions))
		}
		for i := range alternative.Conditions {
			if alternative.Conditions[i].shape() != base.Conditions[i].shape() {
				return nil, fmt.Errorf(
					"alternatives differ at condition %d (%q vs %q): the set cannot be expressed as one AND rule, so it needs one issue per alternative",
					i, alternative.Conditions[i].Type, base.Conditions[i].Type)
			}
		}
	}

	// Union the values per position and count how many positions actually vary.
	merged := toStructuredConditions(base.Conditions)
	varying := 0
	for i := range base.Conditions {
		seen := map[string]bool{}
		var values []string
		for _, alternative := range set.Rules {
			for _, v := range alternative.Conditions[i].Value {
				if !seen[v] {
					seen[v] = true
					values = append(values, v)
				}
			}
		}
		if len(values) != len(base.Conditions[i].Value) {
			varying++
		}
		merged[i].Value = values
	}
	if varying > 1 {
		return nil, fmt.Errorf(
			"alternatives differ in %d condition positions: unioning them would also match combinations the rule set never covered, so the set needs one issue per alternative",
			varying)
	}
	return merged, nil
}

func toStructuredConditions(conditions []akamaiCondition) []JanusStructuredCondition {
	out := make([]JanusStructuredCondition, 0, len(conditions))
	for _, c := range conditions {
		out = append(out, JanusStructuredCondition{
			Type:          c.Type,
			PositiveMatch: c.PositiveMatch,
			Value:         append([]string(nil), c.Value...),
			ValueWildcard: c.ValueWildcard,
		})
	}
	return out
}

// policyActionFor maps the rule set's action onto an Akamai policy action. Every
// alternative must agree: a set that blocks on one branch and alerts on another
// has no single policy action, and picking one would change enforcement.
func policyActionFor(set akamaiRuleSet) (string, error) {
	actions := map[string]bool{}
	for _, alternative := range set.Rules {
		actions[strings.ToLower(strings.TrimSpace(alternative.SourceAction))] = true
	}
	if len(actions) != 1 {
		return "", fmt.Errorf("alternatives disagree on sourceAction (%s): no single policy action applies",
			strings.Join(sortedKeys(actions), ", "))
	}
	var only string
	for action := range actions {
		only = action
	}
	switch only {
	case "block", "deny":
		return "deny", nil
	case "alert", "monitor":
		return "alert", nil
	case "":
		return "", fmt.Errorf("rule set has no sourceAction")
	default:
		return "", fmt.Errorf("unsupported sourceAction %q", only)
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
