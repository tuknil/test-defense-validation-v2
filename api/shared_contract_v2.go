package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

const (
	sharedV2RoutePolicy           = "shared-attack-contracts-v2"
	sharedV2LegacyProfileID       = "waf-standard@1"
	sharedV2ProfileID             = "waf-standard@2"
	sharedV2ResolverID            = "mc-approved-route-adapter"
	sharedV2LegacyProfileDigest   = "sha256:e28f9574b07194222a317dfc4f03293beafb6e3613b87452a4191652fd6b6b1a"
	sharedV2ResolverProfileDigest = "sha256:01f6033b5b09db48056adc8a0d47083f4020cf18d71913c69e283f644ec41a94"
	semanticsDigestProfile        = "rfc8785-sha256-exclude-semantics_digest-v1"
	sourceProjectionDigestProfile = "rfc8785-sha256-cg-source-projection-v1"
	candidateBundleDigestProfile  = "rfc8785-sha256-exclude-bundle_digest-and-candidate_digest-v1"
	checkGenerationContentProfile = "rfc8785-sha256-exclude-content_digest-v1"
)

var (
	errSharedJSONPointerMemberAbsent = errors.New("JSON pointer member is absent")
	errSharedJSONPointerIndexInvalid = errors.New("JSON pointer index is invalid")
)

type sharedTypedRef struct {
	Kind  string `json:"kind"`
	Scope string `json:"scope"`
	ID    string `json:"id"`
}

type sharedContentLocator struct {
	URI        string `json:"uri"`
	Digest     string `json:"digest"`
	MediaType  string `json:"media_type"`
	ByteLength int64  `json:"byte_length"`
	Immutable  bool   `json:"immutable"`
}

type sharedHTTPField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type sharedHTTPBody struct {
	State         string                `json:"state"`
	ContentBase64 string                `json:"content_base64,omitempty"`
	ContentLength int64                 `json:"content_length,omitempty"`
	Digest        string                `json:"digest,omitempty"`
	Content       *sharedContentLocator `json:"content,omitempty"`
}

type sharedSourceMember struct {
	MemberID           string           `json:"member_id"`
	SignalID           string           `json:"signal_id"`
	AffectedArtifactID string           `json:"affected_artifact_id"`
	TerminalState      string           `json:"terminal_state"`
	ArtifactRefs       []sharedTypedRef `json:"artifact_refs"`
}

type sharedSourceArtifact struct {
	ArtifactID          string               `json:"artifact_id"`
	ArtifactKind        string               `json:"artifact_kind"`
	SignalIDs           []string             `json:"signal_ids"`
	AffectedArtifactIDs []string             `json:"affected_artifact_ids"`
	Content             sharedContentLocator `json:"content"`
	MemberRefs          []sharedTypedRef     `json:"member_refs"`
}

type sharedTestInput struct {
	InputID           string           `json:"input_id"`
	SourceMemberRefs  []sharedTypedRef `json:"source_member_refs"`
	SourceArtifactRef sharedTypedRef   `json:"source_artifact_ref"`
	Input             map[string]any   `json:"input"`
}

type sharedObligation struct {
	ObligationID      string           `json:"obligation_id"`
	CoverageRef       sharedTypedRef   `json:"coverage_ref"`
	RequiredInputRefs []sharedTypedRef `json:"required_input_refs"`
	Required          bool             `json:"required"`
}

type sharedUnsupportedDimension struct {
	Dimension          string           `json:"dimension"`
	Reason             string           `json:"reason"`
	SourceMemberRefs   []sharedTypedRef `json:"source_member_refs"`
	SourceArtifactRefs []sharedTypedRef `json:"source_artifact_refs"`
	SourceInputRefs    []sharedTypedRef `json:"source_input_refs"`
}

type sharedSemantics struct {
	ContractID        string `json:"contract_id"`
	SemanticsID       string `json:"semantics_id"`
	SemanticsRevision int    `json:"semantics_revision"`
	SemanticsDigest   string `json:"semantics_digest"`
	DigestProfile     string `json:"digest_profile"`
	SourceBinding     struct {
		CheckGeneration struct {
			ContractID             string `json:"contract_id"`
			ResultID               string `json:"result_id"`
			Revision               *int   `json:"revision,omitempty"`
			MemberCount            int    `json:"member_count"`
			ArtifactCount          int    `json:"artifact_count"`
			SourceProjectionDigest string `json:"source_projection_digest"`
			DigestProfile          string `json:"digest_profile"`
		} `json:"check_generation"`
		Artifacts []sharedSourceArtifact `json:"artifacts"`
		Members   []sharedSourceMember   `json:"members"`
	} `json:"source_binding"`
	TestInputs            []sharedTestInput            `json:"test_inputs"`
	Obligations           []sharedObligation           `json:"obligations"`
	UnsupportedDimensions []sharedUnsupportedDimension `json:"unsupported_dimensions"`
	Components            []map[string]any             `json:"components"`
	Coverage              map[string]any               `json:"coverage"`
}

type sharedBundleArtifact struct {
	ArtifactID          string               `json:"artifact_id"`
	Order               int                  `json:"order"`
	Role                string               `json:"role"`
	Kind                string               `json:"kind"`
	Content             sharedContentLocator `json:"content"`
	ApplicationGroupRef sharedTypedRef       `json:"application_group_ref"`
	DependsOn           []sharedTypedRef     `json:"depends_on"`
}

type sharedBundleDirective struct {
	DirectiveID string         `json:"directive_id"`
	Kind        string         `json:"kind"`
	ArtifactRef sharedTypedRef `json:"artifact_ref"`
	Value       string         `json:"value"`
	Required    bool           `json:"required"`
}

type sharedObligationMapping struct {
	ObligationID     string           `json:"obligation_id"`
	SemanticsRefs    []sharedTypedRef `json:"semantics_refs"`
	SourceMemberRefs []sharedTypedRef `json:"source_member_refs"`
	ArtifactRefs     []sharedTypedRef `json:"artifact_refs"`
	DirectiveRefs    []sharedTypedRef `json:"directive_refs"`
	Coverage         string           `json:"coverage"`
}

type sharedCandidateBundle struct {
	ContractID       string `json:"contract_id"`
	BundleID         string `json:"bundle_id"`
	BundleRevision   int    `json:"bundle_revision"`
	BundleDigest     string `json:"bundle_digest"`
	DigestProfile    string `json:"digest_profile"`
	SemanticsBinding struct {
		ContractID        string               `json:"contract_id"`
		SemanticsID       string               `json:"semantics_id"`
		SemanticsRevision int                  `json:"semantics_revision"`
		SemanticsDigest   string               `json:"semantics_digest"`
		Locator           sharedContentLocator `json:"locator"`
	} `json:"semantics_binding"`
	PrimaryCandidate struct {
		CandidateID          string                    `json:"candidate_id"`
		CandidateRevision    int                       `json:"candidate_revision"`
		CandidateDigest      string                    `json:"candidate_digest"`
		SelectedControlClass string                    `json:"selected_control_class"`
		Artifacts            []sharedBundleArtifact    `json:"artifacts"`
		Directives           []sharedBundleDirective   `json:"directives"`
		ObligationMappings   []sharedObligationMapping `json:"obligation_mappings"`
	} `json:"primary_candidate"`
	ApplicationUnit struct {
		ApplicationUnitID string           `json:"application_unit_id"`
		ArtifactRefs      []sharedTypedRef `json:"artifact_refs"`
		Apply             string           `json:"apply"`
		Rollback          string           `json:"rollback"`
		Remove            string           `json:"remove"`
		Readback          string           `json:"readback"`
	} `json:"application_unit"`
	AtomicGroups []struct {
		AtomicGroupID string           `json:"atomic_group_id"`
		ArtifactRefs  []sharedTypedRef `json:"artifact_refs"`
		Apply         string           `json:"apply"`
		Rollback      string           `json:"rollback"`
		Remove        string           `json:"remove"`
		Readback      string           `json:"readback"`
	} `json:"atomic_groups"`
	Provenance []struct {
		Order        int    `json:"order"`
		OutputDigest string `json:"output_digest"`
	} `json:"provenance"`
}

type AppliedApplicationUnit struct {
	ApplicationUnitID string   `json:"application_unit_id"`
	ArtifactIDs       []string `json:"artifact_ids"`
	ReadbackVerified  bool     `json:"readback_verified"`
}

type sharedResolvedInputs struct {
	CGDocument    map[string]any
	Semantics     sharedSemantics
	Bundle        sharedCandidateBundle
	ArtifactBytes map[string][]byte
	Provenance    LocatorProvenance
	EvidenceRefs  []string
}

type sharedV2InputResolver interface {
	ResolveV2(context.Context, ImmutableResultLocator, ImmutableResultLocator) (sharedResolvedInputs, error)
	Close() error
}

var newSharedV2InputResolver = func() (sharedV2InputResolver, error) {
	legacy, err := newDatabricksLocatorResolverFromEnv()
	if err != nil {
		return nil, err
	}
	return &databricksSharedV2Resolver{databricksLocatorResolver: legacy}, nil
}

type databricksSharedV2Resolver struct{ *databricksLocatorResolver }

func v2LocatorMode(req SubmitDefenseValidationRequest) bool {
	return req.RoutePolicy == sharedV2RoutePolicy || strings.TrimSpace(req.ProfileID) != ""
}

func validateV2LocatorRequest(req SubmitDefenseValidationRequest) []string {
	bad := []string{}
	if req.RoutePolicy != sharedV2RoutePolicy {
		bad = append(bad, "route_policy")
	}
	if req.ProfileID != sharedV2ProfileID && req.ProfileID != sharedV2LegacyProfileID {
		bad = append(bad, "profile_id")
	}
	if req.DefenseResult == nil || validateImmutableLocator(*req.DefenseResult, capDefenseGeneration) != nil {
		bad = append(bad, "defense_result")
	}
	if req.CheckResult == nil || validateSharedV2CheckLocator(*req.CheckResult) != nil {
		bad = append(bad, "check_result")
	}
	if req.DefenseResult != nil && req.CheckResult != nil && req.DefenseResult.CorrelationID != req.CheckResult.CorrelationID {
		bad = append(bad, "check_result.correlation_id")
	}
	if req.DefenseResult != nil && req.DefenseResult.CorrelationID != req.CorrelationID {
		bad = append(bad, "defense_result.correlation_id")
	}
	if req.CandidateArtifactID != "" || req.TestBasisID != "" || req.CheckProfileID != "" || len(req.Candidate) > 0 || len(req.UpstreamInputs) > 0 {
		bad = append(bad, "inline_content")
	}
	if len(req.PrimaryCandidateRaw) > 0 || len(req.AttemptHistory) > 0 || len(req.OutcomeReason) > 0 || len(req.ProofHandoffs) > 0 || len(req.UpstreamResultRef) > 0 || req.ProducedAt != "" || req.UpstreamProse != "" || req.UpstreamResultID != "" || req.UpstreamTerminal != "" {
		bad = append(bad, "inline_upstream_content")
	}
	return uniqueStrings(bad)
}

func validateSharedV2CheckLocator(locator ImmutableResultLocator) error {
	if locator.ContractID != "check-generation@2.1" {
		return errors.New("shared-contract Check Generation locator contract is invalid")
	}
	legacyEnvelope := locator
	legacyEnvelope.ContractID = "check-generation-result@1.0"
	return validateImmutableLocator(legacyEnvelope, capCheckGeneration)
}

func (r *databricksSharedV2Resolver) ResolveV2(ctx context.Context, defense, check ImmutableResultLocator) (sharedResolvedInputs, error) {
	reportExecutionProgress(ctx, "resolving-check-result", "Resolving immutable Check Generation result")
	checkRows, err := r.source.Check(ctx, check.ResultID)
	if err != nil || len(checkRows) != 1 {
		return sharedResolvedInputs{}, fmt.Errorf("resolve Check Generation locator: rows=%d: %w", len(checkRows), err)
	}
	reportExecutionProgress(ctx, "verifying-check-result", "Verifying Check Generation result integrity")
	cgRaw, evidence, err := r.verifyCheckRow(ctx, checkRows[0], check)
	if err != nil {
		return sharedResolvedInputs{}, err
	}
	var cg map[string]any
	if err := decodeStrictJSON(cgRaw, &cg); err != nil {
		return sharedResolvedInputs{}, fmt.Errorf("strict Check Generation JSON: %w", err)
	}
	reportExecutionProgress(ctx, "validating-attack-semantics", "Validating complete attack semantics and obligations")
	semantics, err := validateSharedCGDocument(cg)
	if err != nil {
		return sharedResolvedInputs{}, err
	}
	reportExecutionProgress(ctx, "resolving-defense-result", "Resolving immutable Defense Generation result")
	defenseRows, err := r.source.Defense(ctx, defense.ResultID)
	if err != nil || len(defenseRows) != 1 {
		return sharedResolvedInputs{}, fmt.Errorf("resolve Defense Generation locator: rows=%d: %w", len(defenseRows), err)
	}
	reportExecutionProgress(ctx, "validating-candidate-bundle", "Validating the complete candidate bundle")
	bundle, contents, defenseEvidence, err := validateSharedDefenseRow(defenseRows[0], defense, check, cg, semantics)
	if err != nil {
		return sharedResolvedInputs{}, err
	}
	return sharedResolvedInputs{CGDocument: cg, Semantics: semantics, Bundle: bundle, ArtifactBytes: contents, EvidenceRefs: stableStringUnion(evidence, defenseEvidence), Provenance: LocatorProvenance{RoutePolicy: sharedV2RoutePolicy, DefenseResult: defense, CheckResult: check, Verification: "physical-and-logical-sha256-verified"}}, nil
}

func validateSharedCGDocument(cg map[string]any) (sharedSemantics, error) {
	if stringValue(cg["contract_id"]) != "check-generation@2.1" || stringValue(cg["result_id"]) == "" {
		return sharedSemantics{}, errors.New("Check Generation nested v2 identity is invalid")
	}
	if profile, ok := cg["digest_profile"].(string); ok || cg["content_digest"] != nil {
		if !ok || profile != checkGenerationContentProfile {
			return sharedSemantics{}, errors.New("Check Generation content digest profile is invalid")
		}
		preimage := cloneMap(cg)
		advertised := stringValue(preimage["content_digest"])
		delete(preimage, "content_digest")
		if digestAny(preimage) != advertised {
			return sharedSemantics{}, errors.New("Check Generation content_digest differs")
		}
	}
	raw, ok := cg["attack_match_semantics"].(map[string]any)
	if !ok {
		return sharedSemantics{}, errors.New("embedded attack-match-semantics@2.0 is absent")
	}
	if err := validateSharedSchema(attackMatchSemanticsSchemaID, raw); err != nil {
		return sharedSemantics{}, fmt.Errorf("attack semantics schema: %w", err)
	}
	encoded, _ := json.Marshal(raw)
	var semantics sharedSemantics
	if err := json.Unmarshal(encoded, &semantics); err != nil {
		return sharedSemantics{}, err
	}
	if semantics.DigestProfile != semanticsDigestProfile {
		return sharedSemantics{}, errors.New("semantics digest profile is invalid")
	}
	preimage := cloneMap(raw)
	delete(preimage, "semantics_digest")
	if digestAny(preimage) != semantics.SemanticsDigest {
		return sharedSemantics{}, errors.New("semantics_digest differs")
	}
	identity := semantics.SourceBinding.CheckGeneration
	if identity.ContractID != "check-generation@2.1" || identity.ResultID != stringValue(cg["result_id"]) || identity.DigestProfile != sourceProjectionDigestProfile {
		return sharedSemantics{}, errors.New("embedded Check Generation identity differs")
	}
	if identity.Revision != nil && int64(*identity.Revision) != numberInt(cg["revision"]) {
		return sharedSemantics{}, errors.New("embedded Check Generation revision differs")
	}
	projection := map[string]any{}
	for _, key := range []string{"artifacts", "input_membership", "member_results", "test_inputs"} {
		value, exists := cg[key]
		if !exists {
			return sharedSemantics{}, fmt.Errorf("source projection field %s is absent", key)
		}
		projection[key] = value
	}
	if digestAny(projection) != identity.SourceProjectionDigest {
		return sharedSemantics{}, errors.New("source_projection_digest differs")
	}
	if err := validateSharedCompleteness(cg, semantics); err != nil {
		return sharedSemantics{}, err
	}
	return semantics, nil
}

func validateSharedCompleteness(cg map[string]any, semantics sharedSemantics) error {
	outerMembers, err := indexObjects(cg["member_results"], "member_id")
	if err != nil {
		return err
	}
	outerArtifacts, err := indexObjects(cg["artifacts"], "artifact_id")
	if err != nil {
		return err
	}
	outerInputs, err := indexObjects(cg["test_inputs"], "input_id")
	if err != nil {
		return err
	}
	members := map[string]sharedSourceMember{}
	artifacts := map[string]sharedSourceArtifact{}
	inputs := map[string]sharedTestInput{}
	for _, item := range semantics.SourceBinding.Members {
		if item.MemberID == "" || members[item.MemberID].MemberID != "" {
			return errors.New("duplicate source member")
		}
		members[item.MemberID] = item
	}
	for _, item := range semantics.SourceBinding.Artifacts {
		if item.ArtifactID == "" || artifacts[item.ArtifactID].ArtifactID != "" {
			return errors.New("duplicate source artifact")
		}
		artifacts[item.ArtifactID] = item
	}
	for _, item := range semantics.TestInputs {
		if item.InputID == "" || inputs[item.InputID].InputID != "" {
			return errors.New("duplicate test input")
		}
		inputs[item.InputID] = item
	}
	if len(members) != len(outerMembers) || len(members) != semantics.SourceBinding.CheckGeneration.MemberCount || !sameKeys(members, outerMembers) {
		return errors.New("complete source member set differs")
	}
	if len(artifacts) != len(outerArtifacts) || len(artifacts) != semantics.SourceBinding.CheckGeneration.ArtifactCount || !sameKeys(artifacts, outerArtifacts) {
		return errors.New("complete source artifact set differs")
	}
	for id := range inputs {
		if outerInputs[id] == nil {
			return fmt.Errorf("invented test input %s", id)
		}
	}
	represented, unsupported := map[string]bool{}, map[string]bool{}
	representedArtifacts, unsupportedArtifacts := map[string]bool{}, map[string]bool{}
	representedInputs, unsupportedInputs := map[string]bool{}, map[string]bool{}
	componentIDs, obligationIDs := map[string]bool{}, map[string]bool{}
	for _, component := range semantics.Components {
		id := stringValue(component["component_id"])
		if id == "" || componentIDs[id] {
			return errors.New("duplicate semantics component")
		}
		componentIDs[id] = true
	}
	for _, obligation := range semantics.Obligations {
		obligationIDs[obligation.ObligationID] = true
	}
	referencedComponents, referencedObligations := map[string]bool{}, map[string]bool{}
	semanticsReferencedArtifacts := map[string]bool{}
	for id, member := range members {
		outer := outerMembers[id]
		if member.SignalID != stringValue(outer["signal_id"]) || member.AffectedArtifactID != stringValue(outer["affected_artifact_id"]) || member.TerminalState != sharedTerminalStateFromCG(stringValue(outer["terminal_state"])) || !sameStringSetLocal(refIDs(member.ArtifactRefs), stringSlice(outer["artifact_refs"])) {
			return fmt.Errorf("source member ancestry differs for %s", id)
		}
		positive := member.TerminalState == "verified" || member.TerminalState == "signal-produced"
		if positive != (len(member.ArtifactRefs) > 0) {
			return fmt.Errorf("source member artifact cardinality differs for %s", id)
		}
		for _, ref := range member.ArtifactRefs {
			if ref.Kind != "source-artifact" || ref.Scope != semantics.SemanticsID || artifacts[ref.ID].ArtifactID == "" {
				return errors.New("invented source artifact ref")
			}
		}
	}
	for id, artifact := range artifacts {
		outer := outerArtifacts[id]
		if artifact.ArtifactKind != stringValue(outer["artifact_kind"]) || !sameStringSetLocal(artifact.SignalIDs, stringSlice(outer["signal_ids"])) || !sameStringSetLocal(artifact.AffectedArtifactIDs, stringSlice(outer["affected_artifact_ids"])) || !sameStringSetLocal(refIDs(artifact.MemberRefs), stringSlice(outer["member_ids"])) {
			return fmt.Errorf("source artifact ancestry differs for %s", id)
		}
		for _, ref := range artifact.MemberRefs {
			if ref.Kind != "source-member" || ref.Scope != semantics.SemanticsID || members[ref.ID].MemberID == "" {
				return errors.New("invented source member ref")
			}
		}
		if strings.HasPrefix(artifact.Content.URI, "janus-result-internal:") {
			if _, err := resolveSharedInternalLocator(artifact.Content, cg); err != nil {
				return fmt.Errorf("source artifact %s locator: %w", id, err)
			}
		} else if digest := stringValue(outer["content_hash"]); digest != "" && digest != artifact.Content.Digest {
			return fmt.Errorf("source artifact %s content digest differs", id)
		}
		semanticRef := mapValue(outer["attack_match_semantics_ref"])
		if semanticRef == nil {
			continue
		}
		if stringValue(semanticRef["semantics_id"]) != semantics.SemanticsID {
			return fmt.Errorf("source artifact %s semantics identity differs", id)
		}
		semanticsReferencedArtifacts[id] = true
		for _, componentID := range stringSlice(semanticRef["component_ids"]) {
			if !componentIDs[componentID] {
				return fmt.Errorf("source artifact %s invents component", id)
			}
			referencedComponents[componentID] = true
		}
		for _, obligationID := range stringSlice(semanticRef["obligation_ids"]) {
			if !obligationIDs[obligationID] {
				return fmt.Errorf("source artifact %s invents obligation", id)
			}
			referencedObligations[obligationID] = true
		}
	}
	if len(referencedComponents) != len(componentIDs) || len(referencedObligations) != len(obligationIDs) {
		return errors.New("source artifact semantics references are incomplete")
	}
	for _, input := range semantics.TestInputs {
		outer := outerInputs[input.InputID]
		if input.SourceArtifactRef.Kind != "source-artifact" || input.SourceArtifactRef.Scope != semantics.SemanticsID || artifacts[input.SourceArtifactRef.ID].ArtifactID == "" || input.SourceArtifactRef.ID != stringValue(outer["artifact_id"]) || !sameStringSetLocal(refIDs(input.SourceMemberRefs), stringSlice(outer["member_ids"])) {
			return fmt.Errorf("test input ancestry differs for %s", input.InputID)
		}
		for _, ref := range input.SourceMemberRefs {
			if ref.Kind != "source-member" || ref.Scope != semantics.SemanticsID || members[ref.ID].MemberID == "" {
				return errors.New("invented test input member")
			}
			represented[ref.ID] = true
		}
		representedArtifacts[input.SourceArtifactRef.ID] = true
		representedInputs[input.InputID] = true
	}
	obligations := map[string]bool{}
	work := map[string]bool{}
	for _, obligation := range semantics.Obligations {
		if !obligation.Required || obligation.ObligationID == "" || obligations[obligation.ObligationID] {
			return errors.New("duplicate or optional obligation")
		}
		obligations[obligation.ObligationID] = true
		expectedInputs, expectedMembers, err := sharedCoverageRequirements(obligation.CoverageRef, semantics)
		if err != nil {
			return fmt.Errorf("obligation %s coverage: %w", obligation.ObligationID, err)
		}
		_ = expectedMembers
		for _, ref := range obligation.RequiredInputRefs {
			if ref.Kind != "test-input" || ref.Scope != semantics.SemanticsID || inputs[ref.ID].InputID == "" {
				return fmt.Errorf("bad obligation input ref for %s", obligation.ObligationID)
			}
			key := obligation.ObligationID + "\x00" + ref.ID
			if work[key] {
				return errors.New("duplicate obligation/input assignment")
			}
			work[key] = true
		}
		if !sameStringSetLocal(refIDs(obligation.RequiredInputRefs), expectedInputs) {
			return fmt.Errorf("obligation %s required inputs differ from coverage", obligation.ObligationID)
		}
	}
	for _, dimension := range semantics.UnsupportedDimensions {
		if dimension.Dimension == "" || dimension.Reason == "" || len(dimension.SourceMemberRefs) == 0 {
			return errors.New("incomplete unsupported dimension")
		}
		for _, ref := range dimension.SourceMemberRefs {
			if ref.Kind != "source-member" || ref.Scope != semantics.SemanticsID || members[ref.ID].MemberID == "" {
				return errors.New("invalid unsupported source member")
			}
			unsupported[ref.ID] = true
		}
		for _, ref := range dimension.SourceArtifactRefs {
			if ref.Kind != "source-artifact" || ref.Scope != semantics.SemanticsID || artifacts[ref.ID].ArtifactID == "" {
				return errors.New("invalid unsupported source artifact")
			}
			unsupportedArtifacts[ref.ID] = true
		}
		for _, ref := range dimension.SourceInputRefs {
			if ref.Kind != "test-input" || ref.Scope != semantics.SemanticsID || outerInputs[ref.ID] == nil {
				return errors.New("invalid unsupported source input")
			}
			unsupportedInputs[ref.ID] = true
		}
	}
	if intersectsLocal(represented, unsupported) || len(represented)+len(unsupported) != len(members) {
		return errors.New("represented/unsupported source partition is incomplete")
	}
	for id := range members {
		if !represented[id] && !unsupported[id] {
			return errors.New("unaccounted source member")
		}
	}
	if intersectsLocal(representedArtifacts, unsupportedArtifacts) || len(representedArtifacts)+len(unsupportedArtifacts) != len(artifacts) {
		return errors.New("represented/unsupported source artifact partition is incomplete")
	}
	for id := range artifacts {
		if representedArtifacts[id] != semanticsReferencedArtifacts[id] {
			return fmt.Errorf("source artifact %s semantics representation differs", id)
		}
	}
	if intersectsLocal(representedInputs, unsupportedInputs) || len(representedInputs)+len(unsupportedInputs) != len(outerInputs) {
		return errors.New("represented/unsupported source input partition is incomplete")
	}
	return nil
}

func sharedTerminalStateFromCG(value string) string {
	if value == "no-checkable-artifact" {
		return "no-checkable-signal"
	}
	return value
}

func validateSharedDefenseRow(row defenseRow, locator, checkLocator ImmutableResultLocator, cg map[string]any, semantics sharedSemantics) (sharedCandidateBundle, map[string][]byte, []string, error) {
	if row.RunID != locator.RunID || row.ResultID != locator.ResultID || row.TerminalState != locator.TerminalState {
		return sharedCandidateBundle{}, nil, nil, errors.New("Defense Generation physical identity differs")
	}
	var result defenseCanonicalResult
	if err := decodeStrictJSON([]byte(row.ResultJSON), &result); err != nil {
		return sharedCandidateBundle{}, nil, nil, fmt.Errorf("strict Defense Generation result: %w", err)
	}
	if result.Capability != locator.Capability || result.ContractID != locator.ContractID || result.RequestID != locator.RequestID || result.CorrelationID != locator.CorrelationID || result.RunID != locator.RunID || result.ResultID != locator.ResultID || result.Status != locator.Status || result.TerminalState != locator.TerminalState || !sameTimestamp(result.CreatedAt, locator.CreatedAt) || result.ResultRef == nil || !sameDefenseResultRef(*result.ResultRef, locator.ResultRef) {
		return sharedCandidateBundle{}, nil, nil, errors.New("Defense Generation logical identity differs")
	}
	advertisedDigest, advertisedSize := result.ContentSHA256, result.SizeBytes
	result.ContentSHA256, result.SizeBytes = "", 0
	var unsigned []byte
	var err error
	if len(result.CandidateBundle) > 0 {
		var document map[string]any
		if err := decodeJSONMap([]byte(row.ResultJSON), &document); err != nil {
			return sharedCandidateBundle{}, nil, nil, fmt.Errorf("decode Defense Generation shared result: %w", err)
		}
		delete(document, "content_sha256")
		delete(document, "size_bytes")
		unsigned, err = marshalRFC8785(document)
	} else {
		unsigned, err = json.Marshal(result)
	}
	if err != nil || sha256Value(unsigned) != advertisedDigest || int64(len(unsigned)) != advertisedSize || advertisedDigest != locator.ContentSHA256 || advertisedSize != locator.SizeBytes {
		return sharedCandidateBundle{}, nil, nil, errors.New("Defense Generation outer bytes differ from locator")
	}
	var bundleDoc any
	if err := decodeStrictJSON(result.CandidateBundle, &bundleDoc); err != nil {
		return sharedCandidateBundle{}, nil, nil, fmt.Errorf("strict candidate bundle: %w", err)
	}
	if err := validateSharedSchema(candidateBundleSchemaID, bundleDoc); err != nil {
		return sharedCandidateBundle{}, nil, nil, fmt.Errorf("candidate bundle schema: %w", err)
	}
	var bundle sharedCandidateBundle
	if err := json.Unmarshal(result.CandidateBundle, &bundle); err != nil {
		return sharedCandidateBundle{}, nil, nil, err
	}
	contents := map[string][]byte{}
	for id, raw := range result.CandidateArtifactContents {
		var value any
		if err := decodeStrictJSON(raw, &value); err != nil {
			return sharedCandidateBundle{}, nil, nil, fmt.Errorf("candidate artifact %s: %w", id, err)
		}
		canonical, err := marshalRFC8785(value)
		if err != nil {
			return sharedCandidateBundle{}, nil, nil, err
		}
		contents[id] = canonical
	}
	if err := validateSharedBundle(bundleDoc.(map[string]any), bundle, contents, locator.ResultID, checkLocator, cg, semantics); err != nil {
		return sharedCandidateBundle{}, nil, nil, err
	}
	return bundle, contents, result.EvidenceRefs, nil
}

func validateSharedBundle(document map[string]any, bundle sharedCandidateBundle, contents map[string][]byte, resultID string, checkLocator ImmutableResultLocator, cg map[string]any, semantics sharedSemantics) error {
	if bundle.ContractID != "candidate-bundle@1.0" || bundle.DigestProfile != candidateBundleDigestProfile || bundle.PrimaryCandidate.SelectedControlClass != "waf" {
		return errors.New("candidate bundle identity is invalid")
	}
	candidateDoc := mapValue(document["primary_candidate"])
	candidatePreimage := cloneMap(candidateDoc)
	delete(candidatePreimage, "candidate_digest")
	if digestAny(candidatePreimage) != bundle.PrimaryCandidate.CandidateDigest {
		return errors.New("candidate_digest differs")
	}
	bundlePreimage := cloneMap(document)
	delete(bundlePreimage, "bundle_digest")
	delete(mapValue(bundlePreimage["primary_candidate"]), "candidate_digest")
	if digestAny(bundlePreimage) != bundle.BundleDigest {
		return errors.New("bundle_digest differs")
	}
	binding := bundle.SemanticsBinding
	cgBytes, cgErr := marshalRFC8785(cg)
	expectedCGURI := "databricks-result:///" + url.PathEscape(checkLocator.ResultRef.Catalog) + "/" + url.PathEscape(checkLocator.ResultRef.Schema) + "/" + url.PathEscape(checkLocator.ResultRef.Table) + "/" + url.PathEscape(checkLocator.ResultRef.Key)
	if cgErr != nil || binding.ContractID != semantics.ContractID || binding.SemanticsID != semantics.SemanticsID || binding.SemanticsRevision != semantics.SemanticsRevision || binding.SemanticsDigest != semantics.SemanticsDigest || binding.Locator.URI != expectedCGURI || binding.Locator.Digest != sha256Value(cgBytes) || binding.Locator.ByteLength != int64(len(cgBytes)) || binding.Locator.MediaType != "application/json" || !binding.Locator.Immutable {
		return errors.New("candidate semantics binding or locator differs")
	}
	artifacts := map[string]sharedBundleArtifact{}
	for index, artifact := range bundle.PrimaryCandidate.Artifacts {
		if artifact.ArtifactID == "" || artifacts[artifact.ArtifactID].ArtifactID != "" || artifact.Order != index {
			return errors.New("candidate artifact identity/order differs")
		}
		content, ok := contents[artifact.ArtifactID]
		if !ok || artifact.Content.Digest != sha256Value(content) || artifact.Content.ByteLength != int64(len(content)) || !artifact.Content.Immutable || !validCandidateContentURI(artifact.Content.URI, resultID, artifact.ArtifactID) {
			return fmt.Errorf("candidate artifact %s locator/content differs", artifact.ArtifactID)
		}
		artifacts[artifact.ArtifactID] = artifact
	}
	if len(artifacts) == 0 || len(artifacts) != len(contents) {
		return errors.New("candidate artifact partition is incomplete")
	}
	applicationIDs, err := checkedRefs(bundle.ApplicationUnit.ArtifactRefs, "artifact", bundle.BundleID, artifacts)
	if err != nil || !sameStringSetLocal(applicationIDs, keys(artifacts)) || bundle.ApplicationUnit.Apply != "all-or-nothing" || bundle.ApplicationUnit.Rollback != "all-or-nothing" || bundle.ApplicationUnit.Remove != "all-or-nothing" || bundle.ApplicationUnit.Readback != "verify-every-artifact-or-rollback" {
		return errors.New("application unit is incomplete")
	}
	groups := map[string]bool{}
	memberships := map[string]int{}
	for _, group := range bundle.AtomicGroups {
		if group.AtomicGroupID == "" || groups[group.AtomicGroupID] || group.Apply != "all-or-nothing" || group.Rollback != "all-or-nothing" || group.Remove != "all-or-nothing" || group.Readback != "verify-group-or-rollback" {
			return errors.New("atomic group is invalid")
		}
		groups[group.AtomicGroupID] = true
		ids, err := checkedRefs(group.ArtifactRefs, "artifact", bundle.BundleID, artifacts)
		if err != nil {
			return err
		}
		for _, id := range ids {
			memberships[id]++
		}
	}
	for id, artifact := range artifacts {
		if !groups[artifact.ApplicationGroupRef.ID] || artifact.ApplicationGroupRef.Kind != "atomic-group" || artifact.ApplicationGroupRef.Scope != bundle.BundleID || memberships[id] != 1 {
			return errors.New("atomic artifact membership differs")
		}
		dependencies, err := checkedRefs(artifact.DependsOn, "artifact", bundle.BundleID, artifacts)
		if err != nil {
			return err
		}
		for _, dependency := range dependencies {
			if artifacts[dependency].Order >= artifact.Order {
				return fmt.Errorf("candidate artifact %s dependency order differs", id)
			}
		}
	}
	directives := map[string]sharedBundleDirective{}
	for _, directive := range bundle.PrimaryCandidate.Directives {
		if directive.DirectiveID == "" || directives[directive.DirectiveID].DirectiveID != "" || artifacts[directive.ArtifactRef.ID].ArtifactID == "" || directive.ArtifactRef.Kind != "artifact" || directive.ArtifactRef.Scope != bundle.BundleID {
			return errors.New("candidate directive differs")
		}
		directives[directive.DirectiveID] = directive
	}
	obligations := map[string]sharedObligation{}
	for _, item := range semantics.Obligations {
		obligations[item.ObligationID] = item
	}
	seen := map[string]bool{}
	for _, mapping := range bundle.PrimaryCandidate.ObligationMappings {
		obligation, ok := obligations[mapping.ObligationID]
		if !ok || seen[mapping.ObligationID] || mapping.Coverage != "exact" || len(mapping.SemanticsRefs) != 1 || mapping.SemanticsRefs[0] != obligation.CoverageRef {
			return errors.New("candidate obligation mapping differs")
		}
		seen[mapping.ObligationID] = true
		_, expectedMembers, err := sharedCoverageRequirements(obligation.CoverageRef, semantics)
		if err != nil || !sameStringSetLocal(refIDs(mapping.SourceMemberRefs), expectedMembers) {
			return fmt.Errorf("candidate obligation %s source ancestry differs", mapping.ObligationID)
		}
		for _, ref := range mapping.SourceMemberRefs {
			if ref.Kind != "source-member" || ref.Scope != semantics.SemanticsID {
				return fmt.Errorf("candidate obligation %s source reference differs", mapping.ObligationID)
			}
		}
		if _, err := checkedRefs(mapping.ArtifactRefs, "artifact", bundle.BundleID, artifacts); err != nil {
			return err
		}
		if _, err := checkedRefs(mapping.DirectiveRefs, "directive", bundle.BundleID, directives); err != nil {
			return err
		}
	}
	if len(seen) != len(obligations) {
		return errors.New("candidate obligation mapping set is incomplete")
	}
	if len(bundle.Provenance) == 0 {
		return errors.New("candidate provenance is absent")
	}
	for index, step := range bundle.Provenance {
		if step.Order != index || !validSHA256(step.OutputDigest) {
			return errors.New("candidate provenance order or digest differs")
		}
	}
	return nil
}

func sharedCoverageRequirements(root sharedTypedRef, semantics sharedSemantics) ([]string, []string, error) {
	components := map[string]map[string]any{}
	for _, component := range semantics.Components {
		id := stringValue(component["component_id"])
		if id == "" || components[id] != nil {
			return nil, nil, errors.New("duplicate coverage component")
		}
		components[id] = component
	}
	groups := map[string]map[string]any{}
	for _, raw := range anySlice(semantics.Coverage["groups"]) {
		group := mapValue(raw)
		id := stringValue(group["group_id"])
		if id == "" || groups[id] != nil {
			return nil, nil, errors.New("duplicate coverage group")
		}
		groups[id] = group
	}
	visiting := map[string]bool{}
	var walk func(sharedTypedRef) (map[string]bool, map[string]bool, error)
	walk = func(ref sharedTypedRef) (map[string]bool, map[string]bool, error) {
		if ref.Scope != semantics.SemanticsID {
			return nil, nil, errors.New("coverage reference scope differs")
		}
		inputs, members := map[string]bool{}, map[string]bool{}
		switch ref.Kind {
		case "component":
			component := components[ref.ID]
			if component == nil {
				return nil, nil, errors.New("coverage component is unknown")
			}
			for _, child := range typedRefs(component["input_refs"]) {
				if child.Kind != "test-input" || child.Scope != semantics.SemanticsID {
					return nil, nil, errors.New("component input reference differs")
				}
				inputs[child.ID] = true
			}
			for _, child := range typedRefs(component["source_member_refs"]) {
				if child.Kind != "source-member" || child.Scope != semantics.SemanticsID {
					return nil, nil, errors.New("component source reference differs")
				}
				members[child.ID] = true
			}
		case "coverage-group":
			if visiting[ref.ID] {
				return nil, nil, errors.New("coverage graph contains a cycle")
			}
			group := groups[ref.ID]
			if group == nil {
				return nil, nil, errors.New("coverage group is unknown")
			}
			visiting[ref.ID] = true
			for _, child := range typedRefs(group["member_refs"]) {
				childInputs, childMembers, err := walk(child)
				if err != nil {
					return nil, nil, err
				}
				for id := range childInputs {
					inputs[id] = true
				}
				for id := range childMembers {
					members[id] = true
				}
			}
			delete(visiting, ref.ID)
			if !sameStringSetLocal(keys(members), refIDs(typedRefs(group["source_member_refs"]))) {
				return nil, nil, errors.New("coverage group source ancestry differs")
			}
		default:
			return nil, nil, errors.New("coverage reference kind differs")
		}
		return inputs, members, nil
	}
	inputs, members, err := walk(root)
	return keys(inputs), keys(members), err
}

func anySlice(value any) []any { result, _ := value.([]any); return result }
func typedRefs(value any) []sharedTypedRef {
	items := anySlice(value)
	result := make([]sharedTypedRef, 0, len(items))
	for _, item := range items {
		encoded, _ := json.Marshal(item)
		var ref sharedTypedRef
		if json.Unmarshal(encoded, &ref) == nil {
			result = append(result, ref)
		}
	}
	return result
}

func validCandidateContentURI(uri, resultID, artifactID string) bool {
	expected := "janus-result-internal:" + url.QueryEscape(resultID) + "#/candidate_artifact_contents/" + strings.ReplaceAll(strings.ReplaceAll(artifactID, "~", "~0"), "/", "~1")
	return uri == expected
}

func digestAny(value any) string {
	encoded, err := marshalRFC8785(value)
	if err != nil {
		return ""
	}
	return sha256Value(encoded)
}
func cloneMap(value map[string]any) map[string]any {
	encoded, _ := json.Marshal(value)
	var out map[string]any
	_ = decodeJSONMap(encoded, &out)
	return out
}
func mapValue(value any) map[string]any { result, _ := value.(map[string]any); return result }
func numberInt(value any) int64         { parsed, _ := int64Value(value); return parsed }
func refIDs(refs []sharedTypedRef) []string {
	out := make([]string, len(refs))
	for i := range refs {
		out[i] = refs[i].ID
	}
	return out
}
func stringSlice(value any) []string {
	raw, _ := value.([]any)
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}
func sameStringSetLocal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, v := range a {
		seen[v]++
	}
	for _, v := range b {
		seen[v]--
		if seen[v] < 0 {
			return false
		}
	}
	return true
}
func intersectsLocal(a, b map[string]bool) bool {
	for key := range a {
		if b[key] {
			return true
		}
	}
	return false
}
func indexObjects(value any, field string) (map[string]map[string]any, error) {
	raw, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s array is absent", field)
	}
	out := map[string]map[string]any{}
	for _, item := range raw {
		object, ok := item.(map[string]any)
		id := stringValue(object[field])
		if !ok || id == "" || out[id] != nil {
			return nil, fmt.Errorf("duplicate or invalid %s", field)
		}
		out[id] = object
	}
	return out, nil
}
func sameKeys[A, B any](a map[string]A, b map[string]B) bool {
	if len(a) != len(b) {
		return false
	}
	for key := range a {
		if _, ok := b[key]; !ok {
			return false
		}
	}
	return true
}
func keys[T any](value map[string]T) []string {
	out := make([]string, 0, len(value))
	for key := range value {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
func checkedRefs[T any](refs []sharedTypedRef, kind, scope string, index map[string]T) ([]string, error) {
	seen := map[string]bool{}
	out := []string{}
	for _, ref := range refs {
		if ref.Kind != kind || ref.Scope != scope {
			return nil, errors.New("typed reference kind/scope differs")
		}
		if _, ok := index[ref.ID]; !ok || seen[ref.ID] {
			return nil, errors.New("typed reference is invented or duplicated")
		}
		seen[ref.ID] = true
		out = append(out, ref.ID)
	}
	return out, nil
}
func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func executeSharedContractV2(ctx context.Context, req SubmitDefenseValidationRequest, runID, resultID string) RunOutcome {
	out := RunOutcome{RunID: runID, ResultID: resultID, ProfileID: req.ProfileID}
	resolver, err := newSharedV2InputResolver()
	if err != nil {
		return resolutionFailed(out, "shared-contract resolver: "+err.Error())
	}
	defer resolver.Close()
	resolved, err := resolver.ResolveV2(ctx, *req.DefenseResult, *req.CheckResult)
	if err != nil {
		return resolutionFailed(out, "shared-contract verification failed: "+err.Error())
	}
	reportExecutionProgress(ctx, "reading-application-unit", "Reading back the complete WAF application unit")
	cand, applied, err := sharedV2ApplicationUnit(resolved.Bundle, resolved.ArtifactBytes)
	if err != nil {
		return resolutionFailed(out, "application unit rejected: "+err.Error())
	}

	out = reportResolvedRule(out, cand, "shared-contract v2",
		"the verified application unit "+applied.ApplicationUnitID, os.Stdout)
	out.ApplicationUnit = &applied
	out.InputProvenance = &resolved.Provenance
	out.EvidenceRefs = append([]string{}, resolved.EvidenceRefs...)
	out.Steps = append([]string{
		"authenticated compact CG and DG locators",
		"verified embedded semantics and complete candidate bundle",
		"read back the complete application unit",
	}, out.Steps...)
	return out
}

type sharedRuleDocument struct {
	RuleSetID            string                   `json:"rule_set_id"`
	Action               string                   `json:"action"`
	PlacementMode        string                   `json:"placement_mode,omitempty"`
	CoverageAlternatives [][]string               `json:"coverage_alternatives"`
	RouteAlternatives    []sharedRouteAlternative `json:"route_bound_alternatives,omitempty"`
	Rules                []sharedRuleDefinition   `json:"rules"`
}

type sharedRouteAlternative struct {
	AlternativeID     string                        `json:"alternative_id"`
	ComponentIDs      []string                      `json:"component_ids"`
	ComponentBindings []sharedRouteComponentBinding `json:"component_bindings"`
	Route             sharedRouteBinding            `json:"route"`
}

type sharedRouteComponentBinding struct {
	ComponentID string           `json:"component_id"`
	InputRefs   []sharedTypedRef `json:"input_refs"`
}

type sharedRouteBinding struct {
	Kind      string `json:"kind"`
	Method    string `json:"method"`
	PathKey   string `json:"path_key,omitempty"`
	Scheme    string `json:"scheme,omitempty"`
	Authority string `json:"authority,omitempty"`
	Path      string `json:"path,omitempty"`
}

type sharedRuleDefinition struct {
	RuleID          string   `json:"rule_id"`
	ComponentID     string   `json:"component_id"`
	Carrier         string   `json:"carrier"`
	Name            string   `json:"name"`
	Pattern         string   `json:"pattern"`
	Flags           []string `json:"flags"`
	Transformations []string `json:"transformations"`
}

type sharedCarrierDocument struct {
	RuleSetID       string                 `json:"rule_set_id"`
	CarrierBindings []sharedCarrierBinding `json:"carrier_bindings"`
}

type sharedCarrierBinding struct {
	ComponentID string `json:"component_id"`
	Carrier     string `json:"carrier"`
	Name        string `json:"name"`
}

func decodeStrictLoose(content []byte, target any) error {
	var value any
	if err := decodeStrictJSON(content, &value); err != nil {
		return err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return json.Unmarshal(encoded, target)
}

func resolveSharedInternalLocator(locator sharedContentLocator, enclosing map[string]any) ([]byte, error) {
	if !locator.Immutable || !validSHA256(locator.Digest) || locator.ByteLength < 0 {
		return nil, errors.New("immutable locator metadata is invalid")
	}
	prefix := "janus-result-internal:" + url.QueryEscape(stringValue(enclosing["result_id"])) + "#"
	if !strings.HasPrefix(locator.URI, prefix) {
		return nil, errors.New("locator is not result-internal")
	}
	pointer, err := url.PathUnescape(strings.TrimPrefix(locator.URI, prefix))
	if err != nil {
		return nil, err
	}
	value, err := resolveSharedJSONPointer(enclosing, pointer)
	if err != nil {
		return nil, err
	}
	var content []byte
	if text, ok := value.(string); ok && locator.MediaType != "application/json" && !strings.HasSuffix(locator.MediaType, "+json") {
		content = []byte(text)
	} else {
		content, err = marshalRFC8785(value)
	}
	if err != nil || int64(len(content)) != locator.ByteLength || sha256Value(content) != locator.Digest {
		return nil, errors.New("result-internal locator content differs")
	}
	return content, nil
}

func resolveSharedJSONPointer(root any, pointer string) (any, error) {
	if pointer == "" {
		return root, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, errors.New("invalid JSON pointer")
	}
	current := root
	for _, token := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch typed := current.(type) {
		case map[string]any:
			var ok bool
			current, ok = typed[token]
			if !ok {
				return nil, errSharedJSONPointerMemberAbsent
			}
		case []any:
			var index int
			if _, err := fmt.Sscanf(token, "%d", &index); err != nil || index < 0 || index >= len(typed) {
				return nil, errSharedJSONPointerIndexInvalid
			}
			current = typed[index]
		default:
			return nil, errors.New("JSON pointer traverses a scalar")
		}
	}
	return current, nil
}

// sharedV2ApplicationUnit verifies that the resolved artifact set reads back as a
// complete, self-consistent application unit and returns the rule it carries.
//
// This is the readback check only: that a match-rule and a carrier-configuration
// artifact are both present, agree on their rule set, and cover the same rules.
// Nothing is compiled and no traffic is matched — the rule document's own bytes
// are what gets reported, and later pushed.
func sharedV2ApplicationUnit(bundle sharedCandidateBundle, contents map[string][]byte) (CandidateSpec, AppliedApplicationUnit, error) {
	if len(bundle.ApplicationUnit.ArtifactRefs) != len(contents) {
		return CandidateSpec{}, AppliedApplicationUnit{}, errors.New("application unit/content count differs")
	}
	var (
		main        sharedRuleDocument
		carriers    sharedCarrierDocument
		mainBytes   []byte
		foundMain   bool
		foundCarry  bool
		artifactIDs []string
	)
	for _, artifact := range bundle.PrimaryCandidate.Artifacts {
		content := contents[artifact.ArtifactID]
		artifactIDs = append(artifactIDs, artifact.ArtifactID)
		switch artifact.Kind {
		case "match-rule":
			if foundMain || decodeStrictLoose(content, &main) != nil {
				return CandidateSpec{}, AppliedApplicationUnit{}, errors.New("match-rule artifact is invalid")
			}
			foundMain, mainBytes = true, content
		case "configuration-fragment":
			if foundCarry || decodeStrictLoose(content, &carriers) != nil {
				return CandidateSpec{}, AppliedApplicationUnit{}, errors.New("carrier artifact is invalid")
			}
			foundCarry = true
		default:
			return CandidateSpec{}, AppliedApplicationUnit{}, fmt.Errorf("unsupported application artifact kind %q", artifact.Kind)
		}
	}
	if !foundMain || !foundCarry || main.Action != "block" || main.RuleSetID == "" ||
		main.RuleSetID != carriers.RuleSetID || len(main.Rules) == 0 ||
		len(main.Rules) != len(carriers.CarrierBindings) {
		return CandidateSpec{}, AppliedApplicationUnit{}, errors.New("complete WAF artifact set does not read back")
	}
	// Every rule must have exactly one matching carrier binding, or the unit is not
	// the complete set the producer attested to.
	bindings := map[string]bool{}
	for _, binding := range carriers.CarrierBindings {
		key := binding.ComponentID + "\x00" + binding.Carrier + "\x00" + strings.ToLower(binding.Name)
		if bindings[key] {
			return CandidateSpec{}, AppliedApplicationUnit{}, errors.New("duplicate carrier binding")
		}
		bindings[key] = true
	}
	for _, rule := range main.Rules {
		key := rule.ComponentID + "\x00" + rule.Carrier + "\x00" + strings.ToLower(rule.Name)
		if !bindings[key] {
			return CandidateSpec{}, AppliedApplicationUnit{}, errors.New("rule/carrier binding differs")
		}
	}

	sort.Strings(artifactIDs)
	cand := CandidateSpec{
		Kind:   "waf-rule",
		Engine: "janus-waf-rule-set",
		RuleID: bundle.PrimaryCandidate.CandidateID,
		Rule:   string(mainBytes),
		Action: main.Action,
	}
	if class := strings.ToLower(strings.TrimSpace(bundle.PrimaryCandidate.SelectedControlClass)); class == "firewall" {
		cand.Kind = "firewall-rule"
	}
	applied := AppliedApplicationUnit{
		ApplicationUnitID: bundle.ApplicationUnit.ApplicationUnitID,
		ArtifactIDs:       artifactIDs,
		ReadbackVerified:  true,
	}
	return cand, applied, nil
}
