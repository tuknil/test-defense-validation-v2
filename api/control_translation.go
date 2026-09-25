package main

// control_translation.go reads a control-translation-result@2.0 document and
// extracts the custom WAF rule it translated — the vendor-specific artifact a
// human or an operator API would actually deploy.
//
// The rule is not a top-level field. The document carries a flat `artifacts` map
// keyed by artifact id, and `primary_candidate.artifact_id` names which entry is
// the deployable one; the rest are supporting fragments (per-alternative match
// rules, carrier bindings). Each artifact's `content` is a JSON *string*, so the
// rule needs a second unmarshal, and `content_hash` is sha256 over those exact
// content bytes.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ControlTranslationResult is the subset of control-translation-result@2.0
// needed to reach the deployable artifact. Unlisted fields (accounting,
// translation_mappings, provenance, …) are ignored on purpose: this reader is
// not a contract validator.
type ControlTranslationResult struct {
	Capability       string                                `json:"capability"`
	ContractID       string                                `json:"contract_id"`
	ResultID         string                                `json:"result_id"`
	Status           string                                `json:"status"`
	TerminalState    string                                `json:"terminal_state"`
	ProfileID        string                                `json:"profile_id"`
	PrimaryCandidate ControlTranslationCandidate           `json:"primary_candidate"`
	Artifacts        map[string]ControlTranslationArtifact `json:"artifacts"`
}

// ControlTranslationCandidate points at the deployable entry in Artifacts.
type ControlTranslationCandidate struct {
	ArtifactID            string                   `json:"artifact_id"`
	ArtifactType          string                   `json:"artifact_type"`
	CandidateID           string                   `json:"candidate_id"`
	ContentHash           string                   `json:"content_hash"`
	ContentRef            string                   `json:"content_ref"`
	TargetControlClass    string                   `json:"target_control_class"`
	TargetTechnology      string                   `json:"target_technology"`
	TargetPolicyContextID string                   `json:"target_policy_context_id"`
	CandidateMetadata     ControlCandidateMetadata `json:"candidate_metadata"`
}

// ControlCandidateMetadata carries the deployment caveats. They matter to a
// caller: syntax_profile.validation_level says how far the vendor syntax was
// actually checked, and recommended_policy_binding says the artifact does not
// embed its own action.
type ControlCandidateMetadata struct {
	SemanticRelationship string `json:"semantic_relationship"`
	SyntaxProfile        struct {
		ID              string `json:"id"`
		Family          string `json:"family"`
		DeploymentReady bool   `json:"deployment_ready"`
		ValidationLevel string `json:"validation_level"`
	} `json:"syntax_profile"`
	RecommendedPolicyBinding struct {
		Action                 string `json:"action"`
		Attachment             string `json:"attachment"`
		EmbeddedInArtifact     bool   `json:"embedded_in_artifact"`
		RequiresOperatorReview bool   `json:"requires_operator_review"`
	} `json:"recommended_policy_binding"`
}

// ControlTranslationArtifact is one entry of the artifacts map. Content is the
// vendor artifact as a JSON string, and ContentHash is sha256 over exactly those
// bytes.
type ControlTranslationArtifact struct {
	ArtifactType string `json:"artifact_type"`
	Kind         string `json:"kind"`
	Role         string `json:"role"`
	EmittedAs    string `json:"emitted_as"`
	MediaType    string `json:"media_type"`
	Order        int    `json:"order"`
	Content      string `json:"content"`
	ContentHash  string `json:"content_hash"`
}

// CustomWAFRule is the extracted rule: the raw content bytes exactly as hashed,
// plus the identity a caller needs to deploy or audit it.
type CustomWAFRule struct {
	ArtifactID   string
	ArtifactType string
	CandidateID  string
	Technology   string
	ControlClass string
	Content      []byte
	ContentHash  string
	Metadata     ControlCandidateMetadata
}

// Pretty returns Content re-indented for display. The raw bytes are returned
// unchanged when they do not re-parse, so printing never loses the payload.
func (r CustomWAFRule) Pretty() []byte {
	var buf bytes.Buffer
	if err := json.Indent(&buf, r.Content, "", "  "); err != nil {
		return r.Content
	}
	return buf.Bytes()
}

// ExtractCustomWAFRule unmarshals a control-translation result and returns the
// primary candidate's WAF artifact, verifying that the content matches its
// declared sha256 so a truncated or edited row is rejected rather than printed.
func ExtractCustomWAFRule(raw []byte) (CustomWAFRule, error) {
	var result ControlTranslationResult
	if err := json.Unmarshal(raw, &result); err != nil {
		return CustomWAFRule{}, fmt.Errorf("parse control-translation result: %w", err)
	}

	// Guard against being handed some other capability's result, where
	// primary_candidate would mean something different.
	if result.Capability != "" && result.Capability != "control-translation" {
		return CustomWAFRule{}, fmt.Errorf("not a control-translation result (capability %q)", result.Capability)
	}
	// A run that did not translate has no deployable artifact to report.
	if result.TerminalState != "" && result.TerminalState != "translated" {
		return CustomWAFRule{}, fmt.Errorf("translation did not complete (terminal_state %q)", result.TerminalState)
	}

	candidate := result.PrimaryCandidate
	if strings.TrimSpace(candidate.ArtifactID) == "" {
		return CustomWAFRule{}, fmt.Errorf("primary_candidate.artifact_id is missing")
	}
	artifact, ok := result.Artifacts[candidate.ArtifactID]
	if !ok {
		return CustomWAFRule{}, fmt.Errorf(
			"primary_candidate.artifact_id %q is not present in artifacts (%d available)",
			candidate.ArtifactID, len(result.Artifacts))
	}
	if strings.TrimSpace(artifact.Content) == "" {
		return CustomWAFRule{}, fmt.Errorf("artifact %q has empty content", candidate.ArtifactID)
	}

	// The candidate and the artifact must agree on the hash, and the content must
	// actually hash to it. Either mismatch means the row is not what the
	// translator published, so refuse rather than emit an unverified rule.
	if candidate.ContentHash != "" && candidate.ContentHash != artifact.ContentHash {
		return CustomWAFRule{}, fmt.Errorf(
			"content_hash disagrees: primary_candidate %s, artifact %s",
			candidate.ContentHash, artifact.ContentHash)
	}
	if artifact.ContentHash != "" {
		sum := sha256.Sum256([]byte(artifact.Content))
		if actual := "sha256:" + hex.EncodeToString(sum[:]); actual != artifact.ContentHash {
			return CustomWAFRule{}, fmt.Errorf(
				"artifact %q content does not match its content_hash (declared %s, actual %s)",
				candidate.ArtifactID, artifact.ContentHash, actual)
		}
	}

	// The content is a JSON string holding the vendor artifact; confirm it parses
	// so callers get a real rule document, not an opaque blob.
	if !json.Valid([]byte(artifact.Content)) {
		return CustomWAFRule{}, fmt.Errorf("artifact %q content is not valid JSON", candidate.ArtifactID)
	}

	// The candidate's own type wins; the artifact entry is the fallback.
	artifactType := candidate.ArtifactType
	if artifactType == "" {
		artifactType = artifact.ArtifactType
	}

	return CustomWAFRule{
		ArtifactID:   candidate.ArtifactID,
		ArtifactType: artifactType,
		CandidateID:  candidate.CandidateID,
		Technology:   candidate.TargetTechnology,
		ControlClass: candidate.TargetControlClass,
		Content:      []byte(artifact.Content),
		ContentHash:  artifact.ContentHash,
		Metadata:     candidate.CandidateMetadata,
	}, nil
}

// PrintCustomWAFRule unmarshals a control-translation result, extracts the
// custom WAF rule, and writes it to w: a short provenance header as comments,
// then the rule itself as indented JSON, so the output can be piped through jq
// after stripping the header — or read as-is.
func PrintCustomWAFRule(w io.Writer, raw []byte) error {
	rule, err := ExtractCustomWAFRule(raw)
	if err != nil {
		return err
	}
	return WriteCustomWAFRule(w, rule)
}

// WriteCustomWAFRule prints a rule that has already been extracted, so a caller
// that goes on to use the rule does not have to resolve and re-verify it twice.
func WriteCustomWAFRule(w io.Writer, rule CustomWAFRule) error {
	profile := rule.Metadata.SyntaxProfile
	binding := rule.Metadata.RecommendedPolicyBinding
	header := fmt.Sprintf(`// artifact_id:   %s
// artifact_type: %s
// candidate_id:  %s
// technology:    %s (control class %s)
// content_hash:  %s (verified)
// syntax:        %s, validation_level=%s, deployment_ready=%t
// binding:       action=%s via %s, embedded_in_artifact=%t, requires_operator_review=%t
`,
		rule.ArtifactID, rule.ArtifactType, rule.CandidateID,
		rule.Technology, rule.ControlClass, rule.ContentHash,
		profile.ID, profile.ValidationLevel, profile.DeploymentReady,
		binding.Action, binding.Attachment, binding.EmbeddedInArtifact, binding.RequiresOperatorReview)
	if _, err := io.WriteString(w, header); err != nil {
		return err
	}
	if _, err := w.Write(rule.Pretty()); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

// controlTranslationCLI backs the "control-translation-waf-rule" subcommand: it
// reads the result from a file argument or stdin, prints the resolved rule, and
// with --post hands that same rule to PostIssueForRule.
//
// Posting takes an explicit flag because this command's job is to print a rule:
// creating an XSIAM issue is outward-facing and cannot be undone from here, so it
// should never be a side effect of looking at one.
func controlTranslationCLI(args []string) {
	opts := JanusPayloadOptions{}
	post := false
	var path string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			fmt.Fprintf(os.Stderr, "control-translation-waf-rule: %s needs a value\n", arg)
			os.Exit(1)
			return ""
		}
		switch arg {
		case "--post":
			post = true
		case "--cve":
			opts.CVE = next()
		case "--policy-id":
			opts.PolicyID = next()
		case "--rule-id":
			opts.RuleID = parseInt64Flag(arg, next())
		case "--policy-version":
			opts.PolicyVersion = int(parseInt64Flag(arg, next()))
		case "--control-instance":
			opts.ControlInstanceID = next()
		case "--hostname":
			opts.ProtectedHostname = next()
		case "--scope":
			opts.TargetScopeID = next()
		case "-h", "--help":
			fmt.Fprint(os.Stderr, controlTranslationUsage)
			return
		default:
			path = arg
		}
	}

	var (
		data []byte
		err  error
	)
	if path != "" && path != "-" {
		data, err = os.ReadFile(path)
	} else {
		data, err = io.ReadAll(os.Stdin)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "read control-translation result: %v\n", err)
		os.Exit(1)
	}

	// Resolve and verify once; the same rule is printed and then posted.
	rule, err := ExtractCustomWAFRule(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "extract custom WAF rule: %v\n", err)
		os.Exit(1)
	}
	if err := WriteCustomWAFRule(os.Stdout, rule); err != nil {
		fmt.Fprintf(os.Stderr, "print custom WAF rule: %v\n", err)
		os.Exit(1)
	}

	if !post {
		return
	}
	res, err := PostIssueForRule(context.Background(), rule, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "control-translation-waf-rule: %v\n", err)
		os.Exit(1)
	}
	encoded, _ := json.MarshalIndent(res, "", "  ")
	fmt.Fprintf(os.Stderr, "\nposted issue to XSIAM:\n%s\n", encoded)
}

const controlTranslationUsage = `usage: control-translation-waf-rule [flags] [result.json|-]

  Resolves the custom WAF rule from a control-translation result, verifies its
  content_hash, and prints it. Sends nothing unless --post is given.

  --post      after printing, build the enforcement issue from this rule and
              POST it to XSIAM. Needs XSIAM_HOST, XSIAM_API_KEY and
              XDR_AUTH_ID, plus:

    --cve CVE-YYYY-NNNNN        required with --post
    --policy-id ID              Akamai security policy id
    --rule-id N                 Akamai custom rule id
    --policy-version N          Akamai policy version
    --control-instance ID       e.g. control-instance:akamai-production
    --hostname HOST             protected hostname
    --scope ID                  e.g. population-scope:prod-web
`
