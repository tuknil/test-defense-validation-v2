package main

// xsiam_issue_cli.go backs the "xsiam-issue" subcommand.
//
//	go run . xsiam-issue [issue.json|-]          # print the request body, send nothing
//	go run . xsiam-issue --send [issue.json|-]   # actually create the issue
//	go run . xsiam-issue --from-result ct.json --cve CVE-… [--policy-id …]
//	                                             # build the payload from a
//	                                             # control-translation result
//
// Printing is the default on purpose: creating an issue is outward-facing and
// cannot be undone from here, so sending takes an explicit --send.
//
// With no file argument a worked example is built from typed values, which is
// the quickest way to see the exact body this client produces.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

func xsiamIssueCLI(args []string) {
	send := false
	var path, fromResult string
	opts := JanusPayloadOptions{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			fmt.Fprintf(os.Stderr, "xsiam-issue: %s needs a value\n", arg)
			os.Exit(1)
			return ""
		}
		switch arg {
		case "--send":
			send = true
		case "--from-result":
			fromResult = next()
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
			fmt.Fprint(os.Stderr, xsiamIssueUsage)
			return
		default:
			path = arg
		}
	}

	if fromResult != "" && path != "" {
		fmt.Fprintln(os.Stderr, "xsiam-issue: pass either an issue file or --from-result, not both")
		os.Exit(1)
	}

	var (
		issue XSIAMIssue
		err   error
	)
	if fromResult != "" {
		issue, err = issueFromControlTranslation(fromResult, opts)
	} else {
		issue, err = loadOrBuildIssue(path)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "xsiam-issue: %v\n", err)
		os.Exit(1)
	}

	body, err := EncodeIssue(issue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xsiam-issue: encode: %v\n", err)
		os.Exit(1)
	}

	if !send {
		fmt.Println(string(body))
		fmt.Fprintln(os.Stderr, "\n(dry run — nothing was sent; re-run with --send to create this issue)")
		return
	}

	cfg, err := XSIAMConfigFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "xsiam-issue: %v\n", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	res, err := NewXSIAMClient(cfg).CreateIssue(ctx, issue)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xsiam-issue: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(out))
}

const xsiamIssueUsage = `usage: xsiam-issue [--send] [issue.json|-]

  Prints the exact POST body for /public_api/v1/issue. Sends nothing unless
  --send is given.

  issue.json  a JSON object matching the "issue" body (the inner object, not the
              request_data wrapper). "-" reads stdin. Omit it to build a worked
              example instead.

  --send      create the issue. Requires XSIAM_HOST, XSIAM_API_KEY and
              XDR_AUTH_ID.

  --from-result FILE
              build the issue from a control-translation result: the rule is
              resolved and hash-verified, then mapped to januspayload.

    --cve CVE-YYYY-NNNNN        required with --from-result
    --policy-id ID              Akamai security policy id
    --rule-id N                 Akamai custom rule id
    --policy-version N          Akamai policy version
    --control-instance ID       e.g. control-instance:akamai-production
    --hostname HOST             protected hostname
    --scope ID                  e.g. population-scope:prod-web
`

// parseInt64Flag exits with a clear message rather than silently using zero,
// which would target Akamai rule 0.
func parseInt64Flag(flag, value string) int64 {
	n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xsiam-issue: %s must be a number, got %q\n", flag, value)
		os.Exit(1)
	}
	return n
}

// issueFromControlTranslation resolves the rule from a control-translation result
// file and maps it into a DEPLOY issue.
func issueFromControlTranslation(path string, opts JanusPayloadOptions) (XSIAMIssue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return XSIAMIssue{}, fmt.Errorf("read control-translation result: %w", err)
	}
	rule, err := ExtractCustomWAFRule(data)
	if err != nil {
		return XSIAMIssue{}, err
	}
	return IssueFromCustomWAFRule(rule, opts)
}

// IssueFromCustomWAFRule maps an already-resolved rule into a DEPLOY issue with
// no orchestrator identity. Use IssueForEnforcement when the caller has one: an
// issue without a correlation id cannot be traced back to the run that produced
// the rule.
func IssueFromCustomWAFRule(rule CustomWAFRule, opts JanusPayloadOptions) (XSIAMIssue, error) {
	return IssueForEnforcement(rule, EnforcementInput{JanusPayloadOptions: opts}, IssueIdentity{})
}

// IssueForEnforcement maps a resolved rule, the caller's enforcement input and
// the run's identity into a DEPLOY issue.
//
// Identity is taken from the run rather than generated: a fabricated correlation
// id would break the lineage the issue exists to carry, so an absent one stays
// absent.
func IssueForEnforcement(rule CustomWAFRule, input EnforcementInput, identity IssueIdentity) (XSIAMIssue, error) {
	opts := input.JanusPayloadOptions
	payload, err := JanusPayloadFromCustomWAFRule(rule, opts)
	if err != nil {
		return XSIAMIssue{}, err
	}

	var requestContext JanusRequestContext
	requestContext.ContractID = "xsiam-execution-seam@0.9"
	requestContext.SchemaVersion = "0.9"
	requestContext.RequestID = identity.RequestID
	requestContext.CorrelationID = identity.CorrelationID
	requestContext.CausationID = identity.CausationID
	requestContext.ExpiresAt = input.ExpiresAt
	requestContext.RequestedAction.Operation = "DEPLOY"
	requestContext.RequestedAction.ActionProfile = "akamai-waf-policy-activation"
	requestContext.RequestedAction.ActionProfileVersion = "2"
	requestContext.RequestedAction.DesiredState = "ENFORCING"
	requestContext.Subject.ThreatID = opts.CVE
	requestContext.Target.ControlTechnology = rule.Technology
	requestContext.Target.ControlInstanceID = opts.ControlInstanceID
	requestContext.Target.ProtectedHostname = opts.ProtectedHostname
	requestContext.Target.TargetScopeID = opts.TargetScopeID

	fields := JanusCustomFields{
		RequestID:             identity.RequestID,
		CorrelationID:         identity.CorrelationID,
		CausationID:           identity.CausationID,
		ContractID:            requestContext.ContractID,
		SchemaVersion:         requestContext.SchemaVersion,
		RequestContextVersion: "security-action-execution-request@0.9",
		Operation:             "DEPLOY",
		CapabilityOperation:   "enforce-on-pass",
		ActionProfile:         "akamai-waf-policy-activation",
		ActionProfileVersion:  "2",
		ControlPlane:          rule.Technology,
		Enforcement:           "ENFORCING",
		CVE:                   opts.CVE,
		TargetID:              opts.ControlInstanceID,
		ProtectedHostname:     opts.ProtectedHostname,
		TargetScopeID:         opts.TargetScopeID,
		TargetEnvironment:     targetEnvironmentFor(opts.TargetScopeID),
		CandidateID:           payload.JanusBinding.CandidateID,
		CandidateDigest:       payload.JanusBinding.CandidateDigest,
		CRRef:                 input.ChangeRef,

		AuthorizationID:         input.AuthorizationID,
		AuthorizationArtifactID: input.AuthorizationArtifactID,
		AuthorizationStatus:     input.AuthorizationStatus,
		RecoveryAuthorized:      input.RecoveryAuthorized,

		IdempotencyKey: identity.IdempotencyKey,
		ExpiresAt:      input.ExpiresAt,

		Justification: firstNonEmpty(input.Justification,
			"Enforce the validated "+rule.Technology+" candidate for "+opts.CVE+"."),
	}
	if err := fields.SetRequestContext(requestContext); err != nil {
		return XSIAMIssue{}, err
	}
	if err := fields.SetPayload(payload); err != nil {
		return XSIAMIssue{}, err
	}

	return XSIAMIssue{
		Name:            "JANUS | " + strings.ToUpper(strings.ReplaceAll(rule.Technology, "-", "_")) + " | DEPLOY | " + opts.CVE,
		Description:     "Switch one validated " + rule.Technology + " shadow rule to enforcement.",
		ObservationTime: NowMillis(),
		IssueDomain:     "Janus",
		Category:        "CONFIGURATION",
		Severity:        firstNonEmpty(input.Severity, "HIGH"),
		CustomFields:    fields,
	}, nil
}

// targetEnvironmentFor reads the environment out of a population scope id such as
// "population-scope:prod-web". It is left empty when the scope does not say, since
// mislabelling production is worse than labelling nothing.
func targetEnvironmentFor(scopeID string) string {
	_, suffix, found := strings.Cut(scopeID, ":")
	if !found {
		return ""
	}
	switch {
	case strings.HasPrefix(suffix, "prod"):
		return "production"
	case strings.HasPrefix(suffix, "stag"):
		return "staging"
	case strings.HasPrefix(suffix, "dev"):
		return "development"
	}
	return ""
}

// PostIssueForRule builds the enforcement issue for a resolved rule and posts it
// to XSIAM, reading the tenant configuration from the environment.
//
// This performs an outward-facing, irreversible create. Callers that only want to
// inspect the request should use IssueFromCustomWAFRule with EncodeIssue instead.
func PostIssueForRule(ctx context.Context, rule CustomWAFRule, opts JanusPayloadOptions) (map[string]any, error) {
	return PostEnforcementIssue(ctx, rule, EnforcementInput{JanusPayloadOptions: opts}, IssueIdentity{})
}

// PostEnforcementIssue builds the issue for a resolved rule and posts it to
// XSIAM, reading the tenant configuration from the environment.
//
// The issue is built before the client is configured, so a rule that cannot be
// mapped fails without any request being attempted.
func PostEnforcementIssue(ctx context.Context, rule CustomWAFRule, input EnforcementInput, identity IssueIdentity) (map[string]any, error) {
	issue, err := IssueForEnforcement(rule, input, identity)
	if err != nil {
		return nil, err
	}
	cfg, err := XSIAMConfigFromEnv()
	if err != nil {
		return nil, err
	}
	return NewXSIAMClient(cfg).CreateIssue(ctx, issue)
}

// loadOrBuildIssue reads an issue from a file or stdin, or builds the example.
func loadOrBuildIssue(path string) (XSIAMIssue, error) {
	if path == "" {
		return ExampleDeployIssue()
	}
	var (
		data []byte
		err  error
	)
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return XSIAMIssue{}, fmt.Errorf("read issue: %w", err)
	}

	var issue XSIAMIssue
	decoder := json.NewDecoder(bytes.NewReader(data))
	// Unknown fields are refused: a mistyped custom field would otherwise be
	// dropped silently and the issue would be created missing data.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&issue); err != nil {
		return XSIAMIssue{}, fmt.Errorf("parse issue: %w", err)
	}
	if issue.ObservationTime == 0 {
		issue.ObservationTime = NowMillis()
	}
	return issue, nil
}

// ExampleDeployIssue builds the worked DEPLOY example: one validated Akamai
// shadow rule switched to enforcement. The embedded documents are assembled from
// typed values, so the double-encoded janusrequestcontext / januspayload strings
// and their hashes are produced rather than hand-written.
func ExampleDeployIssue() (XSIAMIssue, error) {
	const (
		cve               = "CVE-2025-64446"
		controlInstanceID = "control-instance:akamai-production"
		protectedHostname = "afo.example.com"
		targetScopeID     = "population-scope:prod-web"
		candidateID       = "control-candidate:550e8400-e29b-41d4-a716-446655440003"
		candidateRevision = "4"
		candidateDigest   = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
		expiresAt         = "2026-09-24T23:30:00Z"
	)

	var requestContext JanusRequestContext
	requestContext.ContractID = "xsiam-execution-seam@0.9"
	requestContext.SchemaVersion = "0.9"
	requestContext.RequestID = "security-action-request:550e8400-e29b-41d4-a716-446655440000"
	requestContext.CorrelationID = "janus-run:550e8400-e29b-41d4-a716-446655440001"
	requestContext.CausationID = "enforcement-transaction:550e8400-e29b-41d4-a716-446655440002"
	requestContext.RequestedAction.Operation = "DEPLOY"
	requestContext.RequestedAction.ActionProfile = "akamai-waf-policy-activation"
	requestContext.RequestedAction.ActionProfileVersion = "2"
	requestContext.RequestedAction.DesiredState = "ENFORCING"
	requestContext.Subject.ThreatID = cve
	requestContext.Target.ControlTechnology = "akamai-waf"
	requestContext.Target.ControlInstanceID = controlInstanceID
	requestContext.Target.ProtectedHostname = protectedHostname
	requestContext.Target.TargetScopeID = targetScopeID
	requestContext.Target.Environment = "production"
	requestContext.ExpiresAt = expiresAt

	var payload JanusPayload
	payload.ArtifactSchema = "akamai-appsec-compound-realization@0.2"
	payload.Operation = "set-policy-action"
	payload.NativeBinding.Version = 43
	payload.NativeBinding.PolicyID = "policy-1"
	payload.NativeBinding.RuleID = 60022381
	payload.StructuredRule = JanusStructuredRule{
		Name: "Janus-Block-" + cve, Operation: "AND", Structured: true,
		Conditions: []JanusStructuredCondition{{
			Type: "pathMatch", PositiveMatch: true, ValueWildcard: true,
			Value: []string{"/api/v2.0/cmdb/system/admin", "/cgi-bin/fwbcgi"},
		}},
		Tag: []string{"janus", cve},
	}
	payload.ExpectedCurrentPolicyAction.Action = "alert"
	payload.DesiredPolicyAction.Action = "deny"
	payload.JanusBinding = JanusBinding{
		CandidateID: candidateID, CandidateRevision: candidateRevision,
		CandidateDigest:        candidateDigest,
		RealizedArtifactDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		ControlInstanceID:      controlInstanceID,
		ProtectedHostname:      protectedHostname,
		TargetScopeID:          targetScopeID,
		ExpectedLiveStateHash:  "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		RecoverySpecRef:        "recovery-spec:550e8400-e29b-41d4-a716-446655440007",
	}

	fields := JanusCustomFields{
		RequestID:             requestContext.RequestID,
		CorrelationID:         requestContext.CorrelationID,
		CausationID:           requestContext.CausationID,
		ContractID:            requestContext.ContractID,
		SchemaVersion:         requestContext.SchemaVersion,
		RequestContextVersion: "security-action-execution-request@0.9",

		Operation:           "DEPLOY",
		CapabilityOperation: "enforce-on-pass",

		ActionProfile:        "akamai-waf-policy-activation",
		ActionProfileVersion: "2",

		ControlPlane: "akamai-waf",
		Enforcement:  "ENFORCING",

		CVE: cve,

		TargetID:          controlInstanceID,
		ProtectedHostname: protectedHostname,
		TargetScopeID:     targetScopeID,
		TargetEnvironment: "production",

		CandidateID:       candidateID,
		CandidateRevision: candidateRevision,
		CandidateDigest:   candidateDigest,

		CRRef: "servicenow-change:CHG0123456",

		AuthorizationID:         "upstream-authorization:550e8400-e29b-41d4-a716-446655440004",
		AuthorizationArtifactID: "authorization-artifact:550e8400-e29b-41d4-a716-446655440005",
		AuthorizationStatus:     "active",

		RecoveryAuthorized: true,

		IdempotencyKey: "enforcement-idempotency:550e8400-e29b-41d4-a716-446655440006",
		ExpiresAt:      expiresAt,

		Justification: "Enforce the exact scope-bound production-shadow realization after pass.",
	}
	if err := fields.SetRequestContext(requestContext); err != nil {
		return XSIAMIssue{}, err
	}
	if err := fields.SetPayload(payload); err != nil {
		return XSIAMIssue{}, err
	}

	return XSIAMIssue{
		Name:            "JANUS | AKAMAI_WAF | DEPLOY | " + cve,
		Description:     "Switch one validated Akamai shadow rule to enforcement.",
		ObservationTime: NowMillis(),
		IssueDomain:     "Janus",
		Category:        "CONFIGURATION",
		Severity:        "HIGH",
		CustomFields:    fields,
	}, nil
}
