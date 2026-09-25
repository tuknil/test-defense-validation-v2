package main

// xsiam_issue_cli.go backs the "xsiam-issue" subcommand.
//
//	go run . xsiam-issue [issue.json|-]          # print the request body, send nothing
//	go run . xsiam-issue --send [issue.json|-]   # actually create the issue
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
	"time"
)

func xsiamIssueCLI(args []string) {
	send := false
	var path string
	for _, arg := range args {
		switch arg {
		case "--send":
			send = true
		case "-h", "--help":
			fmt.Fprint(os.Stderr, xsiamIssueUsage)
			return
		default:
			path = arg
		}
	}

	issue, err := loadOrBuildIssue(path)
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

  --send      create the issue. Requires XSIAM_HOST, XSIAM_API_KEY_HEADER,
              XSIAM_API_KEY and XDR_AUTH_ID.
`

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
