package main

// xsiam_issue.go creates an issue in XSIAM via POST /public_api/v1/issue.
//
// This is the outward-facing hand-off: an issue carries the enforcement request
// for a validated control candidate into the execution seam. It depends only on
// the standard library and on nothing else in this package, so it can be lifted
// out as-is.
//
// Env:
//
//	XSIAM_HOST     host only, e.g. api-example.xdr.eu.paloaltonetworks.com
//	XSIAM_API_KEY  the key itself (secret; never logged or echoed)
//	XDR_AUTH_ID    value for x-xdr-auth-id
//
// The key header is always Authorization, so it is fixed rather than configured:
// one fewer variable to set, and one fewer way to misconfigure a tenant.
//
// The two heaviest fields, janusrequestcontext and januspayload, are JSON
// *strings* inside the JSON body. They are built here from typed values and
// marshalled once, so nothing has to be escaped by hand — that double encoding is
// the easiest part of this request to get wrong.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// XSIAMConfig is the connection and credential set for one tenant.
type XSIAMConfig struct {
	Host string
	// APIKeyHeader is fixed to Authorization by XSIAMConfigFromEnv; it stays a
	// field so a caller constructing a config directly can override it.
	APIKeyHeader string
	APIKey       string // secret
	AuthID       string
	// HTTPClient is optional; a 30s client is used when nil.
	HTTPClient *http.Client
	// scheme defaults to https. It exists so tests can point the client at a local
	// stub server; production callers never set it.
	scheme string
}

// XSIAMConfigFromEnv reads the three required variables. The error names what is
// missing without ever printing a value, so it is safe in logs.
func XSIAMConfigFromEnv() (XSIAMConfig, error) {
	cfg := XSIAMConfig{
		Host:         strings.TrimSpace(os.Getenv("XSIAM_HOST")),
		APIKeyHeader: "Authorization",
		APIKey:       strings.TrimSpace(os.Getenv("XSIAM_API_KEY")),
		AuthID:       strings.TrimSpace(os.Getenv("XDR_AUTH_ID")),
	}
	var missing []string
	for name, value := range map[string]string{
		"XSIAM_HOST": cfg.Host, "XSIAM_API_KEY": cfg.APIKey, "XDR_AUTH_ID": cfg.AuthID,
	} {
		if value == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return XSIAMConfig{}, fmt.Errorf("missing required environment: %s", strings.Join(missing, ", "))
	}
	// A host with a scheme or path is a common paste error and would silently
	// produce a wrong URL, so reject it rather than trying to repair it.
	if strings.Contains(cfg.Host, "/") {
		return XSIAMConfig{}, fmt.Errorf("XSIAM_HOST must be a bare host, got %q", cfg.Host)
	}
	return cfg, nil
}

// issueURL is the endpoint this client posts to.
func (c XSIAMConfig) issueURL() string {
	scheme := c.scheme
	if scheme == "" {
		scheme = "https"
	}
	return (&url.URL{Scheme: scheme, Host: c.Host, Path: "/public_api/v1/issue"}).String()
}

// ---- request body ----

// XSIAMIssueEnvelope is the outer {"request_data":{"issue":{…}}} wrapper.
type XSIAMIssueEnvelope struct {
	RequestData struct {
		Issue XSIAMIssue `json:"issue"`
	} `json:"request_data"`
}

// XSIAMIssue is the issue itself.
type XSIAMIssue struct {
	Name string `json:"name"`
	// Description is prose for a human triaging the issue.
	Description string `json:"description"`
	// ObservationTime is epoch MILLISECONDS, not seconds.
	ObservationTime int64             `json:"observation_time"`
	IssueDomain     string            `json:"issue_domain"`
	Category        string            `json:"category"`
	Severity        string            `json:"severity"`
	CustomFields    JanusCustomFields `json:"custom_fields"`
}

// JanusCustomFields are the tenant's janus* custom fields. They are modelled as a
// struct rather than a map so a misspelled key is a compile error: XSIAM silently
// drops unknown custom fields, which would otherwise lose data with no signal.
type JanusCustomFields struct {
	RequestID     string `json:"janusrequestid"`
	CorrelationID string `json:"januscorrelationid"`
	CausationID   string `json:"januscausationid"`

	ContractID            string `json:"januscontractid"`
	SchemaVersion         string `json:"janusschemaversion"`
	RequestContextVersion string `json:"janusrequestcontextversion"`

	Operation           string `json:"janusoperation"`
	CapabilityOperation string `json:"januscapabilityoperation"`

	ActionProfile        string `json:"janusactionprofile"`
	ActionProfileVersion string `json:"janusactionprofileversion"`

	ControlPlane string `json:"januscontrolplane"`
	Enforcement  string `json:"janusenforcement"`

	CVE string `json:"januscve"`

	TargetID          string `json:"janustargetid"`
	ProtectedHostname string `json:"janusprotectedhostname"`
	TargetScopeID     string `json:"janustargetscopeid"`
	TargetEnvironment string `json:"janustargetenvironment"`

	CandidateID       string `json:"januscandidateid"`
	CandidateRevision string `json:"januscandidaterevision"`
	CandidateDigest   string `json:"januscandidatedigest"`

	CRRef string `json:"januscrref"`

	AuthorizationID         string `json:"janusauthorizationid"`
	AuthorizationArtifactID string `json:"janusauthorizationartifactid"`
	AuthorizationStatus     string `json:"janusauthorizationstatus"`

	RecoveryAuthorized bool `json:"janusrecoveryauthorized"`

	IdempotencyKey string `json:"janusidempotencykey"`

	ExpiresAt string `json:"janusexpiresat"`

	RequestContextHash string `json:"janusrequestcontexthash"`
	PayloadHash        string `json:"januspayloadhash"`

	Justification string `json:"janusjustification"`

	// RequestContext and Payload are JSON documents carried as strings. Use
	// SetRequestContext / SetPayload rather than assigning them directly, so the
	// encoding and the matching hash stay consistent.
	RequestContext string `json:"janusrequestcontext"`
	Payload        string `json:"januspayload"`
}

// SetRequestContext marshals ctxDoc, stores it as the embedded string, and sets
// janusrequestcontexthash to the sha256 of exactly those bytes.
func (f *JanusCustomFields) SetRequestContext(ctxDoc any) error {
	encoded, sum, err := encodeEmbedded(ctxDoc)
	if err != nil {
		return fmt.Errorf("encode janusrequestcontext: %w", err)
	}
	f.RequestContext, f.RequestContextHash = encoded, sum
	return nil
}

// SetPayload does the same for januspayload / januspayloadhash.
func (f *JanusCustomFields) SetPayload(payloadDoc any) error {
	encoded, sum, err := encodeEmbedded(payloadDoc)
	if err != nil {
		return fmt.Errorf("encode januspayload: %w", err)
	}
	f.Payload, f.PayloadHash = encoded, sum
	return nil
}

// encodeEmbedded marshals a document and returns the string form plus the sha256
// of those exact bytes, so the hash always describes what is actually sent.
func encodeEmbedded(doc any) (string, string, error) {
	if s, ok := doc.(string); ok {
		// Already-encoded JSON is accepted as-is, but must be valid: sending a
		// malformed blob would fail server-side with a far less obvious error.
		if !json.Valid([]byte(s)) {
			return "", "", fmt.Errorf("value is a string but not valid JSON")
		}
		return s, sha256Prefixed([]byte(s)), nil
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return "", "", err
	}
	return string(encoded), sha256Prefixed(encoded), nil
}

func sha256Prefixed(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// ---- the embedded documents ----

// JanusRequestContext is the janusrequestcontext document.
type JanusRequestContext struct {
	ContractID    string `json:"contract_id"`
	SchemaVersion string `json:"schema_version"`
	RequestID     string `json:"request_id"`
	CorrelationID string `json:"correlation_id"`
	CausationID   string `json:"causation_id"`

	RequestedAction struct {
		Operation            string `json:"operation"`
		ActionProfile        string `json:"action_profile"`
		ActionProfileVersion string `json:"action_profile_version"`
		DesiredState         string `json:"desired_state"`
	} `json:"requested_action"`

	Subject struct {
		ThreatID string `json:"threat_id"`
	} `json:"subject"`

	Target struct {
		ControlTechnology string `json:"control_technology"`
		ControlInstanceID string `json:"control_instance_id"`
		ProtectedHostname string `json:"protected_hostname"`
		TargetScopeID     string `json:"target_scope_id"`
		Environment       string `json:"environment"`
	} `json:"target"`

	ExpiresAt string `json:"expires_at"`
}

// JanusPayload is the januspayload document: the realization to apply.
type JanusPayload struct {
	ArtifactSchema string `json:"artifact_schema"`
	Operation      string `json:"operation"`

	NativeBinding struct {
		Version  int    `json:"version"`
		PolicyID string `json:"policy_id"`
		RuleID   int64  `json:"rule_id"`
	} `json:"native_binding"`

	StructuredRule JanusStructuredRule `json:"structured_rule"`

	ExpectedCurrentPolicyAction struct {
		Action string `json:"action"`
	} `json:"expected_current_policy_action"`
	DesiredPolicyAction struct {
		Action string `json:"action"`
	} `json:"desired_policy_action"`

	JanusBinding JanusBinding `json:"janus_binding"`
}

// JanusStructuredRule is the vendor rule carried in the payload.
type JanusStructuredRule struct {
	Name       string                     `json:"name"`
	Operation  string                     `json:"operation"`
	Structured bool                       `json:"structured"`
	Conditions []JanusStructuredCondition `json:"conditions"`
	Tag        []string                   `json:"tag"`
}

type JanusStructuredCondition struct {
	Type          string   `json:"type"`
	PositiveMatch bool     `json:"positiveMatch"`
	Value         []string `json:"value"`
	ValueWildcard bool     `json:"valueWildcard"`
}

// JanusBinding ties the realization back to the validated candidate.
type JanusBinding struct {
	CandidateID            string `json:"candidate_id"`
	CandidateRevision      string `json:"candidate_revision"`
	CandidateDigest        string `json:"candidate_digest"`
	RealizedArtifactDigest string `json:"realized_artifact_digest"`
	ControlInstanceID      string `json:"control_instance_id"`
	ProtectedHostname      string `json:"protected_hostname"`
	TargetScopeID          string `json:"target_scope_id"`
	ExpectedLiveStateHash  string `json:"expected_live_state_hash"`
	RecoverySpecRef        string `json:"recovery_spec_ref"`
}

// ---- client ----

// XSIAMClient posts issues to one tenant.
type XSIAMClient struct {
	cfg    XSIAMConfig
	client *http.Client
}

func NewXSIAMClient(cfg XSIAMConfig) *XSIAMClient {
	c := cfg.HTTPClient
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	return &XSIAMClient{cfg: cfg, client: c}
}

// XSIAMError is a non-2xx response. It carries the body, which is what
// `curl --fail-with-body` prints: the server's own message is usually the only
// way to tell a bad custom field from a bad credential.
type XSIAMError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *XSIAMError) Error() string {
	body := strings.TrimSpace(e.Body)
	if body == "" {
		return fmt.Sprintf("xsiam: %s", e.Status)
	}
	return fmt.Sprintf("xsiam: %s: %s", e.Status, truncateForError(body))
}

func truncateForError(s string) string {
	const max = 2000
	if len(s) <= max {
		return s
	}
	return s[:max] + "… (truncated)"
}

// EncodeIssue returns the exact JSON body CreateIssue would send. It exists so a
// caller can inspect or diff the request without performing it — creating an
// issue is not reversible from here.
func EncodeIssue(issue XSIAMIssue) ([]byte, error) {
	var envelope XSIAMIssueEnvelope
	envelope.RequestData.Issue = issue
	return json.MarshalIndent(envelope, "", "  ")
}

// CreateIssue posts one issue and returns the decoded response body.
//
// It sets no retry: a retry without a server-side idempotency guarantee risks a
// duplicate issue, so whether to retry is the caller's decision. Use
// janusidempotencykey to make one safe.
func (c *XSIAMClient) CreateIssue(ctx context.Context, issue XSIAMIssue) (map[string]any, error) {
	body, err := EncodeIssue(issue)
	if err != nil {
		return nil, fmt.Errorf("encode issue: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.issueURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(c.cfg.APIKeyHeader, c.cfg.APIKey)
	req.Header.Set("x-xdr-auth-id", c.cfg.AuthID)

	res, err := c.client.Do(req)
	if err != nil {
		// The URL can appear here; the credentials are headers and never do.
		return nil, fmt.Errorf("post issue: %w", err)
	}
	defer res.Body.Close()

	// Bounded read: an error page can be arbitrarily large.
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, &XSIAMError{StatusCode: res.StatusCode, Status: res.Status, Body: string(raw)}
	}

	var decoded map[string]any
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("decode response: %w (body: %s)", err, truncateForError(string(raw)))
	}
	return decoded, nil
}

// NowMillis is the observation_time form the API expects.
func NowMillis() int64 { return time.Now().UnixMilli() }
