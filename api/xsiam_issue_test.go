package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func decodeIssueBody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var envelope struct {
		RequestData struct {
			Issue map[string]any `json:"issue"`
		} `json:"request_data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("issue body is not valid JSON: %v", err)
	}
	if envelope.RequestData.Issue == nil {
		t.Fatal("body is missing request_data.issue")
	}
	return envelope.RequestData.Issue
}

// TestEncodeIssueMatchesTheDocumentedShape pins the envelope, the epoch-millisecond
// observation_time, and the exact set of janus custom fields.
func TestEncodeIssueMatchesTheDocumentedShape(t *testing.T) {
	issue, err := ExampleDeployIssue()
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeIssue(issue)
	if err != nil {
		t.Fatal(err)
	}
	got := decodeIssueBody(t, body)

	for _, key := range []string{"name", "description", "observation_time", "issue_domain", "category", "severity", "custom_fields"} {
		if _, ok := got[key]; !ok {
			t.Errorf("issue is missing %q", key)
		}
	}
	// Seconds would be ~10 digits and silently land the issue in 1970.
	observed, ok := got["observation_time"].(float64)
	if !ok || int64(observed) < 1_000_000_000_000 {
		t.Errorf("observation_time must be epoch milliseconds, got %v", got["observation_time"])
	}

	fields, ok := got["custom_fields"].(map[string]any)
	if !ok {
		t.Fatal("custom_fields is not an object")
	}
	want := []string{
		"janusrequestid", "januscorrelationid", "januscausationid",
		"januscontractid", "janusschemaversion", "janusrequestcontextversion",
		"janusoperation", "januscapabilityoperation",
		"janusactionprofile", "janusactionprofileversion",
		"januscontrolplane", "janusenforcement", "januscve",
		"janustargetid", "janusprotectedhostname", "janustargetscopeid", "janustargetenvironment",
		"januscandidateid", "januscandidaterevision", "januscandidatedigest",
		"januscrref", "janusauthorizationid", "janusauthorizationartifactid", "janusauthorizationstatus",
		"janusrecoveryauthorized", "janusidempotencykey", "janusexpiresat",
		"janusrequestcontexthash", "januspayloadhash", "janusjustification",
		"janusrequestcontext", "januspayload",
	}
	for _, key := range want {
		if _, ok := fields[key]; !ok {
			t.Errorf("custom_fields is missing %q", key)
		}
	}
	if len(fields) != len(want) {
		t.Errorf("custom_fields has %d keys, want %d", len(fields), len(want))
	}
	if _, ok := fields["janusrecoveryauthorized"].(bool); !ok {
		t.Errorf("janusrecoveryauthorized must be a boolean, got %T", fields["janusrecoveryauthorized"])
	}
}

// TestEmbeddedDocumentsAreStringsWithMatchingHashes covers the double encoding:
// janusrequestcontext and januspayload are JSON *strings* in the body, and their
// hashes must describe exactly the bytes that get sent.
func TestEmbeddedDocumentsAreStringsWithMatchingHashes(t *testing.T) {
	issue, err := ExampleDeployIssue()
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeIssue(issue)
	if err != nil {
		t.Fatal(err)
	}
	fields := decodeIssueBody(t, body)["custom_fields"].(map[string]any)

	for _, pair := range []struct{ doc, hash string }{
		{"janusrequestcontext", "janusrequestcontexthash"},
		{"januspayload", "januspayloadhash"},
	} {
		encoded, ok := fields[pair.doc].(string)
		if !ok {
			t.Fatalf("%s must be a JSON string, got %T", pair.doc, fields[pair.doc])
		}
		var inner map[string]any
		if err := json.Unmarshal([]byte(encoded), &inner); err != nil {
			t.Fatalf("%s does not parse as JSON: %v", pair.doc, err)
		}
		sum := sha256.Sum256([]byte(encoded))
		if want := "sha256:" + hex.EncodeToString(sum[:]); fields[pair.hash] != want {
			t.Errorf("%s = %v, want %s (sha256 of the exact embedded bytes)", pair.hash, fields[pair.hash], want)
		}
	}

	// Spot-check that the request context survived the round trip intact.
	var requestContext JanusRequestContext
	if err := json.Unmarshal([]byte(fields["janusrequestcontext"].(string)), &requestContext); err != nil {
		t.Fatal(err)
	}
	if requestContext.RequestedAction.Operation != "DEPLOY" || requestContext.RequestedAction.DesiredState != "ENFORCING" {
		t.Errorf("requested_action = %+v", requestContext.RequestedAction)
	}
	if requestContext.Target.ProtectedHostname != "afo.example.com" {
		t.Errorf("target.protected_hostname = %q", requestContext.Target.ProtectedHostname)
	}
}

func TestSetPayloadAcceptsPreEncodedJSONAndRejectsGarbage(t *testing.T) {
	var fields JanusCustomFields
	if err := fields.SetPayload(`{"already":"encoded"}`); err != nil {
		t.Fatalf("pre-encoded JSON should be accepted: %v", err)
	}
	if fields.Payload != `{"already":"encoded"}` {
		t.Errorf("pre-encoded JSON must pass through byte for byte, got %q", fields.Payload)
	}
	if err := fields.SetPayload("not json at all"); err == nil {
		t.Error("a non-JSON string must be rejected rather than sent as a broken blob")
	}
}

// TestCreateIssuePostsTheDocumentedRequest checks the method, path, headers and
// body against a stub server.
func TestCreateIssuePostsTheDocumentedRequest(t *testing.T) {
	var (
		gotMethod, gotPath, gotAuth, gotAuthID, gotContentType string
		gotBody                                                []byte
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAuthID = r.Header.Get("x-xdr-auth-id")
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reply":{"issue_id":"ISSUE-1"}}`))
	}))
	defer server.Close()

	client := NewXSIAMClient(XSIAMConfig{
		Host: "placeholder.invalid", APIKeyHeader: "Authorization",
		APIKey: "secret-key", AuthID: "42",
		HTTPClient: server.Client(),
	})
	// Point the client at the stub without going through the real host.
	client.cfg.Host = strings.TrimPrefix(server.URL, "http://")
	client.cfg.scheme = "http"

	issue, err := ExampleDeployIssue()
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.CreateIssue(context.Background(), issue)
	if err != nil {
		t.Fatalf("CreateIssue: %v", err)
	}
	if res["reply"] == nil {
		t.Errorf("decoded response = %v", res)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/public_api/v1/issue" {
		t.Errorf("path = %q", gotPath)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type = %q", gotContentType)
	}
	if gotAuth != "secret-key" {
		t.Errorf("api key header = %q", gotAuth)
	}
	if gotAuthID != "42" {
		t.Errorf("x-xdr-auth-id = %q", gotAuthID)
	}
	if _, ok := decodeIssueBody(t, gotBody)["custom_fields"]; !ok {
		t.Error("posted body is missing custom_fields")
	}
}

// TestCreateIssueSurfacesTheErrorBody is the --fail-with-body behaviour: the
// server's own message is usually the only way to tell a bad custom field from a
// bad credential, so it must not be discarded.
func TestCreateIssueSurfacesTheErrorBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"reply":{"err_msg":"unknown custom field janustypo"}}`))
	}))
	defer server.Close()

	client := NewXSIAMClient(XSIAMConfig{
		Host: strings.TrimPrefix(server.URL, "http://"), APIKeyHeader: "Authorization",
		APIKey: "secret-key", AuthID: "42", HTTPClient: server.Client(),
		scheme: "http",
	})

	issue, _ := ExampleDeployIssue()
	_, err := client.CreateIssue(context.Background(), issue)
	if err == nil {
		t.Fatal("a 400 must be an error")
	}
	var apiErr *XSIAMError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error should be an *XSIAMError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Body, "janustypo") {
		t.Errorf("the server's message must be preserved, got %q", apiErr.Body)
	}
	// The credential must never leak into an error string.
	if strings.Contains(err.Error(), "secret-key") {
		t.Error("the API key must not appear in the error")
	}
}

func TestXSIAMConfigFromEnvNamesEveryMissingVariable(t *testing.T) {
	required := []string{"XSIAM_HOST", "XSIAM_API_KEY", "XDR_AUTH_ID"}
	for _, key := range required {
		t.Setenv(key, "")
	}
	_, err := XSIAMConfigFromEnv()
	if err == nil {
		t.Fatal("expected an error when nothing is configured")
	}
	for _, key := range required {
		if !strings.Contains(err.Error(), key) {
			t.Errorf("error should name %s: %v", key, err)
		}
	}
	// The key header is fixed, so it is not something an operator can leave unset.
	if strings.Contains(err.Error(), "XSIAM_API_KEY_HEADER") {
		t.Errorf("the header is no longer configurable and must not be reported missing: %v", err)
	}

	// A pasted URL rather than a bare host would silently build a wrong endpoint.
	t.Setenv("XSIAM_HOST", "https://example.xdr.paloaltonetworks.com/")
	t.Setenv("XSIAM_API_KEY", "k")
	t.Setenv("XDR_AUTH_ID", "1")
	if _, err := XSIAMConfigFromEnv(); err == nil {
		t.Error("a host containing a scheme or path must be rejected")
	}
}

// TestXSIAMConfigUsesTheFixedAuthorizationHeader pins the header the client
// sends, now that it is no longer read from the environment.
func TestXSIAMConfigUsesTheFixedAuthorizationHeader(t *testing.T) {
	t.Setenv("XSIAM_HOST", "example.xdr.paloaltonetworks.com")
	t.Setenv("XSIAM_API_KEY", "k")
	t.Setenv("XDR_AUTH_ID", "1")
	cfg, err := XSIAMConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKeyHeader != "Authorization" {
		t.Errorf("APIKeyHeader = %q, want Authorization", cfg.APIKeyHeader)
	}
}

func TestIssueURLIsTheDocumentedEndpoint(t *testing.T) {
	cfg := XSIAMConfig{Host: "example.xdr.paloaltonetworks.com"}
	if got := cfg.issueURL(); got != "https://example.xdr.paloaltonetworks.com/public_api/v1/issue" {
		t.Errorf("issueURL = %q", got)
	}
}
