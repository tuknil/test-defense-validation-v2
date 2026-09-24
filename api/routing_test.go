package main

import "testing"

// TestRunIDFromPathStripsTheMountedCollection covers the regression where the
// compatibility handler, mounted on /v1/compat/defense-validation-runs/, stripped
// the durable collection's prefix instead of its own. TrimPrefix is a no-op when
// the prefix does not match, so the full request path was handed to the ledger
// lookup and every compatibility run detail returned 404.
func TestRunIDFromPathStripsTheMountedCollection(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		base string
		want string
	}{
		{"durable run", runsPath + "/dv-run-abc", runsPath, "dv-run-abc"},
		{"durable subresource", runsPath + "/dv-run-abc/result", runsPath, "dv-run-abc/result"},
		{"durable collection", runsPath, runsPath, ""},
		{"durable collection slash", runsPath + "/", runsPath, ""},
		{"compat run", compatRunsPath + "/dv-run-abc", compatRunsPath, "dv-run-abc"},
		{"compat collection", compatRunsPath, compatRunsPath, ""},
		{"trailing slash", compatRunsPath + "/dv-run-abc/", compatRunsPath, "dv-run-abc"},
		{"wrong base yields nothing", compatRunsPath + "/dv-run-abc", runsPath, ""},
		{"unrelated path", "/healthz", runsPath, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runIDFromPath(tc.path, tc.base); got != tc.want {
				t.Errorf("runIDFromPath(%q, %q) = %q, want %q", tc.path, tc.base, got, tc.want)
			}
		})
	}

	// The two collections share a suffix, so the compatibility path must never be
	// resolvable against the durable base: that is exactly the bug being pinned.
	if got := runIDFromPath(compatRunsPath+"/dv-run-abc", runsPath); got == "dv-run-abc" {
		t.Error("compatibility path must not resolve against the durable collection base")
	}
}
