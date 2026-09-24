package main

// resolve_inline.go handles a request that carries the rule inline, rather than
// naming a producer result to read it from. There is nothing to look up: the
// candidate in the request body is the rule, and it is reported as-is.
//
// Inline mode carries no producer lineage, so nothing here is hash-verified
// against an upstream result. The locator and upstream_inputs paths are the
// verified ones; this path exists for driving the service directly.

import (
	"encoding/json"
	"os"
	"strings"
)

// reportInlineCandidate reports the rule supplied in the request body.
func reportInlineCandidate(req SubmitDefenseValidationRequest, runID, resultID string) RunOutcome {
	base := RunOutcome{RunID: runID, ResultID: resultID}
	if len(req.Candidate) == 0 {
		return resolutionFailed(base, "no candidate supplied: provide candidate inline, or a defense_result/check_result locator, or upstream_inputs")
	}
	var cand CandidateSpec
	if err := json.Unmarshal(req.Candidate, &cand); err != nil {
		return resolutionFailed(base, "candidate is not valid: "+err.Error())
	}
	if strings.TrimSpace(cand.Rule) == "" {
		return resolutionFailed(base, "candidate.rule is empty")
	}

	out := reportResolvedRule(base, cand, "inline request", "the request body", os.Stdout)
	out.Limitations = append(out.Limitations,
		"Inline mode carries no producer lineage: the rule was not verified against an upstream result.")
	return out
}
