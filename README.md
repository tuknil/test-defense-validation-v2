# defense-validation webapp

A prototype of the `defense-validation@1.0` capability (see
[defense-validation-lld.md](defense-validation-lld.md)), built as a **separate UI and
Go API server**.

It resolves a defensive control candidate from a verified producer result and
reports it. **It produces no verdict of any kind** — nothing is executed and no
traffic is sent. Pushing the resolved rule to a third-party control plane is the
next stage of this repo.

## Durable asynchronous lifecycle

The canonical orchestration API persists a queued PostgreSQL ledger row before
returning `202 Accepted`:

- `POST /v1/defense-validation-runs`
- `GET /v1/defense-validation-runs/{run_id}`
- `GET /v1/defense-validation-runs/{run_id}/result`
- `POST /v1/defense-validation-runs/{run_id}/cancel`

Submission requires `Idempotency-Key` and `X-Correlation-ID`. The body
`request_id` may be omitted during migration and is then populated from
`Idempotency-Key`; when present it must match. Body `correlation_id` may likewise
be populated from `X-Correlation-ID` and must match when present. Semantically
identical retries return the existing run, while a different normalized request
under the same key returns `409 idempotency_conflict`.

An in-process worker atomically leases queued work, heartbeats running work, and
recovers expired leases with a bounded attempt count. Every claim has a unique
lease token; heartbeats, staging, publication, completion, failure, and
cancellation are fenced by that token. Heartbeat errors or ownership loss cancel
the active executor. If a worker disappears during cancellation, lease-expiry
recovery completes the transition to `canceled`.

The accepted contract is always `defense-validation@1.0`, independent of
`DV_INPUT_UPSTREAM`. Canonical requests may carry inline artifacts,
`upstream_inputs`, or both. Upstream resolution is selected only when configured
and `upstream_inputs` is present.

An additive reference-only mode accepts no executable inline content. It requires
`route_policy: registered-waf-route-v1` and exactly two complete immutable
locators in `defense_result` and `check_result`. The resolver directly queries
only `36889_janus_dev.defense_generation.defense_generation_results` and
`36889_janus_dev.check_generation.check_generation_results`, requires exactly
one row from each, verifies row and logical-result identity and SHA-256 metadata,
and hydrates a Check Generation payload only from the fixed managed Volume
`/Volumes/36889_janus_dev/check_generation/payloads`. The Check Generation half is
verified for lineage even though no test is derived from it. The resolver verifies the complete current Defense
Generation canonical producer shape, including fully populated upstream result
references, checks `primary_candidate.artifact_hash` against the exact artifact
content, and validates the Check Generation persisted wrapper plus strict
completion/result contract versions. Both verified locators are retained in result
`input_provenance`, while verified producer
evidence lineage is stably deduplicated into result `evidence_refs`. Locator SQL
queries have a fixed 60-second deadline. Databricks input resolution is created
only when a reference-only run needs it; inline and local startup remain usable
without Databricks input configuration.

The WAF-first shared-contract path is additive and selected with
`route_policy: shared-attack-contracts-v2` and `profile_id: waf-standard@2`.
Its request contains only the authenticated CG and DG immutable locators, never
hydrated producer bodies. It first verifies both outer producer results, then
validates the embedded `attack-match-semantics@2.0` and
`candidate-bundle@1.0` against the repository-local Draft 2020-12 schemas. It
also verifies RFC 8785 digests, CG source projection and complete ancestry,
every DG artifact and directive, exact obligation mappings, candidate and bundle
digests, and the complete all-or-nothing application unit. The older
`registered-waf-route-v1` and inline/upstream paths are unchanged for replay.

V2 reads back the complete candidate artifact set all-or-nothing: a match-rule and
a carrier-configuration artifact must both be present, agree on their rule set, and
cover exactly the same rules. The match-rule document's own bytes are then the rule
that gets reported. Results add `profile_id` and the read-back `application_unit`,
which is provenance for the rule rather than a judgement about it.

Exact schemas, the offline catalog, route profile, direct CG/DG chain fixtures,
and provenance manifests are checked into `api/contracts/shared-attack-contracts`
and `api/testdata/shared-attack-contracts-v2`. Runtime schema resolution has no
network loader. The approved Draft 2020-12 validator is vendored under
`api/third_party/jsonschema`, so standalone CI has no sibling-repository dependency.

Completed results are staged in PostgreSQL before external publication. The
Databricks writer uses an insert-only `MERGE` keyed by `result_id`, then reads the
row back and requires exact `run_id` and JSON equality. Recovery republishes the
same staged bytes and never reruns the check. A completed response advertises a
Databricks `result_ref` only when a fully qualified destination is configured and
publication succeeds; otherwise the run fails without a fabricated reference.
The immutable result includes the normalized request digest, exact upstream
result identities, and deduplicated upstream evidence references used by the
check.

Optional callback delivery is enabled by supplying `X-Janus-Callback-URL`,
`X-Janus-Callback-Workflow-ID`, and `X-Janus-Callback-Signal` together. The URL
must use HTTPS, the signal must equal `janus.capability-completion.v1`, and an
optional `CAPABILITY_CALLBACK_ALLOWED_HOSTS` comma-separated allowlist restricts
the destination hostname. Body-level `callback` metadata is rejected.

After a terminal status and corresponding result response are committed, the
same PostgreSQL transaction makes one stable outbox event eligible for delivery:
`defense-validation:<run_id>:terminal:v1`. A separate leased dispatcher posts only
the workflow ID and wakeup identifiers using `CAPABILITY_CALLBACK_TOKEN`; the
canonical result body is never included. Delivery is at least once with jittered
backoff, `Retry-After` support, and indefinite 15-minute retries after the
initial schedule. Polling remains available when delivery fails or callbacks are
not configured. The callback token is never returned or logged.
Errors from the canonical lifecycle endpoints are root objects containing
`code`, `detail`, and `retryable`. Submission accepts only the
`application/json` media type (parameters such as `charset` are allowed).

Valid transitions are `queued -> running -> completed|failed|canceled`,
`queued -> canceled`, `running -> queued` for a fenced publication retry, and
expired `running -> failed|canceled` during recovery. Terminal states are
immutable.

The existing executor and UI remain available through the clearly separate,
deprecated synchronous path `POST /v1/compat/defense-validation-runs`. Enabling
`DV_INPUT_UPSTREAM` does not reroute an inline compatibility request unless that
request actually contains `upstream_inputs`.

## What a run does

A run resolves one **defensive control candidate** — the rule — and reports it.
It does not execute the rule, send attack or benign traffic, bring up a substrate,
or decide whether the rule blocks anything. Pushing the rule to a third-party
control plane is the next stage, and any pass/fail determination belongs to that
plane.

The rule can be obtained three ways, tried in this order:

1. **`route_policy: shared-attack-contracts-v2`** — verifies the compact CG
   semantics and the DG candidate bundle, then reads the complete application unit
   back. The match-rule document's own bytes are the rule.
2. **`route_policy: registered-waf-route-v1`** — verifies two immutable producer
   locators (`defense_result`, `check_result`) and takes the DG candidate.
3. **`upstream_inputs`** — reads the rule from the `control-translation` entry's
   Databricks row, and only from that entry. Its `primary_candidate` carries no
   content, so the rule is resolved through the `artifacts` map by `artifact_id`
   and verified against its `content_hash`. Any other producer's result is
   rejected rather than guessed at.
4. **inline `candidate`** — the rule travels in the request. This mode carries no
   producer lineage, so nothing is verified against an upstream result.

Every resolution failure ends the run as `failed`; a rule is never reported unless
it resolved and verified.

### Terminal states

| State | Meaning |
|---|---|
| `rule-resolved` | A rule was read from a verified producer result and reported. **This says nothing about whether the rule is effective.** |
| `failed` | No rule could be resolved. |
| `malfunction` | Internal fault, not a bad input. |

There is no `blocked` / `not-blocked` / `could-not-test`, and the result carries no
`match`, `expected`, `actual` or `substrate`: this capability reports the rule, it
does not judge it.

### Reading the rule from the CLI

The control-translation extractor is also available standalone, without the API or
a database:

```bash
cd api && go run . control-translation-waf-rule testdata/control-translation-result.json
```

It resolves `primary_candidate.artifact_id` against the `artifacts` map, verifies
`content_hash`, and prints the rule with its provenance.

With `--post` the same resolved rule is then mapped to an enforcement issue and
POSTed to XSIAM — print first, then hand off:

```bash
cd api && go run . control-translation-waf-rule result.json --post \
  --cve CVE-2026-77392 --policy-id policy-1 --rule-id 60022381 --policy-version 43 \
  --control-instance control-instance:akamai-production \
  --hostname afo.example.com --scope population-scope:prod-web
```

The rule is resolved and verified once, printed, and that same value is handed to
`PostIssueForRule` — nothing is re-parsed. Posting takes an explicit `--post`
because this command's job is to print a rule: creating an issue is
outward-facing and cannot be undone, so it is never a side effect of looking at
one. The mapping runs before the request, so a rule that cannot be mapped fails
without anything being sent.

As a library:

```go
rule, err := ExtractCustomWAFRule(resultJSON)   // resolve + verify
_ = WriteCustomWAFRule(os.Stdout, rule)         // print
res, err := PostIssueForRule(ctx, rule, opts)   // map -> issue -> POST
```

### Posting the enforcement issue from a run

A run can hand the resolved rule straight to XSIAM. Add an `enforcement` object to
the submission; omit it and nothing is posted.

```jsonc
{
  "contract_id": "defense-validation@1.0",
  // … the usual fields …
  "enforcement": {
    "cve": "CVE-2026-77392",
    "policy_id": "policy-1",
    "rule_id": 60022381,
    "policy_version": 43,
    "control_instance_id": "control-instance:akamai-production",
    "protected_hostname": "afo.example.com",
    "target_scope_id": "population-scope:prod-web",
    "change_ref": "servicenow-change:CHG0123456"
  }
}
```

The order is **rule row written → issue posted**. An issue names a candidate the
execution seam is expected to look up, so it is never posted before that row
exists; when the write is skipped or fails, the skip is recorded:

```
"No enforcement issue was posted: the rule row was not written, and an issue
 must not name a candidate that cannot be looked up."
```

**Credentials stay in the environment** (`XSIAM_HOST`, `XSIAM_API_KEY`,
`XDR_AUTH_ID`; the key header is always `Authorization` and is not configurable). They are deployment state, not request data — a
caller must not be able to redirect a hand-off to another tenant by changing a
body. Everything the rule artifact cannot supply comes from the `enforcement`
JSON; unknown keys in it are rejected, since a mistyped one would otherwise be
dropped and the issue posted with that value missing.

Identity comes from the **run**, not the body: `januscorrelationid`,
`janusrequestid` and `januscausationid` are the run's own, and
`janusidempotencykey` is the result id — so a replayed run resolving the same
result cannot create a second issue.

A posting failure **does not fail the run**. The rule is already resolved,
verified and durably written; losing the hand-off is a delivery problem, and
reporting the run as failed would misdescribe what happened. It lands in
`limitations` instead, never swallowed.

### Creating an XSIAM enforcement issue

`api/xsiam_issue.go` is a standalone client for `POST /public_api/v1/issue` — the
outward-facing hand-off that carries an enforcement request into the execution
seam. It depends only on the standard library.

```bash
cd api && go run . xsiam-issue            # print the exact POST body, send nothing
go run . xsiam-issue issue.json           # same, from your own issue JSON ("-" for stdin)
go run . xsiam-issue --send issue.json    # actually create the issue
```

Sending needs `XSIAM_HOST` (bare host, no scheme), `XSIAM_API_KEY` and
`XDR_AUTH_ID`. The key header is fixed to `Authorization`. **Printing is the default**: creating an issue
is outward-facing and cannot be undone from here, so it takes an explicit
`--send`.

Two details the API is unforgiving about, both handled for you:

- `observation_time` is epoch **milliseconds**. Seconds would silently place the
  issue in 1970.
- `janusrequestcontext` and `januspayload` are JSON **strings** inside the JSON
  body. Build them with `SetRequestContext` / `SetPayload`, which marshal the
  typed document and set the matching `…hash` field to the sha256 of exactly the
  bytes that get sent — no hand-escaping, and the hash can never drift from the
  content.

#### Building the payload from a resolved rule

`api/janus_payload.go` maps a control-translation Akamai rule set onto
`januspayload`, end to end from the result row:

```bash
cd api && go run . xsiam-issue --from-result testdata/control-translation-result.json \
  --cve CVE-2026-77392 --policy-id policy-1 --rule-id 60022381 --policy-version 43 \
  --control-instance control-instance:akamai-production \
  --hostname afo.example.com --scope population-scope:prod-web
```

The rule supplies **what** to enforce; the flags supply **where**. Akamai policy
coordinates, target identifiers and the live-state hash are not in the artifact,
so they are caller-supplied rather than invented — an invented one would target
the wrong control.

**The shapes do not line up on their own, and the gap is load-bearing.** A rule
set is `combinationOperation: OR` over alternatives that are each an `AND` of
conditions; XSIAM's `structured_rule` is a single rule with one operation. That
collapse is only sound when the alternatives differ in **at most one** condition
position:

```
(A ∧ B₁) ∨ (A ∧ B₂)   ==  A ∧ (B₁ ∨ B₂)          one position — exact
(A₁ ∧ B₁) ∨ (A₂ ∧ B₂)  ≠  (A₁ ∨ A₂) ∧ (B₁ ∨ B₂)   two — also matches A₁ ∧ B₂
```

The second form would silently widen the rule and block traffic the validated
candidate never covered, so it is **refused** with a message saying the set needs
one issue per alternative. Mismatched condition shapes, a negated condition
merging with a positive one, and alternatives that disagree on `sourceAction` are
refused for the same reason.

`realized_artifact_digest` is computed from the emitted `structured_rule`, so it
always describes what is actually sent.

`custom_fields` is a struct rather than a map, so a misspelled janus field is a
compile error; XSIAM drops unknown custom fields silently, which would otherwise
lose data with no signal. A non-2xx response returns an `*XSIAMError` carrying the
server's body, matching `curl --fail-with-body` — that body is usually the only
way to tell a bad custom field from a bad credential. The API key is never logged
or included in an error.


## Step 3 — Run ledger

Every submitted run is recorded in an in-memory ledger (LLD §11.1), keeping the
**exact immutable request bytes** alongside the executed result.

- `GET /v1/defense-validation-runs` — list runs, newest first (compact summaries).
- `GET /v1/defense-validation-runs/{run_id}` — one run's immutable `request` + full
  `response`.

The UI shows a left **Runs** panel; clicking a run opens its immutable request
(marked immutable) and rendered result on the right.

**Persistence — PostgreSQL container.** The ledger is stored in a `db` Postgres
service (`postgres:16-alpine`) defined in `docker-compose.yml`. The immutable
request and the executed response are `JSONB` columns of `defense_validation_run`.
The API connects via `DATABASE_URL` (default `postgres://mc:mc@db:5432/mitigation`)
and waits for the db healthcheck before serving.

The db data lives on the named volume `pgdata` (`/var/lib/postgresql/data`), so
runs are **durable across `docker stop` and `docker rm` of the db container** —
recreate it and the data is intact; the API's connection pool reconnects
automatically. Only `docker compose down -v` deletes the volume.

**Authoritative result sink — Databricks.** A canonical async completion is
published to a Databricks Delta table. The `result_id` column stores the run's full
`result_id` value (`defense-validation-result:<hex>`), and the
[result envelope](#result-envelope)'s `result_ref.key` reports that same value, so
a consumer can `SELECT … WHERE result_id = '<value>'`. Publication is an
insert-only, idempotent `MERGE` with exact read-back verification. A transient
failure retries the staged result under a new fenced lease; exhaustion or an
unconfigured sink fails the run without returning a Databricks reference. Config
(put the DSN, which carries a token, in
`.env` — never in `docker-compose.yml`):

```
DATABRICKS_DSN=token:<PAT>@<host>/sql/1.0/warehouses/<id>
DATABRICKS_CATALOG=...
DATABRICKS_SCHEMA=...
DATABRICKS_TABLE=defense_validation
DATABRICKS_RULE_TABLE=defense_validation_rules
```

Target table:
`defense_validation(run_id string, result_id string, result_json STRING, primary key(run_id, result_id))`.

**Rule sink.** The resolved rule is additionally written to its own table, so it is
queryable directly rather than only as a field inside a result blob — this is the
row a push integration reads:

```sql
create table defense_validation_rules(
  run_id string, result_id string, candidate_id string,
  kind string, engine string, action string,
  rule string, rule_sha256 string, source string, created_at timestamp,
  constraint rule_pk primary key(result_id)) using delta
```

The write is an insert-only idempotent `MERGE` keyed by `result_id`, so a retried
run rewrites the same row and a rule already handed off is never mutated. It is a
hand-off, not a gate: a write failure does not invalidate an already-verified rule,
so the run still reports it and records the failure in `limitations` rather than
swallowing it.

**Running without Databricks.** With `DATABRICKS_DSN` unset both sinks are
disabled, the run still completes, and `result_ref` is a stand-in built from the
configured destination and marked `"placeholder": true`:

```json
"result_ref": { "system": "databricks", "catalog": "…", "schema": "…",
                "table": "defense_validation", "key": "defense-validation-result:…",
                "placeholder": true }
```

Nothing was written at that address. The marker is the contract: a consumer must
treat a placeholder reference as "this is where the row would go", never as a row
it can read. `limitations` also records that the rule was not written.
The host must be reachable from the API and the workspace's IP access list must
allow it. A `403 "Unauthorized network access"` means the API's authorized route
or workspace access configuration must be corrected.

### Result envelope

Every run response (and the stored ledger/`GET` record) leads with a compact
envelope, then appends the resolved `candidate` rule, `detail`, `steps` and
`limitations`. There is no verdict detail. The
`candidate` and `test_basis` are embedded so a `defense_validation` row is
self-contained — a downstream consumer reads the rule and test from that row and
need not query the upstream table the rule was sourced from:

```json
{
  "capability": "defense-validation",
  "contract_id": "defense-validation@1.0",
  "run_id": "dv-run-…",
  "result_id": "defense-validation-result:1c40b2497a6f766452572f2c",
  "terminal_state": "rule-resolved",
  "status": "completed",
  "correlation_id": "mc-request:CVE-2021-44228:waf:1",
  "result_ref": {
    "system": "databricks", "catalog": "…", "schema": "…", "table": "defense_validation",
    "key": "defense-validation-result:1c40b2497a6f766452572f2c"
  },
  "evidence_refs": []
}
```

- `terminal_state` — `rule-resolved`, `failed`, or `malfunction`. It reports
  whether a rule could be resolved, never whether the rule is effective.
- `status` — canonical async lifecycle status. `completed` is exposed only after
  authoritative Databricks publication; `failed` includes a stable failure
  envelope. The deprecated synchronous compatibility path may still report its
  legacy `storage-failed` value.
- `correlation_id` — echoed from the request when supplied (optional).
- `result_ref` — points at the Databricks row for this result. `key` is the
  `result_id` value itself (the same string in the top-level `result_id` and in
  the table's `result_id` column), so a consumer can
  `SELECT … WHERE result_id = '<key>'`.

For a local (non-Docker) API run, point `DATABASE_URL` at any reachable Postgres.

### Input contract: rule read from Databricks (upstream mode)

A **separate executor**, **on by default** (set env **`DV_INPUT_UPSTREAM`** to
`0`/`false`/`no` to fall back to the legacy inline-`candidate` executor), serves the same
`POST /v1/defense-validation-runs` endpoint with a different input contract. Instead
of inline artifacts the request carries **`upstream_inputs`** — each entry's
`result_ref` points at a Databricks row — and the rule comes from the
**`control-translation`** entry:

```
SELECT result_json FROM catalog.schema.table WHERE result_id = key
```

(using `DATABRICKS_DSN`). That result's `primary_candidate` carries no content of
its own: `artifact_id` names an entry in the flat `artifacts` map, and that entry's
`content` — a JSON string — is the vendor rule. It is verified against its
`content_hash`, and `primary_candidate.content_hash` must agree with the named
artifact's, before anything is reported. `target_control_class` and `artifact_type`
supply the candidate's kind and engine.

Only a `control-translation` result is read. A referenced row of any other
capability is rejected — its rule lives somewhere else entirely, and guessing would
mean reporting a rule that was never verified. Other entries may appear in
`upstream_inputs` as lineage, but they are never read as the rule.

The resolved rule is fed to the shared reporting step, so the result shape is
identical across all input modes. A read, parse or hash failure yields `failed` — a
rule is never reported unverified — and so does a request with no
`control-translation` entry.
- Upstream mode is the default; set `DV_INPUT_UPSTREAM=0` to run only the inline
  executor. Both paths require canonical `contract_id: "defense-validation@1.0"`.

## Run it — Docker (recommended)

Both services run as containers via Docker Compose:

```bash
docker compose up -d --build
```

- UI → http://localhost:8082
- API → http://localhost:8137
- API docs (Swagger UI) → http://localhost:8137/docs · spec at http://localhost:8137/openapi.yaml

The UI's API endpoint is **not hardcoded** — it's injected at container start from the
`API_BASE` env var (default `http://localhost:8137`). The nginx entrypoint renders
`env.js` (`window.DV_API_BASE`) via `envsubst`, and the UI reads it (the field stays
editable for manual override). For ACA, set `API_BASE` to the API app's public FQDN.

Then stop with `docker compose down` (keep `-v` off to preserve the ledger).

No Docker socket is needed: the API resolves and reports a rule and runs no
substrate.

## Run it — local (without Docker for the app itself)

**API** (defaults to port 8090; override with `PORT`):

```bash
cd api && PORT=8137 go run .
```

**UI** (any static file server):

```bash
cd ui && python3 -m http.server 5501
```

Open http://localhost:5501 and set the "API base URL" field to match the API
port (e.g. `http://localhost:8137`).

## Verify the API directly

```bash
curl -s -X POST localhost:8137/v1/defense-validation-runs \
  -H 'Content-Type: application/json' \
  -d '{"contract_id":"defense-validation@1.0","candidate_artifact_id":"candidate:CVE-123:waf:3","test_basis_id":"test-basis:CVE-123:1","check_profile_id":"defense-validation-profile:waf-http:1","candidate":{"kind":"waf-rule","rule":"SecRule ARGS \"@rx attack\" \"id:1,deny,status:403\""}}'
```
