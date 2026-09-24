"use strict";

// Two starting payloads. Inline carries the rule itself; upstream names a verified
// producer row and the service resolves the rule from it.
const INLINE_PAYLOAD = {
  contract_id: "defense-validation@1.0",
  candidate_artifact_id: "candidate:log4shell:waf-rule:1",
  test_basis_id: "test-basis:log4shell:true-positive:1",
  check_profile_id: "defense-validation-profile:waf-http:1",
  candidate: {
    kind: "waf-rule",
    engine: "modsecurity",
    rule_id: "1005440",
    action: "deny",
    rule:
      'SecRule REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_URI|ARGS|ARGS_NAMES ' +
      '"@rx (?i)\\$\\{jndi:(?:ldaps?|rmi|dns|nis|iiop|corba|nds|https?):/[^}]*\\}" ' +
      '"id:1005440,phase:2,deny,status:403,t:none,t:urlDecodeUni,' +
      "log,msg:'Log4Shell JNDI lookup attempt (CVE-2021-44228)',tag:'CVE-2021-44228\"",
  },
};

const UPSTREAM_PAYLOAD = {
  contract_id: "defense-validation@1.0",
  candidate_artifact_id: "candidate:akamai-waf:e6fcf665",
  test_basis_id: "unused-in-this-mode",
  check_profile_id: "defense-validation-profile:waf-http:1",
  upstream_inputs: [
    {
      capability: "control-translation",
      contract_id: "control-translation-result@2.0",
      result_id: "control-translation-result:e0b7e5cf-24ce-4c2b-9112-afc3006576de",
      result_ref: {
        system: "databricks",
        catalog: "36889_janus_dev",
        schema: "control_translation",
        table: "control_translation_results",
        key: "control-translation-result:e0b7e5cf-24ce-4c2b-9112-afc3006576de",
      },
    },
  ],
};

const INPUT_NOTES = {
  inline: "The rule travels in the request. No producer lineage, so nothing is hash-verified against an upstream result.",
  upstream: "The rule is read from the named Databricks row and verified against its content_hash before being reported.",
};

const form = document.getElementById("run-form");
const payloadEl = document.getElementById("payload");
const submitBtn = document.getElementById("submit-btn");
const apiBaseInput = document.getElementById("api-base");
const statusEl = document.getElementById("composer-status");
const runListEl = document.getElementById("run-list");
const detailEl = document.getElementById("detail");
const composerEl = document.getElementById("composer");
const inputToggle = document.getElementById("input-toggle");
const inputNote = document.getElementById("input-note");

let selectedRunId = null;
let inputMode = "inline";

inputToggle.addEventListener("click", (e) => {
  const btn = e.target.closest(".toggle-opt");
  if (!btn) return;
  inputMode = btn.dataset.mode;
  inputToggle.querySelectorAll(".toggle-opt").forEach((b) =>
    b.classList.toggle("active", b === btn)
  );
  inputNote.textContent = INPUT_NOTES[inputMode] || "";
  payloadEl.value = JSON.stringify(
    inputMode === "inline" ? INLINE_PAYLOAD : UPSTREAM_PAYLOAD, null, 2);
});

function showLanding() {
  selectedRunId = null;
  detailEl.hidden = true;
  composerEl.hidden = false;
  loadRuns();
}

function showDetail() {
  composerEl.hidden = true;
  detailEl.hidden = false;
}

const esc = (s) =>
  String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

const apiBase = () => (apiBaseInput.value || "").trim().replace(/\/+$/, "");

// A resolved rule is a success; anything else is not. None of these are verdicts
// about the rule — only about whether it could be read.
const STATE_CLASS = {
  "rule-resolved": "ok",
  failed: "err",
  malfunction: "err",
};

function setStatus(state, text) {
  statusEl.className = "response " + state;
  statusEl.textContent = text;
}

// ---- Left run panel ----

async function loadRuns() {
  let runs;
  try {
    const res = await fetch(apiBase() + "/v1/compat/defense-validation-runs");
    runs = await res.json();
  } catch (err) {
    runListEl.innerHTML = `<li class="run-empty">Cannot reach API.</li>`;
    return;
  }
  if (!Array.isArray(runs) || runs.length === 0) {
    runListEl.innerHTML = `<li class="run-empty">No runs yet.</li>`;
    return;
  }
  runListEl.innerHTML = runs
    .map((r) => {
      const cls = STATE_CLASS[r.terminal_state] || "warn";
      const active = r.run_id === selectedRunId ? " active" : "";
      const time = new Date(r.created_at).toLocaleTimeString();
      return `
        <li class="run-item${active}" data-run="${esc(r.run_id)}">
          <div class="run-top">
            <span class="dot dot-${cls}"></span>
            <span class="run-state">${esc(r.terminal_state)}</span>
          </div>
          <div class="run-id">${esc(r.run_id)}</div>
          <div class="run-time">${esc(time)}</div>
        </li>`;
    })
    .join("");
}

runListEl.addEventListener("click", (e) => {
  const li = e.target.closest(".run-item");
  if (li) selectRun(li.dataset.run);
});

document.getElementById("refresh-btn").addEventListener("click", loadRuns);
document.getElementById("new-btn").addEventListener("click", showLanding);

// ---- Run detail: immutable request + the resolved rule ----

async function selectRun(runId) {
  selectedRunId = runId;
  showDetail();
  loadRuns();
  detailEl.innerHTML = `<p class="detail-empty">Loading ${esc(runId)}…</p>`;
  let rec;
  try {
    const res = await fetch(apiBase() + "/v1/compat/defense-validation-runs/" + encodeURIComponent(runId));
    if (!res.ok) throw new Error("HTTP " + res.status);
    rec = await res.json();
  } catch (err) {
    detailEl.innerHTML = `<p class="detail-empty">Could not load run: ${esc(err.message)}</p>`;
    return;
  }
  renderDetail(rec);
}

function renderDetail(rec) {
  const o = rec.response || {};
  const time = new Date(rec.created_at).toLocaleString();
  detailEl.innerHTML = `
    <div class="detail-head">
      <span class="run-id-lg">${esc(rec.run_id)}</span>
      <span class="detail-time">${esc(time)}</span>
      <button type="button" id="back-btn" class="back-btn">＋ New run</button>
    </div>

    <h3>Request <em class="immutable">immutable</em></h3>`;

  detailEl.querySelector("#back-btn").addEventListener("click", showLanding);

  detailEl.insertAdjacentHTML("beforeend", `
    <pre class="code">${esc(JSON.stringify(rec.request, null, 2))}</pre>

    <h3>Resolved rule</h3>
    ${outcomeHTML(o)}

    <h3>Push to control plane</h3>
    ${pushHTML(o)}`);
}

// prettyRule renders a rule body: JSON rule sets are re-indented, and any other
// syntax (a ModSecurity SecRule, for instance) is shown as written.
function prettyRule(rule) {
  if (!rule) return "";
  try {
    return JSON.stringify(JSON.parse(rule), null, 2);
  } catch (err) {
    return rule;
  }
}

function outcomeHTML(o) {
  if (!o || !o.terminal_state) return `<div class="response idle">No result.</div>`;
  const cls = STATE_CLASS[o.terminal_state] || "warn";
  const cand = o.candidate || {};
  const steps = (o.steps || []).map((s) => `<li>${esc(s)}</li>`).join("");
  const limits = (o.limitations || []).map((s) => `<li>${esc(s)}</li>`).join("");

  const rule = cand.rule
    ? `<pre class="code rule">${esc(prettyRule(cand.rule))}</pre>`
    : `<p class="detail-line">No rule on this result — see the detail below.</p>`;

  return `
    <div class="response ${cls}">
      <div class="verdict"><span class="state">${esc(o.terminal_state)}</span></div>
      <p class="summary">${esc(o.prose_summary || "")}</p>
      <table class="cmp">
        <tbody>
          <tr><th>kind</th><td>${esc(cand.kind || "—")}</td></tr>
          <tr><th>engine</th><td>${esc(cand.engine || "—")}</td></tr>
          <tr><th>rule id</th><td>${esc(cand.rule_id || "—")}</td></tr>
          <tr><th>action</th><td>${esc(cand.action || "—")}</td></tr>
        </tbody>
      </table>
      ${rule}
      <p class="detail-line">${esc(o.detail || "")}</p>
      ${limits ? `<details open><summary>limitations</summary><ul>${limits}</ul></details>` : ""}
      <details><summary>resolution steps</summary><ol>${steps}</ol></details>
      <details><summary>full response JSON</summary><pre class="json-dump">${esc(JSON.stringify(o, null, 2))}</pre></details>
    </div>`;
}

// pushHTML is the placeholder for the third-party push stage. It reports what the
// rule would be pushed as, and states plainly that no push has happened.
function pushHTML(o) {
  const cand = (o && o.candidate) || {};
  if (!cand.rule) {
    return `<div class="response idle">Nothing to push: no rule was resolved.</div>`;
  }
  return `
    <div class="response idle">
      <p class="summary">Not pushed. No control-plane integration is wired up yet.</p>
      <table class="cmp">
        <tbody>
          <tr><th>target engine</th><td>${esc(cand.engine || "—")}</td></tr>
          <tr><th>control class</th><td>${esc(cand.kind || "—")}</td></tr>
          <tr><th>requested action</th><td>${esc(cand.action || "—")}</td></tr>
        </tbody>
      </table>
      <p class="detail-line">
        Whether this rule actually blocks anything is decided by the control plane
        it is pushed to, not by this service.
      </p>
    </div>`;
}

// ---- Submit ----

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  let payload;
  try {
    payload = JSON.parse(payloadEl.value);
  } catch (err) {
    setStatus("err", "Payload is not valid JSON: " + err.message);
    return;
  }

  const url = apiBase() + "/v1/compat/defense-validation-runs";
  submitBtn.disabled = true;
  submitBtn.textContent = "Resolving…";
  setStatus("idle", "Resolving the rule…");

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const body = await res.json();
    if (res.ok && body.terminal_state) {
      setStatus(body.terminal_state === "rule-resolved" ? "ok" : "err",
        "Run complete: " + body.terminal_state);
      await loadRuns();
      selectRun(body.run_id);
    } else {
      setStatus("err", "HTTP " + res.status + "\n\n" + JSON.stringify(body, null, 2));
    }
  } catch (err) {
    setStatus("err", "Request failed: " + err.message + "\nIs the API running at " + apiBase() + "?");
  } finally {
    submitBtn.disabled = false;
    submitBtn.textContent = "Resolve rule · POST";
  }
});

// ---- Init ----
// API endpoint comes from the runtime-injected env (window.DV_API_BASE), falling
// back to localhost for local dev. The field stays editable for manual override.
apiBaseInput.value = (window.DV_API_BASE || "http://localhost:8137").trim();
payloadEl.value = JSON.stringify(INLINE_PAYLOAD, null, 2);
inputNote.textContent = INPUT_NOTES.inline;
loadRuns();
