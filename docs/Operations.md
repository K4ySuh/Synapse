# Synapse Operations

This guide covers the normal local workflow for the current Synapse runtime.

## Python Environment

Use a repository-local virtual environment for Synapse. This keeps MCP runtime
dependencies, Playwright, Selenium, and browser driver paths away from distro
Python packages:

```bash
cd /path/to/Synapse
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e '.[browser]'
python -m playwright install chromium
```

The Synapse launcher reads `SYNAPSE_PYTHON` from `config/synapse.env`; by
default it uses the active console `VIRTUAL_ENV`, then
`$SYNAPSE_ROOT/.venv/bin/python` when present, and falls back to `python3` only
when no venv is available. MCP clients should launch:

```text
MCPS/Synapse-MCP/bin/synapse-mcp
```

The installed `synapse-mcp` package console script can start the server too,
but the repository launcher is preferred for Beta use because it anchors
`SYNAPSE_ROOT`, `SYNAPSE_PYTHON`, runtime data, and the full `AGENTS.md`
operating prompt. If you invoke the installed console script directly, set
`SYNAPSE_ROOT` or `SYNAPSE_PROMPT_PATH`; otherwise Synapse serves a packaged
target-neutral fallback prompt so MCP prompt/resource calls still work.

Do not point the MCP client directly at system `python3` for Synapse when
browser authentication is needed. System package builds of Playwright can be
incomplete or use mismatched Node driver paths; the venv install is the
supported path for browser auth.

Verify browser support:

```bash
. .venv/bin/activate
python -m playwright --version
python - <<'PY'
from playwright.sync_api import sync_playwright
with sync_playwright() as pw:
    browser = pw.chromium.launch(headless=True)
    browser.close()
print("playwright ok")
PY
```

## Setup Check

Run:

```bash
bin/check-setup
```

The check validates local prerequisites, confirms the venv-aware Synapse MCP
starts, checks optional Playwright/Selenium imports with the configured
`SYNAPSE_PYTHON`, and prints MCP client config. The Synapse MCP entry is the
required operational endpoint; the Burp MCP entry is optional but highly
recommended when live Burp Suite state or UI/session operations are needed.
External scanner binaries such as `sqlmap`, `ffuf`, `nmap`, and `nuclei` are
warnings by default because passive workspace, dump, documentation, and static
analysis workflows can run without them. Use `bin/check-setup --strict-tools`
when validating a full active-adapter workstation.

- `synapse`
- `burp` when the optional launcher is installed, otherwise a commented example

To print only the MCP config:

```bash
bin/print-mcp-config
```

`bin/print-mcp-config` prints both the Codex TOML snippet and the Claude Code
`.mcp.json` snippet. Copy the Claude snippet into your local `.mcp.json` or
merge the `synapse` entry into an existing Claude Code MCP config. Do not
commit local MCP configuration files because they often contain absolute paths.
See `MCPS/Synapse-MCP/examples/claude-mcp-config.example.json` for a standalone
template.

## Optional Burp MCP

Synapse can operate without the Burp MCP for workspace state, scoped evidence,
offline Burp-dump analysis, crawl/recon adapters, passive triage, credential
references, and reporting. Install and configure the Burp MCP when an
engagement needs live Burp Suite operations such as proxy history, Repeater, or
Burp UI/session state.

The optional Burp MCP path expects:

- Java on `PATH`
- PortSwigger's Burp MCP proxy launcher under `MCPS/Burp-Mcp/`
- Burp Suite running with PortSwigger's MCP Server extension enabled
- `MCP_SSE_URL` in `config/synapse.env` pointing at the Burp MCP extension

`bin/check-setup` reports missing Burp MCP pieces as warnings, not setup
failures. A warning means live Burp MCP operations are unavailable from this
checkout until the optional dependency is installed or started.

## Authority-Aware Execution

The stable 174-tool stdio profile is `legacy`: its existing examples and
`confirm=true` gates remain byte-compatible. The opt-in modern profile uses
server-held authority instead. Its supported execution profiles are `observe`,
`supervised`, and `full_delegated`; action input cannot select a profile, grant,
session, step-up, dispatch, or resume state.

The production `synapse-mcp-modern` launcher projects either
`modern-compact` or `modern-direct` through official SDK 2.0.0. Compact exposes
eleven fixed operations; direct exposes all 174 actions in Registry order. Both
receive principal/session/grant bindings only through trusted adapter context,
reject those fields and `confirm` in model arguments, and call the same
Registry path as legacy. `actions.run_passive` additionally rejects any
descriptor whose maximum effects permit traffic, credential/secret use, remote
mutation, or local destruction. The modern launcher is additive; it does not
change the default frozen `synapse-mcp` server.

Generated local files are returned as opaque resource references rather than
paths. The modern adapter persists their private server-held records under
`DATA/modern-adapter/`; reads require the same principal, authority session,
workspace, allowed root, and file version after restart or across workers.

Install the isolated modern runtime with:

```bash
pip install -e '.[modern]'
```

Production startup requires private (`0600`) operator files. The identity
binding maps authenticated principals to server-held workspace and authority
contexts:

```json
{
  "version": 1,
  "principals": {
    "local-operator": {
      "defaultWorkspace": "workspace-id",
      "default": {
        "executionProfile": "supervised",
        "authoritySessionId": "operator-session"
      },
      "workspaces": {
        "workspace-id": {
          "executionProfile": "supervised",
          "authoritySessionId": "operator-session",
          "selectedGrantId": "optional-grant-id"
        }
      }
    }
  }
}
```

The request-state keyring is ordered: the first key seals new state and all
listed keys may unseal during rotation. Each decoded key must be at least 32
bytes. Add a new first key, allow in-flight TTLs to expire, then retire the old
key. Keep the server name and audience stable across workers.

```json
{
  "version": 1,
  "keys": ["base64:<operator-generated-32-byte-or-longer-key>"]
}
```

Launch stdio with an explicitly configured local principal:

```bash
synapse-mcp-modern \
  --surface modern-compact \
  --transport stdio \
  --server-name synapse-modern \
  --audience synapse-modern \
  --identity-bindings DATA/modern-adapter/identity-bindings.json \
  --stdio-principal local-operator \
  --request-state-keyring DATA/modern-adapter/request-state-keyring.json
```

`config/modern-inspector.json` contains the corresponding Inspector template.
An explicit `--allow-ephemeral-request-state` is permitted only for local,
single-process development and warns that resume does not survive restart.

Streamable HTTP additionally requires a private digest-to-principal map. Store
only the lowercase SHA-256 digest of a high-entropy bearer token, never the raw
token:

```json
{
  "version": 1,
  "tokenDigests": {
    "<64-lowercase-hex-sha256-digest>": "local-operator"
  }
}
```

Loopback HTTP uses `--transport streamable-http --http-token-map <path>` and
still requires an identity binding and persistent keyring unless explicit
ephemeral development mode is selected. Non-loopback HTTP also requires
`--enable-remote`, one or more `--allowed-host` and `--allowed-origin` values,
and either `--tls-termination direct` with certificate/key files or
`--tls-termination trusted-proxy` with explicit proxy CIDRs. Ambiguous or
untrusted forwarded headers, unused `X-Forwarded-*` fields, wildcard/blank
allowlists, non-HTTPS remote origins, duplicate/missing bearer authentication,
Host or Origin violations, and contradictory remote/TLS settings fail closed. The
adapter does not provide OAuth; deployers supply the narrow token resolver and
TLS boundary. Authenticated HTTP responses use private/no-store caching.

`--observability otel` preserves an active OpenTelemetry trace ID and uses the
deployment's standard OpenTelemetry provider/exporter configuration; without an
exporter, the SDK API remains a no-op. `--observability disabled` removes the
SDK server tracing middleware while retaining a bounded local invocation trace
ID. Trace identity affects correlation only, never authorization, and
secret/request-state contents are not logged.

Authority state is private, crash-atomic JSON at:

```text
DATA/workspaces/<workspace-id>/authority/state.json
```

Use the local operator entry point, never an MCP action, to manage it:

```bash
synapse-authority --workspace <workspace> list-grants
synapse-authority --workspace <workspace> create-grant grant.json
synapse-authority --workspace <workspace> inspect-grant <grant-id>
synapse-authority --workspace <workspace> revise-grant grant.json --expected-revision <n>
synapse-authority --workspace <workspace> revoke-grant <grant-id> --expected-revision <n>
synapse-authority --workspace <workspace> issue-step-up <grant-id> <revision> <authorization-fingerprint> <idempotency-key>
synapse-authority --workspace <workspace> list-requests
synapse-authority --workspace <workspace> inspect-request <opaque-request-state>
synapse-authority --workspace <workspace> approve-request <opaque-request-state>
synapse-authority --workspace <workspace> resume-request <opaque-request-state>
synapse-authority --workspace <workspace> adopt-legacy-job <job-id> <grant-id> --session <trusted-session-id>
synapse-authority --workspace <workspace> reconcile-dispatch <dispatch-id> <succeeded|failed|cancelled>
synapse-authority --workspace <workspace> usage <grant-id>
```

Grant JSON names total, per-window, and active counters as dispatch budgets.
One unit is one canonical action dispatch, not one HTTP request. Crawler page,
redirect, form, delay, and concurrency limits remain explicit action inputs and
are sealed into the plan fingerprint. A JSON `null` limit is explicitly
unbounded; no hidden ceiling is substituted.

`full_delegated` executes a covered plan immediately without caller
`confirm=true` or a per-call pause. `supervised` returns `ApprovalRequired`
with `-32001`, an exact requirement delta, and an opaque expiring request state
when selected sensitive dimensions need step-up. The preferred operator command
is `approve-request`: it derives the grant revision, canonical authorization
fingerprint, and idempotency key from server-held state instead of accepting
them from the client. `ScopeDenied` remains `-32002` and cannot be repaired by a
grant. Revocation and expiry stop the next new dispatch immediately.

Background polling is a zero-budget continuation only after durable dispatch
and job records agree on workspace, origin action, grant revision, dispatch,
parent plan, job, handler, effects, outputs, and lifecycle. Expiry or revocation
does not erase already-dispatched work. A pre-Phase-2 job returns an adoption
requirement in an authority-aware profile; use
`synapse-authority ... adopt-legacy-job <job-id> <grant-id> --session <trusted-session-id>`
after review.
Unknown state-changing dispatches are never retried automatically. Reconcile
them explicitly. An explicit retry is accepted only for an explicitly
idempotent plan with an idempotency key, and records `priorDispatchId`.

Reusable target credentials may use exact `targetOrigins` independently of
exact proxy/provider `providerScopes`. Migrated CORS and crawler requests
resolve target headers for every actual destination. An uncovered redirect or
discovered in-scope origin continues anonymously with a credential-coverage
observation; provider credentials remain confined to the proxy transport.

The modern adapter selects trusted bindings only from its private identity
file; per-request resume state is never read from process environment. The
official SDK seals Synapse's opaque operation handle into the client-visible
token. Drive a human-supervised round manually so an automatic state-only retry
loop does not expire while waiting for an operator:

```python
first = await client.session.call_tool(
    "actions.run_active",
    {"actionId": "cors.execute_test", "arguments": arguments},
    allow_input_required=True,
)
# A trusted operator lists/inspects the raw server-held request and runs:
# synapse-authority --workspace <workspace> approve-request <raw-request-id>
result = await client.session.call_tool(
    "actions.run_active",
    {"actionId": "cors.execute_test", "arguments": arguments},
    request_state=first.request_state,
    allow_input_required=True,
)
```

The retry must use the identical action and arguments. Synapse restores the
original correlation, idempotency key, profile, grant, and grant revision from
the durable repository before replanning. With the required production
keyring, both the client token and its bound server-held operation record
survive restart; all workers must share the same state directory, ordered
keyring, server name, audience, and identity binding. The raw authority request
remains separately durable and visible through `list-requests` and
`inspect-request`.

Rollback stops the modern server or selects the stable legacy server. Preserve
the authority file: authorized, dispatched, unknown, and historical records
remain necessary for recovery and must not be deleted during rollback.

## Environment

Launchers source:

```text
config/synapse.env
```

Use it to override local paths and binaries. Keep secrets out of this file.
Shodan keys are set only at runtime with `shodan.session_key.set`.
The `SYNAPSE_CVE_*` variables set the default CVE intelligence source endpoints
(`SYNAPSE_CVE_NVD_URL`, `SYNAPSE_CVE_KEV_URL`, `SYNAPSE_CVE_POC_GITHUB_URL`,
`SYNAPSE_CVE_GITHUB_SEARCH_URL`) and the default enabled source set
(`SYNAPSE_CVE_SOURCES`). Each endpoint resolves as runtime override → env var →
baked default, so a moved source URL can be re-pointed at runtime with
`cve.set_source_endpoint` without editing this file. CVE provider API keys (NVD,
GitHub) are set only at runtime with `cve.session_key.set`.
`SYNAPSE_PYTHON` may be set here when you need to override the console's active
`VIRTUAL_ENV` or `$SYNAPSE_ROOT/.venv`.
`SYNAPSE_REPORTS_DIR` controls the top-level local report root and defaults to
`$SYNAPSE_ROOT/reports`.
The `SYNAPSE_MCP_*_TIMEOUT_SECONDS` values bound individual stdio
`tools/call` requests and are separate from adapter `timeoutSeconds` values
recorded on background jobs. The MCP deadline returns a recoverable JSON-RPC
timeout for slow synchronous calls; it does not replace background jobs for
long-running crawls, scans, or worker workflows.

Synapse runtime data is rooted under `SYNAPSE_ROOT/DATA` by default. Relative
`SYNAPSE_DATA_DIR` values resolve from `SYNAPSE_ROOT`, and relative
`SYNAPSE_DUMP_DIR` values resolve from `SYNAPSE_DATA_DIR`; they do not resolve
from the MCP client's current working directory. `SYNAPSE_DATA_DIR` must remain
under `SYNAPSE_ROOT`, and `SYNAPSE_DUMP_DIR` must remain under
`SYNAPSE_DATA_DIR`.

## Starting A Project

Preferred entry point:

```text
project.start(
  organization="<organization>",
  hosts=["example.com"],
  notes="<operator notes>",
  dumpPath="/path/to/dump",
  fingerprint=true
)
```

This saves scope, creates evidence folders, and optionally fingerprints hosts
from an offline Burp dump. It also creates or updates a workspace using
`workspaceId` when supplied, otherwise the organization name. The workspace
scope snapshot stores authorized hosts, patterns, and CIDRs for that
engagement; active adapters use that workspace scope before falling back to the
global scope file. The response also includes authentication guidance for the
first run: if authentication is required, collect the login-flow description
before storing credentials or running authenticated tooling.

Project, scope-check, and workspace-summary responses expose counts, paths, and
a five-record preview by default. Follow `pagination.nextCursor` with `cursor`
and `limit` (`inventoryLimit` on `project.start`/`scope.set`) to enumerate large
inventories without truncation, or use `includeInventory=true` only when the
complete response is deliberately required.

## Workspace Context

The workspace layer is the preferred place for engagement knowledge. It stores
raw data locally, normalizes supported source output, deduplicates entities per
target, and returns compact summaries for the agent.

Synapse operations are organized into two adapter domains. Web application
operations include sitemap generation, crawling, content discovery, and passive
web candidate triage. Infrastructure operations include service enumeration and
external exposure/OSINT. Both domains write to the same workspace and evidence
model.

Manual ingestion:

```text
workspace.ingest_data(
  workspaceId="<workspace>",
  target="example.com",
  source="ffuf",
  dataType="tool_output",
  format="json",
  rawData="<raw ffuf json>"
)
```

Planning context:

```text
workspace.prepare_target_context(
  workspaceId="<workspace>",
  target="example.com",
  purpose="next_step_planning"
)
```

Use `workspace.summary` to scan workspace-level progress and
`workspace.create_finding` to record operator-reviewed issues. Ingestion returns
`scopeStatus` (`in_scope`, `out_of_scope`, or `scope_unset`) and a reason so
passive/offline data can be retained without hiding authorization state. Raw
evidence is kept under `DATA/workspaces/<workspace>/targets/<host>/evidence/`
and should be opened only when detail is needed.

## Offline Dump Format

The Synapse MCP expects Burp dumps inside the relevant target evidence folder,
for example
`DATA/workspaces/<workspace>/targets/<host>/evidence/burp-dumps/<dump>/`, in
this format:

```text
<dump>/
|-- manifest.json
|-- history.jsonl
|-- requests/<id>.http
`-- responses/<id>.http
```

Each `history.jsonl` entry should include request and response file paths. Paths
may be absolute or relative to the dump directory.

Run analysis with:

```text
sitemap.from_dump(dumpPath="/path/to/dump")
sqli.analyze_dump(dumpPath="/path/to/dump")
xss.analyze_dump(dumpPath="/path/to/dump")
fingerprint.from_dump(dumpPath="/path/to/dump", organization="<organization>")
```

Pass `workspaceId` to `sitemap.from_dump` when you want passive site map output
ingested into workspace target state:

```text
sitemap.from_dump(dumpPath="/path/to/dump", workspaceId="<workspace>")
```

SQLi and XSS dump analysis remain passive. When the operator wants their
candidates preserved in workspace context, pass `workspaceId`, `target`, and
`ingest=true`; Synapse stores normalized observations such as `sqli_candidate`,
`xss_candidate`, `xss_reflection`, and `xss_sink` through the adapter result
model.

Stage XSS validation with a no-traffic plan. The conservative default returns
one inert marker and the exact wire payload, without HTML, script syntax, or a
browser helper:

```text
xss.generate_test_code(
  parameter="q",
  context="html",
  url="https://example.com/search",
  mode="reflection_marker",
  marker="SYNAPSEXSS20260718"
)
```

Carry the returned `mode`, `marker`, and one value from `exactWirePayloads` into
the separately approved call to `xss.execute_test`. The marker is sent without
rewriting. Select `context_breakout` only for an approved medium-risk syntax
test and `execution` only for an approved high-risk execution-capable test; the
tool rejects a lower `riskTier` before traffic and accepts only payloads from
the matching plan.

## Site Maps And Crawling

Prefer passive site map generation when you already have a Burp-style dump:

```text
sitemap.from_dump(dumpPath="/path/to/dump", onlyInScope=true)
```

Passive dump ingestion extracts request method, URL/path/query parameters, body
parameter names, JSON field paths, cookie names, Authorization schemes, status
codes, content types, redirects, forms, JSON/GraphQL/API-like endpoints,
interesting error signals, authentication boundaries, and state-changing
methods. It does not replay requests or store cookie/header/body secret values.

For live crawling, first persist scope with `scope.set` or `project.start`, then
run:

```text
crawler.crawl(
  target="https://example.com/",
  maxPages=200,
  maxDepth=6,
  delayMillis=0,
  confirm=true
)
```

The crawler sends GET requests, extracts HTML links and forms, records query
parameters, status codes, content types, titles, and form inputs, and writes the
site map under the target workspace evidence folder. Custom external `output`
paths require `allowExternalOutput=true` after explicit approval.
For the migrated crawler path, the requested/default JSON and sibling graph
paths are resolved before dispatch and stored in the execution plan. Existing
destinations are classified as overwrite; default retention is classified as
possible local destruction. A changed/traversed/symlink-substituted path cannot
redirect the writer after policy.
It follows ordinary links, click-like navigation attributes such as `data-href`
and JavaScript `location` handlers, meta refresh targets, and bounded GET form
submissions. By default it also fetches linked JavaScript assets for route
literal extraction and follows discovered links to other persisted in-scope
hosts. POST forms are recorded as workflow context but are not submitted. Set
lower `maxPages`, `maxDepth`, nonzero `delayMillis`, or
`includeInScopeHosts=false` when OPSEC, rate, or strict single-host constraints
matter more than broad endpoint discovery. Crawl results are ingested into the
workspace layer automatically and recorded in `actions.json`; pass `workspaceId`
to select a workspace, or omit it to use the current scope organization/default
workspace.

Cross-host links, redirects, form actions, and JavaScript references outside
the workspace scope are still written as relation edges with `scopeStatus` and
`followed=false`; no request is sent to those related assets. Review the
relations before updating scope.

After an approved initial crawl and an approved scoped credential are available,
use `crawler.extended` for authenticated POST-form mapping:

```text
crawler.extended(
  target="https://example.com/",
  credentialId="prod-cookie",
  maxPostForms=50,
  confirm=true
)
```

`crawler.extended` requires a previous `crawler.crawl` action in the same target
workspace, `credentialId`, and `confirm=true`. It submits discovered POST forms
with generated test values based on input names, types, and existing hidden
values, then parses the responses for additional links and forms. Each POST
attempt is recorded in evidence and target `actions.json` with the form page,
action URL, method, status, parameter names, redacted sensitive values, response
header summary, credential metadata, and approval metadata. Forms with obvious
admin, deletion, password, upload, import/export, billing, role, or permission
markers are skipped by default; set `includeSensitivePostForms=true` only after
the operator approves that broader state-changing coverage.

`crawler.crawl` starts a background job by default. Poll completion with
`jobs.status(jobId="<job-id>")`; finalization ingests the sitemap, refreshes
workspace fingerprinting, and refreshes perimeter inventory. Pass
`background=false` only when the operator explicitly wants a blocking run.
Treat `status` as worker-process health and `resultDisposition` as crawl
coverage: a completed worker may report `partial` or `no_coverage`. The compact
`resultSummary` includes attempted requests, HTTP responses, successful
fetches, visited pages, blocked redirects, queued remainder, and categorized
errors; failed seed attempts are not counted as visited pages.

Polling does not create new authority for a job and does not require the
operator to repeat the authority already used to dispatch it. `jobs.status`
validates the job's persisted continuation plan, then may refresh/persist state,
run the finalizer once, write workspace/evidence, and remove worker/stdio
sidecars. The plan seal covers finalizer identity/data and all result/cleanup
and process-sidecar paths, so edited job metadata fails before a PID, return-code
write, finalizer, or deletion is used. It is therefore not a pure-read action.
Authority-aware execution re-evaluates grant revocation/expiry before a new
active dispatch or explicit resume while preserving the historical truth of
work already dispatched.

Site-map and crawl artifacts include a `flowGraph` object for first-glance
workflow review. It links hosts, endpoints, and forms with request, navigation,
redirect, and form-action edges, preserving HTTP methods and observed status
codes where available. Mermaid and SVG flowcharts are written next to the JSON
artifact; use `flowGraph.svgPath` for direct browser viewing and
`flowGraph.mermaidPath` as the Mermaid source.

## JavaScript Intelligence And App Maps

Use JavaScript intelligence after passive sitemap ingestion or an approved crawl
has populated workspace endpoints. It adds client-side request knowledge that
may not have appeared in observed traffic.

```text
js.discover_assets(workspaceId="<workspace>", target="example.com")
```

Asset discovery is passive. It reads stored sitemap, crawler, and workspace
endpoint data to identify `.js` and `.mjs` assets or JavaScript content-type
records.

```text
js.fetch_assets(
  workspaceId="<workspace>",
  target="example.com",
  confirm=true,
  maxAssets=50,
  maxBytesPerAsset=750000
)
```

Fetching assets sends bounded GET requests through the configured HTTP backend.
It requires in-scope targets and `confirm=true` unless `httpBackend="disabled"`
or `disableTraffic=true`. The tool stores JS assets under:

```text
DATA/workspaces/<workspace>/targets/<host>/outputs/js-intelligence/assets/
```

Static analysis does not send traffic and does not execute JavaScript:

```text
js.analyze_static(workspaceId="<workspace>", target="example.com", normalizeAfter=true)
jobs.status(jobId="<returned-analysis-job-id>")
```

It extracts API endpoints, HTTP methods, API base URLs, GraphQL operations,
WebSocket URLs, storage keys, auth/CSRF header names, and object identifier
names. Header and token values are not stored. Static analysis starts as a
background job by default with a 1800 second timeout and a default maximum of 3
concurrent JS analysis/normalization jobs. Pass `background=false` only for
explicit small blocking runs.

Normalize extracted requests into workspace entities:

```text
js.normalize_endpoints(workspaceId="<workspace>", target="example.com", ingest=true)
jobs.status(jobId="<returned-normalize-job-id>")
```

JS-derived endpoints and parameters use `source = "js_intelligence"`, include
`sourceAsset` and confidence, and are marked `derived=true`, `inferred=true`,
and `observed=false`. Existing observed endpoints remain observed; matching JS
references become `js_endpoint_reference` observations instead of changing the
observed endpoint record.

When `normalizeAfter=true` is passed to `js.analyze_static`, `jobs.status` on
the completed analysis job attempts to start `js.normalize_endpoints` using the
generated `analysisPath`. Poll the returned `normalizeJob.job.jobId` to ingest
the normalized endpoint results.

Render a comprehensive sitemap-style application map:

```text
js.render_app_map(
  workspaceId="<workspace>",
  target="example.com",
  format="html",
  outputPath="reports/js-app-map-example.html"
)
```

Supported formats are `html`, `markdown`, and `json`. Without `outputPath`,
reports are written to
`reports/<workspace>/js-app-map-<target>.html` or the matching extension.
Relative report paths resolve under `reports/<workspace>/`; external
absolute paths require `allowExternalOutput=true`.

The app map combines observed workspace requests and JS-inferred requests in a
collapsible tree. It includes request method, path, origin, parameters, source
asset, confidence, JavaScript asset inventory, and JS static-analysis signals.
There is one canonical JavaScript report: the HTML app map is the JavaScript
Intelligence layer report, identical to
`documentation.render_layer_report(layer="js")` for that target. Markdown and
JSON formats keep the compact app-map structure. Treat JS-inferred requests as
hypotheses until confirmed through observed traffic or an approved validation
workflow.

Crawler and sitemap ingestion can produce prioritized candidate observations in
`observations.json`, including `sitemap_finding_candidate`,
`post_form_candidate`, high-value form leads, `auth_boundary`,
`state_changing_method`, `authorization_header_observed`, `json_endpoint`,
`graphql_endpoint`, `api_route`, `redirect_observed`, and `interesting_error`.
These are planning leads, not operator-reviewed findings.

## External Perimeter Inventory

After scope setup and initial data collection through crawl, sitemap import,
nmap, Shodan, nuclei, or operator notes, build a passive external-perimeter
inventory:

```text
fingerprint.analyze_workspace(workspaceId="<workspace>", target="example.com")
perimeter.analyze_workspace(workspaceId="<workspace>")
perimeter.build_summary(workspaceId="<workspace>")
perimeter.render_report(
  workspaceId="<workspace>",
  format="html",
  outputPath="reports/perimeter.html"
)
```

The workspace fingerprint layer normalizes technology names, versions, layers,
confidence, and evidence sources from stored services, endpoints, headers,
cookies, and observations. The perimeter layer classifies host assets, web
applications, underlying stack, canonical login/admin portals, protected
resources, candidate review items, and recommended next steps from stored
workspace data. It writes `models/perimeter.json` under each target and
`perimeter-summary.json` at workspace level. Both steps are passive and do not
send traffic.

If an Nmap import contains at least 100 apparent open services and at least 75%
are `tcpwrapped`, Synapse records `scan_interference` and retains the raw rows
but excludes them from planning, fingerprinting, and perimeter/CVE correlation.
Treat the inventory as a coverage gap and rerun a narrower version-aware
profile before using it for CVE reasoning.

For completed crawl or recon jobs, the default review sequence is:

```text
jobs.list(activeOnly=true, workspaceId="<workspace>")
jobs.status(jobId="<job-id>")
fingerprint.analyze_workspace(workspaceId="<workspace>", target="example.com")
perimeter.build_summary(workspaceId="<workspace>", refresh=true)
perimeter.render_report(workspaceId="<workspace>", refresh=true, format="html")
```

Without an explicit `outputPath`, generated perimeter reports are written to
`reports/<workspace>/perimeter.html` or
`reports/<workspace>/perimeter.md`. If you provide a relative path, keep it
workspace-report-root-relative, for example `reports/perimeter.html`; do not prefix it
with `DATA/workspaces/...`.

Only after reviewing these outputs should the next plan suggest deeper
technology or version validation such as nmap service detection, Nuclei
technology templates, or targeted approved probes.

## Finding Lifecycle

Heuristic observations are hypotheses until an operator promotes or records
them as findings. Deterministic passive analyzers may store conclusive facts as
`operatorReviewed=false` findings pending signoff. Use:

```text
workspace.promote_observation_to_finding(
  workspaceId="<workspace>",
  target="example.com",
  type="sitemap_finding_candidate",
  value="https://example.com/admin",
  status="candidate"
)

workspace.mark_finding_reviewed(
  workspaceId="<workspace>",
  target="example.com",
  findingId="<finding-id>",
  status="confirmed"
)
```

The lifecycle tools support `candidate`, `confirmed`, `false_positive`,
`accepted_risk`, and `fixed` statuses. Use `workspace.update_finding` for
impact, remediation, reproduction steps, severity, and confidence changes;
`workspace.link_evidence_to_finding` for evidence IDs; and
`workspace.export_finding_context` when preparing report context.

## Pretexts And Detection Outcomes

Pretext candidates are stored as draft workspace entities with provenance
references to observations. Review the draft text and source references before
approval:

```text
approve_pretext_candidate(
  workspaceId="<workspace>",
  target="example.com",
  entityKey="<pretext-key>",
  confirm=true
)
```

Report behavior is fixed: internal reports include the pretext subject, sender
persona, body template, and observation reference IDs; high-level reports show
only aggregate pretext counts by sophistication and status.

Actions can carry `mitreTechniqueId` for purple-team debriefs. After the
blue-team review, record the observed detection outcome:

```text
mark_detection_outcome(
  workspaceId="<workspace>",
  target="example.com",
  actionKey="<action-key>",
  detected=false,
  notes="No matching alert found during debrief."
)
```

If the technique ID exists in the static reference table, Synapse creates or
updates one `detection_gap` entity for that action. Detection Coverage renders
only in internal reports.

## Passive Candidate Triage

After sitemap, crawler, Shodan, or operator-note ingestion has populated a
workspace target, run passive candidate analyzers before considering active
validation:

```text
ssrf.analyze_workspace(
  workspaceId="<workspace>",
  target="example.com",
  ingest=true
)

open_redirect.analyze_workspace(
  workspaceId="<workspace>",
  target="example.com",
  ingest=true
)

command_injection.analyze_workspace(
  workspaceId="<workspace>",
  target="example.com",
  organization="<organization>",
  ingest=true
)
```

These tools do not send traffic. They store `ssrf_candidate` and reportable
`open_redirect_candidate` observations when ingestion is enabled. Open-redirect
analysis canonicalizes repeated method/route/location/parameter surfaces and
requires navigation semantics: an observed `Location`, a client navigation
sink, a redirect-specific route, or authentication continuation context. A URL
value alone is insufficient. WordPress oEmbed URL inputs and uncorroborated
search configuration are stored as non-reportable
`open_redirect_surface_classification` observations; oEmbed remains eligible
for SSRF review. Re-running analysis suppresses stale redirect candidates while
preserving their history. Command injection analysis stores
`command_injection_candidate` observations and reads
`fingerprint.json` when available to infer `unix`, `windows`, or `unknown`
payload syntax. A reportable command-injection candidate requires boundary-
matched parameter semantics plus independent route, observed-request,
JavaScript execution-API, or OS command-response corroboration. A weak single
signal is stored as a low-confidence, non-reportable
`command_injection_discovery` observation and should not enter an active
validation queue. Use the test plan helpers to prepare manual validation inputs
and guardrails:

```text
ssrf.generate_test_plan(candidate=<candidate>, callbackBaseUrl="https://canary.example")
open_redirect.generate_test_plan(candidate=<candidate>, externalUrl="https://redirect-test.example/")
command_injection.generate_test_plan(candidate=<candidate>)
```

Command-injection test plans use only benign echo-style marker payloads. To
manually replay one allowlisted payload in Burp Repeater or another client
without having Synapse send traffic, build a redacted request first:

```text
command_injection.prepare_replay(candidate=<candidate>, marker="SYNAPSE_CHECK")
```

If the operator approves active validation for a specific candidate, run one
bounded marker request:

```text
command_injection.execute_test(
  workspaceId="<workspace>",
  candidate=<candidate>,
  confirm=true,
  approvalReason="<operator-approved benign marker test>",
  riskTier="low"
)
```

The active test enforces scope, can use `credentialId`, redacts secret-bearing
headers from evidence, and records `possible_command_injection` only when the
marker is observed in the response.

The SSTI, LFI/RFI, and SSI adapters follow the same workspace-first pattern:

```text
ssti.passive_analyze(workspaceId="<workspace>", target="example.com", ingest=true)
lfi.passive_analyze(workspaceId="<workspace>", target="example.com", ingest=true)
ssi.passive_analyze(workspaceId="<workspace>", target="example.com", ingest=true)
```

They store candidate observations such as `ssti_candidate`, `lfi_candidate`,
`rfi_candidate`, `path_traversal_candidate`, `file_download_candidate`, and
`ssi_candidate`. Their planners do not send traffic:

```text
ssti.plan_tests(candidate=<candidate>)
lfi.plan_tests(candidate=<candidate>)
ssi.plan_tests(candidate=<candidate>)
```

SSTI and SSI can also build no-traffic manual replay requests for built-in
benign payloads:

```text
ssti.prepare_replay(candidate=<candidate>, payload="{{7*7}}")
ssi.prepare_replay(candidate=<candidate>, payload="<!-- synapse-ssi-marker -->")
```

Active validation is available only with exact operator approval and
`confirm=true`. SSTI uses benign arithmetic/syntax probes, LFI/RFI uses
public-file and path-normalization probes, and SSI uses marker comments plus a
safe non-command echo directive. These active tools enforce scope, support
`credentialId`, redact secret-bearing headers, store raw evidence, and record
workspace actions.

Access-control mapping and planning are no-traffic by default:

```text
access_control.identify_objects(workspaceId="<workspace>", target="example.com", ingest=true)
access_control.record_context(
  workspaceId="<workspace>",
  target="example.com",
  contextId="user_a",
  role="user",
  credentialId="user-a-cookie",
  ownedObjectTypes=["user", "account"]
)
access_control.build_test_matrix(workspaceId="<workspace>", target="example.com", ingest=true)
access_control.plan_tests(matrixEntry=<matrix-entry>)
```

The adapter stores its extended model under the target's `models/access-control/`
folder while also creating normal workspace observations. `objects.json` and
`matrix.json` are current reportable snapshots; `classifications.json` retains
framework/public fields, identifiers without object shape or authorization
context, dependency/example-only inferred routes, and routes consistently
observed as 404/410. Mixed status evidence prevents automatic refutation.
Only reportable protected-object or privileged-function candidates enter the
matrix, while stale observations remain stored with `isReportable=false`. Use
`record_context` to map authorized user, role, and credential labels before
building the matrix. Matrix entries describe BOLA, BOPLA, and BFLA test ideas,
required contexts, risk tier, and missing information. Request replay is not
performed by the planner. BOLA/BOPLA comparisons require two authenticated
peers and BFLA requires privileged plus non-privileged authenticated roles.
Missing roles are written to `coverage-gaps.json` as blocked, non-executable
coverage gaps. An explicitly recorded anonymous context creates a separate
`ANONYMOUS_BASELINE` entry and never substitutes for an authenticated role.
To confirm a specific executable matrix entry, the operator must
approve an exact replay with concrete contexts and a concrete request URL:

```text
access_control.execute_matrix_test(
  workspaceId="<workspace>",
  target="example.com",
  matrixEntry=<matrix-entry>,
  requestUrl="https://example.com/api/users/123",
  contexts=[
    {"contextId": "user_a", "credentialId": "user-a-cookie", "expectedAccess": true},
    {"contextId": "user_b", "credentialId": "user-b-cookie", "expectedAccess": false}
  ],
  confirm=true,
  approvalReason="<operator-approved cross-context replay>",
  riskTier="medium"
)
```

Replay enforces scope, uses credential IDs instead of pasted secrets, blocks
state-changing methods unless `allowStateChanging=true`, compares full responses
in memory, stores sanitized response summaries in `models/access-control/replays.json`,
records an action, and stores a deterministic `requestFingerprint` plus a
nonced `replayId` for each execution. It creates
`possible_broken_access_control` observations when a context expected to be
denied receives a similar successful response. Identical 2xx application-error
JSON is downgraded with `downgradeReason: identical_error_shaped_json` unless
success markers or data-bearing JSON keys are present.
If an authenticated replay context has no usable `credentialId` for the target,
Synapse fails before traffic. Replay context IDs must exactly match the matrix's
`requiredContexts`. Anonymous replay requires an explicitly anonymous baseline
context; the tool does not convert missing or invalid authenticated roles to
anonymous requests.

The passive API, auth, and misconfiguration analyzers run the same way: read
existing workspace state, optionally `ingest=true`, and send no traffic.

```text
spec_import.import_spec(workspaceId="<workspace>", target="example.com", rawData="<openapi-or-postman-json>", ingest=true)
headers_cookies.analyze_workspace(workspaceId="<workspace>", target="example.com", ingest=true)
csrf.analyze_workspace(workspaceId="<workspace>", target="example.com", ingest=true)
cors.analyze_workspace(workspaceId="<workspace>", target="example.com", ingest=true)
xxe.analyze_workspace(workspaceId="<workspace>", target="example.com", ingest=true)
insecure_deser.analyze_workspace(workspaceId="<workspace>", target="example.com", ingest=true)
graphql.analyze_workspace(workspaceId="<workspace>", target="example.com", ingest=true)
tls_posture.analyze_workspace(workspaceId="<workspace>", target="example.com", ingest=true)
jwt.analyze(token="<operator-supplied-jwt>")
```

`spec_import` normalizes documented OpenAPI/Swagger/Postman endpoints as inferred
(not observed) surface. `headers_cookies` reports missing or weak security
headers and insecure cookie flags from already-captured responses (cookie names
and flags only, never values). `csrf` recognizes normalized framework token
names and separates authenticated state changes from login, logout, recovery,
and registration. Ordinary untokenized authentication forms do not enter the
candidate queue by default. Supply exact-URL `workflowContexts` only after
operator review: login requires an attacker-account/session-switch description,
`credentialedBaselineApproved=true`, a stored target-scoped
`baselineCredentialId`, and `approvalId`; recovery/registration requires a
concrete `unauthorizedStateChangeImpact` plus `impactEvidenceIds`. Missing
prerequisites and recognized-token forms remain non-reportable classifications.
Weak `SameSite` signals adjust priority only after eligibility. `xxe` and
`insecure_deser` raise XML-parser and serialized-blob candidates.
`tls_posture` normalizes certificate and protocol issues from existing
Shodan/perimeter SSL data. `jwt.analyze` performs offline structural analysis of
an operator-supplied token and never echoes the token or any matched secret.

Two of these expose one bounded active probe each, gated by scope and
`confirm=true` after operator approval:

```text
cors.execute_test(workspaceId="<workspace>", candidate=<cors-candidate>, confirm=true, approvalReason="<approved Origin-reflection probe>")
graphql.execute_test(workspaceId="<workspace>", candidate=<graphql-candidate>, confirm=true, approvalReason="<approved introspection probe>")
```

`cors.analyze_workspace` separates browser-readable credentialed-origin
candidates from informational policy observations. Public wildcard reads and
wildcard-plus-credentials do not enter the vulnerability queue; fixed
credentialed allowlists also remain informational unless workspace evidence
shows that the allowed origin was supplied cross-origin. Credentialed `null`
policies remain candidates because a sandboxed attacker context can serialize a
null origin.

`cors.execute_test` sends one Origin request and records a normalized browser
verdict. A reportable `possible_cors_misconfiguration` requires the exact
attacker-controlled probe origin (including an explicitly selected `null`
origin) and `Access-Control-Allow-Credentials: true`. Wildcard plus credentials
is `invalid_noncredentialed_wildcard`: the response may be public without
credentials, but the browser rejects a credentialed read. Public reads remain
informational until response sensitivity is reviewed separately.
`graphql.execute_test` sends one introspection POST and, on a successful schema,
normalizes GraphQL operations and arguments into workspace endpoints and
parameters without executing discovered operations.

## Scoped Credentials

Persist HTTP credentials only after scope is set. Each credential is bound to one
or more authorized hosts and is redacted from tool responses:

```text
credentials.set(
  id="prod-cookie",
  type="cookie",
  scopes=["example.com"],
  secret="SESSIONID=...",
  confirm=true
)
```

Supported types are `bearer`, `basic`, `cookie`, `header`, and browser-derived
`session`. Use a stored credential with HTTP tools by passing `credentialId`,
for example:

```text
crawler.crawl(target="https://example.com/", credentialId="prod-cookie", confirm=true)
ffuf.build_command(target="https://example.com/", wordlist="/path/to/words.txt", credentialId="prod-cookie")
nuclei.build_command(target="https://example.com/", profile="medium", credentialId="prod-cookie")
```

Secrets are stored locally under `DATA/credentials/credentials.json` with file
mode `0600` where supported. `credentials.list` and `credentials.get` redact
secret values. Custom header credentials must use valid HTTP token header names
and cannot contain CR/LF in the header name or value.

For cookie-based sessions that need renewal, store an authentication profile
after scope is set and operator approval is available:

```text
credentials.set_auth_profile(
  id="main-login",
  credentialId="prod-cookie",
  scopes=["example.com"],
  loginUrl="https://example.com/login",
  username="alice",
  password="<password>",
  usernameField="username",
  passwordField="password",
  cookieNames=["SESSIONID"],
  successPattern="Welcome",
  confirm=true
)
```

Authentication profiles default to POST. GET-based credential submission is
blocked unless `allowCredentialInUrl=true` is provided after explicit operator
approval, because GET credentials can appear in URLs, logs, referrers, and tool
output.

Run the profile when the project authenticates for the first time or when a
cookie credential is believed to be expired:

```text
credentials.authenticate(profileId="main-login", confirm=true)
```

The authentication request sends active traffic and updates the referenced
cookie credential. Responses and evidence contain redacted credential metadata,
not cookie or password values.

For JavaScript-heavy, SSO, MFA, device-approval, or token-brokered flows, use a
browser authentication profile. Playwright is the local default provider;
Selenium Remote can be used for managed browser or grid environments:

```text
credentials.set_browser_auth_profile(
  id="main-sso",
  credentialId="browser-session",
  scopes=["app.example.com", "idp.example.com"],
  loginUrl="https://app.example.com/login",
  username="alice",
  password="<password>",
  manualCompletion=true,
  headless=false,
  successUrlPattern="/dashboard",
  protectedUrl="https://app.example.com/dashboard",
  cookieNames=["SESSIONID"],
  confirm=true
)
```

Run the browser profile after explicit approval. It starts as a background job
by default and stores a scoped `session` credential containing browser-derived
cookies and approved storage values:

```text
credentials.browser_auth_check_setup(provider="playwright", browser="chromium")
credentials.browser_authenticate(profileId="main-sso", confirm=true)
jobs.status(jobId="<returned-job-id>")
credentials.validate_session(
  credentialId="browser-session",
  target="https://app.example.com/dashboard",
  requestTimeout=45,
  confirm=true
)
```

Use explicit `steps` with `{{username}}`, `{{password}}`, and approved
`manualValues` placeholders for repeatable browser flows. For MFA or device
approval, keep `manualCompletion=true` and use headed mode so the operator can
complete the interactive step without secrets entering evidence.

Browser auth has three common operating modes:

- `manualCompletion=true`, `headless=false`: Synapse opens a real browser and
  waits for a success URL or selector while the operator completes SSO, MFA,
  CAPTCHA, smart-card, or device-approval steps.
- `steps=[...]`: Synapse executes a repeatable browser flow with actions such
  as `goto`, `fill`, `click`, `press`, `select`, `wait_for_url`, and
  `wait_for_selector`. Use placeholders for credentials and one-time values
  rather than hard-coding secrets in steps.
- `provider="selenium_remote"`: Synapse drives a remote WebDriver endpoint when
  the assessment requires a managed browser profile, enterprise certificate
  store, or Selenium Grid.

Browser-derived `session` credentials store cookies with domain/path metadata
and optional approved storage-token values. Synapse also stores safe browser
context headers (`User-Agent`, `Accept-Language`, and `Accept`) by default so
non-browser authenticated requests more closely match the Playwright session
that established the login. When a tool later receives `credentialId`, Synapse
resolves only the cookies that match that request target, which is important
for SSO flows spanning identity-provider and application hosts. If a SPA stores
bearer tokens in browser storage, configure `tokenStorageKeys` and optionally
`authorizationStorageKey` so Synapse can derive the intended `Authorization`
header from the captured browser state.

The default browser auth timeout is 1800 seconds and protected-resource
validation defaults to a 45 second request timeout. Increase
`authTimeoutSeconds` or `requestTimeout` for slow SSO, device approval, or
large protected landing pages.

Background browser auth writes worker argument files for restart-tolerant job
execution. Per-run args/result/state filenames include the profile ID and a
nonce so parallel same-target jobs keep separate attribution paths. Arguments are
sanitized before persistence and the args/state sidecars are written with
private file permissions where the platform supports it. Known secret-bearing
keys such as `password`, `secret`, and `token` are stripped from worker args; the
worker resolves reusable secrets from the protected credentials/profile store
through its state path. The browser-auth args file is removed during job
finalization, while the result and state files remain for debugging.

## Adaptive Nuclei Profiles

Nuclei is exposed through adaptive profiles rather than fixed commands:

- `low_noise`: conservative rates, higher signal severities, and context URLs
  that avoid state-changing endpoints.
- `medium`: balanced rates and broader common web, CVE, exposure, API, and
  GraphQL coverage.
- `pentest_aggressive`: broader severity/tag selection, higher throughput, and
  state-changing context URLs for explicitly approved testing.

Build a suggested command without sending traffic:

```text
nuclei.build_command(
  target="https://example.com/",
  workspaceId="<workspace>",
  profile="medium"
)
```

Run only after scope and approval:

```text
nuclei.run_profile(
  target="https://example.com/",
  workspaceId="<workspace>",
  profile="medium",
  approvalReason="Approved medium Nuclei validation",
  riskTier="medium",
  confirm=true
)
```

When workspace context exists, command generation uses it to choose relevant
target URLs and tags. Operators can override `targetUrls`, `tags`, `severity`,
`templates`, `workflows`, `vars`, `rateLimit`, `concurrency`, and `bulkSize`.
`requestTimeout` controls Nuclei's per-request timeout. `timeoutSeconds`
controls the outer Synapse process timeout and defaults to a profile-derived
budget based on target count and rate limit, so low-rate multi-target runs are
not killed prematurely. `nuclei.run_profile` starts a background job by default
and returns a `jobId` immediately. Poll completion with:

```text
jobs.status(jobId="<job-id>")
jobs.list(activeOnly=true, workspaceId="<workspace>")
```

Background job records are stored under the workspace data tree with stdout,
stderr, return-code, approval, tool metadata, and a fingerprinted creation-time
continuation plan. While the MCP process is
alive, a watchdog enforces the outer job timeout and terminates the job process
group when the budget is exceeded. Lazy finalization during `jobs.status`
ingests completed tool output and records the workspace action. If the MCP
process restarts and later observes that a job exceeded its timeout without a
recoverable process handle, the job is marked `timed_out` without terminating
an unknown process group.
Background job timeouts are clamped to a 30 second minimum and a 24 hour
maximum in the stored job record.

The shared HTTP client ignores `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`
(`trust_env=false`). Select `httpBackend="proxy"` plus an explicit `proxyUrl`
when a proxy is intended. Proxy endpoints are recorded separately from the
assessment target. Authenticated proxies use the internal
`proxyCredentialId` request field and a target-scoped credential reference;
userinfo in `proxyUrl` is rejected so secrets do not enter plans or evidence.
Proxy URLs are origin-only; path, query, and fragment components are rejected.
For migrated HTTP actions, redirects are followed only after each normalized
hop passes the frozen target envelope; cross-host redirects remain possible
when that envelope explicitly covers the destination.

The MCP stdio transport has its own recoverability deadlines for synchronous
`tools/call` requests: 45 seconds by default, 15 seconds for fast metadata
helpers, and 30 seconds for `jobs.status`. If one of these deadlines is hit,
the call returns a JSON-RPC timeout error and the server continues handling
subsequent requests. Tune the values in `config/synapse.env` with
`SYNAPSE_MCP_TOOL_TIMEOUT_SECONDS`, `SYNAPSE_MCP_FAST_TOOL_TIMEOUT_SECONDS`,
and `SYNAPSE_MCP_STATUS_TOOL_TIMEOUT_SECONDS`.

Tool calls run on a small thread pool (default 4 workers, override with
`SYNAPSE_MCP_TOOL_WORKERS`). The stdin loop is still single-flight, so this does
not run requests in parallel; its purpose is timeout recovery. A tool that
exceeds its deadline keeps running in its worker thread (Python cannot safely
kill it), so the spare workers keep one orphaned thread from starving later
recovery calls such as `jobs.status` and `jobs.cancel`. Workspace writes are
flock-guarded, JSON files are written with tmp+rename, and evidence events are
append-only, but the durable fix for long work remains the background-job model:
prefer the default `background=true` and poll with `jobs.status`.

When command-backed adapters are run with `background=false`, Synapse still
launches the subprocess in its own process group and terminates that process
group if the adapter timeout is exceeded.

Synchronous tools that send several HTTP requests are additionally bounded by a
total wall-clock budget so they cannot drift past the tool deadline (which would
orphan a worker). `js.fetch_assets` reuses one pooled HTTP client, defaults to
20 assets, and stops starting new requests after `totalBudgetSeconds` (default
30); skipped assets are reported in `errors` with `budgetExceeded=true`.
`access_control.execute_matrix_test` applies the same `totalBudgetSeconds`
budget across contexts, clamps each request timeout to the remaining budget
(each context still uses its own fresh client so cookies never leak between
authorization contexts), and reports `budgetExceeded` plus `skippedContexts`.
The looping injection probes (`ssti`, `ssi`, `lfi`) reuse a
pooled client across their benign payloads.

Pass `background=false` only for short, explicitly bounded runs that should
block until completion. Nuclei JSONL output is ingested as `nuclei_result`
observations and candidate findings when the run completes, including
background runs, and still requires operator review before reporting.

`ffuf.run_profile`, `nmap.run_profile`, and `crawler.crawl` also default to
background jobs and use the same `jobs.status(jobId=...)` polling path. Crawler
jobs run through an internal Python worker subprocess, preserve the same
scope/workspace/evidence paths, and finalize the worker result through
`jobs.status`.

## CVE Intelligence And Verification

The `cve` adapter turns fingerprinted technology components into candidate CVEs
and helps verify them under operator control. It never sends target traffic
during correlation and never fetches or executes public PoC code.

Typical flow:

1. Fingerprint the target so components carry versions and CPEs. Run
   `fingerprint.probe_versions` (confirm-gated, in-scope, bounded benign GETs)
first when components are version-imprecise.
   Version-unknown components produce a `cve_version_precision_gap` and skip
   broad NVD keyword lookup by default. Use `includeVersionUnknown=true` only
   for an explicitly broad run; uncorroborated product-only matches are still
   suppressed, regardless of CVSS.
2. `cve.correlate` (requires `confirm=true`) queries the enabled sources and
   records one `cve_candidate` observation per component/CVE. Discovery uses NVD
   and Shodan; enrichment adds CISA KEV (known-exploited), a public PoC index,
   and optionally GitHub search or local `searchsploit`. Each candidate carries
   an applicability `confidence` (from version precision) and an
   `exploitMaturity` (`in_the_wild` > `public_poc` > `exploit_referenced` >
   `none`). Only product/version/CPE/CVE identifiers leave the workspace.
3. `cve.plan_tests` and `cve.prepare_replay` produce a no-traffic verification
   plan and a benign replay request; PoC references are surfaced as read-only
   intelligence.
4. `cve.execute_test` (requires `confirm=true`, in-scope) sends one bounded
   benign request, or returns a `nuclei.build_command` delegation when a safe
   template exists. Promote to a finding only after review with
   `workspace.promote_observation_to_finding`.

Sources are selectable per call with `sources`, and their endpoints are
config-driven. When a source URL changes or fails, inspect
`cve.sources` (resolved endpoints plus last per-source status, including the URL
tried and HTTP status), re-point it with `cve.set_source_endpoint`, and re-run
`cve.correlate` with `refresh=true`. Provider responses are shared across
targets by source/endpoint/query hash under `DATA/cache/cve-intelligence/`;
each correlation still records target-local evidence. Source-and-credential-
tier token buckets coordinate all MCP processes. A 429 honors `Retry-After`,
uses bounded exponential backoff, and returns `status=rate_limited` with
attempt, retry, remaining-delay, cache-hit, and network-request state if the
bounded wait is exhausted. Re-run the same correlation to reuse completed
queries and continue at the first missing query. `providerMaxAttempts` and
`providerMaxWaitSeconds` bound one query; provider-safe budget defaults apply
unless the rate capacity/window overrides are deliberately configured. A
single failing or rate-limited source degrades to a recorded status and never
fails the run.
After a successful discovery-source refresh, Synapse retires prior unreviewed
CVE candidates that the evaluated source no longer returns. The rows remain in
workspace history but leave planning/report output; they revive automatically
if a later successful refresh returns them. A failed provider refresh does not
retire prior candidates.

Treat `versionApplicability` as package-range evidence, not as the final target
conclusion. `deploymentDisposition` evaluates NVD platform/configuration CPEs
and explicit advisory preconditions against independent workspace context. A
`contradicted` candidate is retained as a non-reportable refutation. An
`unknown` disposition remains a low-confidence candidate, emits a
`cve_prerequisite_gap`, and has `testable=false`. Use `cve.plan_tests` to review
the returned `controllingFacts`; `cve.prepare_replay` and `cve.execute_test`
remain blocked until those facts identify the reachable affected code path.
Adding later fingerprint or operator-reviewed deployment context updates the
same candidate and can make it testable without losing its history.

The PoC index environment default is assigned in `config/synapse.env` outside
shell `${VAR:-default}` expansion so the literal formatter braces survive as
`{year}/{cveId}.json`. Inspect `cve.sources` after startup: the source entry
shows `configuredEnabled`, effective `enabled`, and startup/current
`configuration` validation. A malformed template is disabled with
`configuration_error` before correlation traffic. Runtime endpoint overrides
are rejected unless they contain exactly `{year}` and `{cveId}` and interpolate
to an absolute HTTP(S) URL; only strict CVE identifiers can construct a path.

For correlation review, use top-level `sourceStatus` only for aggregate
provider health. Reproduce an individual candidate from its `sourceResults`:
each entry has a stable `sourceResultId`, normalized `queryHash`/`query`, exact
resolved `url`, `httpStatus`, cache state, and target-local `evidenceId`.
Candidate `evidenceIds` include those query snapshots. A candidate never copies
the run's last-request URL.

## Shodan Exposure Intelligence

Use `shodan.company_queries` to plan pivots without an API call, then obtain
approval for exact network-touching operations. `shodan.host`,
`shodan.internetdb`, `shodan.domain`, `shodan.search`, and
`shodan.target_summary` preserve a canonical compact model for ingestion even
when `raw=true` returns the provider response to the caller.

Search and target-summary ingestion distributes services to the discovered
hostname/IP rather than the query seed. The seed retains `asset_relation` and
DNS context so the operator can decide whether related assets belong in scope.
TLS, HTTP, module, CPE, provider CVE, and DNS metadata survive normalization.
Ordinary DNS resolution is recorded as `dns_resolution`; it is not treated as
an origin-IP leak without separate routing/CDN evidence.

## Scope And Cleanup

Inspect local dump artifacts before changing projects:

```text
cache.inspect_scope_data
```

Review `deleteCandidates` and `pruneCandidates`. Clean only after operator
approval:

```text
cache.clean_out_of_scope(confirm=true)
```

Unknown-host artifacts are kept and reported.

Generated sitemap, crawler, JS intelligence, and replaceable raw-evidence
artifacts default to latest-only retention for new runs. To inspect older
generated artifacts already on disk:

```text
cache.inspect_generated_artifacts(keep=1)
```

Review `outputCandidates` and `evidenceCandidates`, then clean only after
operator approval:

```text
cache.clean_generated_artifacts(keep=1, confirm=true)
```

This cleanup targets generated duplicates, not reviewed findings, credentials,
scope files, or manually supplied dumps.

Workspace deletion is separate from dump cache cleanup. Inspect the deletion
plan first, then delete only after operator approval:

```text
workspace.delete(workspaceId="client-workspace")
workspace.delete(workspaceId="client-workspace", confirm=true)
```

This permanently removes `DATA/workspaces/<workspace-id>/`. It does not remove
global evidence indexes under `DATA/evidence/orgs/`.

## Evidence Context

Use:

```text
workspace.prepare_target_context(workspaceId="<workspace>", target="example.com")
evidence.host_context(target="https://example.com")
fingerprint.analyze_workspace(workspaceId="<workspace>", target="example.com")
fingerprint.read_host(target="example.com", organization="<organization>")
```

Evidence events with host-bearing fields are indexed under the relevant host
folder when possible.

## Reporting

Render the default all-layers HTML report from stored workspace context:

```text
documentation.render_workspace_report(
  workspaceId="<workspace>",
  layers=["perimeter", "js", "auth", "access_control", "web_vulnerabilities", "cve", "engagement"],
  format="html",
  redactionMode="operator",
  outputPath="reports/workspace-report.html"
)
```

This report uses all seven normalized passive providers. Report generation reads existing
workspace entities, model artifacts, and evidence metadata; it does not fetch
JavaScript, authenticate, replay requests, crawl, scan, or send active traffic.
Each layer exposes the same report structure: summary values, sections,
per-target context, coverage gaps, and recommended next steps. Omit `layers`
to include the default set. HTML reports embed the repository Synapse banner
and shared report styling so the output is portable and visually consistent
with the project assets. Without `outputPath`, reports use
`reports/<workspace>/<artifact>.<ext>` so each workspace has one navigable
report directory.

For broad workspaces, keep the complete authorization scope and workspace state,
but process the audit through stable bounded groups:

```text
documentation.plan_scope_groups(
  workspaceId="<workspace>",
  targetBatchSize=20,
  groupCursor=0,
  groupLimit=5
)

documentation.prepare_validation_batch(
  workspaceId="<workspace>",
  groupId="scope-001",
  batchSize=20,
  cursor=0
)

documentation.render_workspace_report_batches(
  workspaceId="<workspace>",
  runId="review-2026-07-18",
  targetBatchSize=20,
  recordBatchSize=40,
  groupCursor=0,
  partCursor=0,
  maxParts=1,
  maxGroups=1
)
```

The scope-group manifest is stored at
`reports/<workspace>/scope-groups.json`. Existing target assignments remain
stable as the workspace grows; known `asset_relation` records keep related
assets together when the batch limit permits. Wildcard and CIDR authorization
rules are never silently expanded and appear as non-enumerable coverage gaps.
The MCP response is compact by default: it returns counts, five-target previews,
and a paginated group page rather than echoing the complete target/relation
inventory. Set `includeTargets=true` only for the requested group page; the full
auditable inventory remains in the manifest. An unchanged plan reuses that
snapshot until `refreshGroups=true` or scope membership changes.

Validation batching is passive planning only. It never sends traffic and does
not replace the exact scope check, action explanation, or explicit approval
required before an active test. Its cursor pages a deterministic, target-fair
candidate queue without deleting deferred candidates.

Batch rendering writes
`reports/<workspace>/<run>/manifest.json`, a self-contained `index.html`, and
`scope-NNN/part-NNN.html` plus JSON context siblings. `targetBatchSize` and
`recordBatchSize` accept 1–40; `maxGroups` defaults to one so a single call does
not regenerate the whole engagement. `maxParts` also defaults to one and caps
the number of record-bounded report files written by the call. When a group has
more records, resume it with the returned `nextGroupCursor` and
`nextPartCursor`; after its final part, `nextGroupCursor` advances and
`nextPartCursor` becomes null. Deferred group/part counts and per-part coverage
metadata prevent a partial report from appearing complete.

Use the public presentation names `operator` (detailed operational view),
`operator_raw` (detailed raw compatibility policy), or `high_level` (concise
internal view). Existing callers may continue to pass `internal` or `raw`; they
select the same underlying compatibility policies. Results return both the
user-facing `presentation` and underlying `redactionPolicy`, while built
contexts carry `redaction.presentation` and `redaction.mode`. `safe` is accepted
only as a deprecated compatibility input. These modes remain internal report
presentation/policy controls, not client-export security boundaries.

Render a single normalized layer report:

```text
documentation.render_layer_report(
  workspaceId="<workspace>",
  target="example.com",
  layer="js",
  format="html",
  redactionMode="operator",
  outputPath="reports/js-layer-example.html"
)
```

Valid layer names are `perimeter`, `js`, `auth`, `access_control`,
`web_vulnerabilities`, `cve`, and `engagement`. Use
`documentation.list_layers` to inspect available layers and
`documentation.build_layer_report_context` when you need JSON context before
rendering.

Render the default assessment summary report from stored workspace context:

```text
documentation.render_assessment_summary(
  workspaceId="<workspace>",
  assessmentType="Web Application Assessment"
)
```

The summary report groups general scope and finding counts, technologies per
host, actions performed, confirmed findings, pending observations, suggested
next steps, limitations, and an evidence index. Use
`documentation.render_markdown` with an explicit `template` when a different
built-in report format is required.

## Tests

Run:

```bash
bin/test
```

Focused modes:

```bash
bin/test --core
bin/test --template
bin/test --core -k access_control
bin/test --core -k phase3b_facade
bin/generate-action-inventory --check
```

The isolated modern SDK profile is installed and tested separately so the
stable installation has no MCP SDK dependency:

```bash
pip install -e '.[modern]'
bin/test-modern
```

The production suite covers both compact/direct surfaces and both official-SDK
supported wire eras over stdio and loopback Streamable HTTP, including complete
schemas, structured outcomes, authority spoofing denial, HTTP protocol and
security checks, durable resource isolation, rotating request state, restart
resume exactly once, and real subprocess startup. Use `synapse-mcp` to roll
back immediately to the stable legacy profile. The deprecated `modern-spike`
extra and `synapse-mcp-modern-spike` command only forward to the production
runtime. CI runs the full suite and contract subset on Python 3.10–3.13, then
runs the optional modern extra in a separate Python 3.13 job; every job asserts
that tests leave the checkout clean.

The helper sets `PYTHONDONTWRITEBYTECODE=1` and the correct `PYTHONPATH` values
for the core MCP suite and the custom adapter template tests. The current suite
covers adapter analysis, credential safety, workspace entity
ingestion/deduplication, workspace resources, JS intelligence
extraction/reporting, active-tool ingestion hooks, and MCP dispatch.
