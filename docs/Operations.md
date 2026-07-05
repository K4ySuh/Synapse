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
but the repository launcher is preferred for alpha use because it anchors
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
`DATA/workspaces/<workspace>/reports/js-app-map-<target>.html` or the matching
extension. Relative paths are workspace-relative; external absolute paths
require `allowExternalOutput=true`.

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

For completed crawl or recon jobs, the default review sequence is:

```text
jobs.list(activeOnly=true, workspaceId="<workspace>")
jobs.status(jobId="<job-id>")
fingerprint.analyze_workspace(workspaceId="<workspace>", target="example.com")
perimeter.build_summary(workspaceId="<workspace>", refresh=true)
perimeter.render_report(workspaceId="<workspace>", refresh=true, format="html")
```

Without an explicit `outputPath`, generated perimeter reports are written to
`DATA/workspaces/<workspace>/reports/perimeter.html` or
`DATA/workspaces/<workspace>/reports/perimeter.md`. If you provide a relative
path, keep it workspace-relative, for example `reports/perimeter.html`; do not
prefix it with `DATA/workspaces/...`.

Only after reviewing these outputs should the next plan suggest deeper
technology or version validation such as nmap service detection, Nuclei
technology templates, or targeted approved probes.

## Finding Lifecycle

Observations are hypotheses until an operator promotes or records them as
findings. Use:

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

These tools do not send traffic. They store `ssrf_candidate` and
`open_redirect_candidate` observations when ingestion is enabled. Command
injection analysis stores `command_injection_candidate` observations and reads
`fingerprint.json` when available to infer `unix`, `windows`, or `unknown`
payload syntax. Use the test plan helpers to prepare manual validation inputs
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
folder while also creating normal workspace observations. Use
`record_context` to map authorized user, role, and credential labels before
building the matrix. Matrix entries describe BOLA, BOPLA, and BFLA test ideas,
required contexts, risk tier, and missing information. Request replay is not
performed by the planner. To confirm a specific matrix entry, the operator must
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
If a replay context has no usable `credentialId` for the target, Synapse keeps
the replay active by sending that context as an unauthenticated request and
records the anonymous fallback in the replay context metadata.

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
and flags only, never values). `csrf` flags state-changing forms with no
recognized anti-CSRF token, cross-referenced with weak `SameSite` signals. `xxe`
and `insecure_deser` raise XML-parser and serialized-blob candidates.
`tls_posture` normalizes certificate and protocol issues from existing
Shodan/perimeter SSL data. `jwt.analyze` performs offline structural analysis of
an operator-supplied token and never echoes the token or any matched secret.

Two of these expose one bounded active probe each, gated by scope and
`confirm=true` after operator approval:

```text
cors.execute_test(workspaceId="<workspace>", candidate=<cors-candidate>, confirm=true, approvalReason="<approved Origin-reflection probe>")
graphql.execute_test(workspaceId="<workspace>", candidate=<graphql-candidate>, confirm=true, approvalReason="<approved introspection probe>")
```

`cors.execute_test` sends one Origin-reflection request and only records
`possible_cors_misconfiguration` when the supplied origin is reflected.
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
stderr, return-code, approval, and tool metadata. While the MCP process is
alive, a watchdog enforces the outer job timeout and terminates the job process
group when the budget is exceeded. Lazy finalization during `jobs.status`
ingests completed tool output and records the workspace action. If the MCP
process restarts and later observes that a job exceeded its timeout without a
recoverable process handle, the job is marked `timed_out` without terminating
an unknown process group.
Background job timeouts are clamped to a 30 second minimum and a 24 hour
maximum in the stored job record.

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
`cve.correlate` with `refresh=true`. A single failing or rate-limited source
degrades to a recorded status and never fails the run.

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
  layers=["perimeter", "js", "auth", "access_control"],
  format="html",
  outputPath="reports/workspace-report.html"
)
```

This report uses normalized passive providers for perimeter, JavaScript,
authentication, and access-control layers. Report generation reads existing
workspace entities, model artifacts, and evidence metadata; it does not fetch
JavaScript, authenticate, replay requests, crawl, scan, or send active traffic.
Each layer exposes the same report structure: summary values, sections,
per-target context, coverage gaps, and recommended next steps. Omit `layers`
to include the default set. HTML reports embed the repository Synapse banner
and shared report styling so the output is portable and visually consistent
with the project assets.

Render a single normalized layer report:

```text
documentation.render_layer_report(
  workspaceId="<workspace>",
  target="example.com",
  layer="js",
  format="html",
  outputPath="reports/js-layer-example.html"
)
```

Valid layer names are `perimeter`, `js`, `auth`, and `access_control`. Use
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
```

The helper sets `PYTHONDONTWRITEBYTECODE=1` and the correct `PYTHONPATH` values
for the core MCP suite and the custom adapter template tests. The current suite
covers adapter analysis, credential safety, workspace entity
ingestion/deduplication, workspace resources, JS intelligence
extraction/reporting, active-tool ingestion hooks, and MCP dispatch.
