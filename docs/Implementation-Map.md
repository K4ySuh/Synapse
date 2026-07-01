# Synapse Implementation Map

This map reflects the current repository implementation: a workspace-first MCP
knowledge layer with guarded adapters, durable background jobs, passive
fingerprinting, and perimeter reporting.

## Runtime Topology

```text
MCP client
|-- optional stdio: burp
|   `-- MCPS/Burp-Mcp/bin/portswigger-burp-mcp
|       `-- java -jar mcp-proxy.jar --sse-url $MCP_SSE_URL
|           `-- PortSwigger Burp MCP extension
|
`-- stdio: synapse
    `-- MCPS/Synapse-MCP/bin/synapse-mcp
        `-- $SYNAPSE_PYTHON -m synapse_mcp.transport.stdio_server
            |-- resources and prompt
            |-- workspace and core state modules
            `-- guarded analysis and recon adapters
```

Burp stays as the optional live application-state boundary. Synapse owns local
policy, scope, workspace knowledge, evidence, dump analysis, credentials, and
guarded wrappers for non-Burp tools, and can operate without the Burp MCP when
live Burp Suite operations are not needed.

## Launch And Configuration

Both launchers set `SYNAPSE_ROOT`, source `config/synapse.env`, then start their
server process. The Synapse MCP launcher uses `SYNAPSE_PYTHON` when set,
otherwise it prefers the active console `VIRTUAL_ENV`, then
`$SYNAPSE_ROOT/.venv/bin/python`, and falls back to `python3`.

```text
config/synapse.env
|-- MCP_SSE_URL              optional Burp MCP extension URL
|-- BURP_MCP_PROXY_JAR       optional PortSwigger proxy jar path
|-- SQLMAP_BIN               sqlmap executable for command generation
|-- FFUF_BIN                 ffuf executable
|-- NMAP_BIN                 nmap executable
|-- NUCLEI_BIN               nuclei executable
|-- SYNAPSE_MCP_TOOL_TIMEOUT_SECONDS        default MCP tools/call deadline
|-- SYNAPSE_MCP_FAST_TOOL_TIMEOUT_SECONDS   fast metadata tools/call deadline
|-- SYNAPSE_MCP_STATUS_TOOL_TIMEOUT_SECONDS jobs.status/finalizer deadline
|-- SYNAPSE_MCP_TOOL_WORKERS                tool executor worker count (default 4, for timeout recovery)
|-- SYNAPSE_PYTHON           defaults to active VIRTUAL_ENV, then $SYNAPSE_ROOT/.venv/bin/python
|-- SYNAPSE_PROMPT_PATH      defaults to $SYNAPSE_ROOT/AGENTS.md
|-- SYNAPSE_DATA_DIR         defaults to $SYNAPSE_ROOT/DATA
`-- SYNAPSE_DUMP_DIR         defaults to $SYNAPSE_DATA_DIR/workspaces
```

Relative Synapse path values are anchored to these configured roots, not the
current launch directory. `SYNAPSE_DATA_DIR` must resolve under `SYNAPSE_ROOT`,
and `SYNAPSE_DUMP_DIR` must resolve under `SYNAPSE_DATA_DIR`, so normal
operations do not create stray runtime `DATA/` trees from an MCP client's
working directory.

`bin/check-setup` validates required Synapse prerequisites, confirms the
Synapse MCP starts, reports optional Burp MCP readiness as warnings, and prints
client config. `bin/print-mcp-config` prints config without running the checks;
it emits an enabled Burp block only when the optional launcher is present.

## Data Layout

```text
AGENTS.md                         shared AI-client and MCP prompt

DATA/
|-- scope/scope.json              global authorized hosts, patterns, CIDRs, and notes
|-- workspaces/<workspace-id>/    normalized engagement/target knowledge
|   |-- workspace.json
|   |-- scope.json                workspace-owned hosts, patterns, and CIDRs
|   |-- jobs/<job-id>/job.json    background job records (sidecars embedded on finalization)
|   |-- reports/                  generated perimeter, layer, workspace, and app-map reports
|   |-- outputs/                  workspace-level generated outputs
|   `-- targets/<host>/
|       |-- target.json
|       |-- entities/
|       |   |-- services.json
|       |   |-- endpoints.json
|       |   |-- parameters.json
|       |   |-- findings.json
|       |   |-- actions.json
|       |   `-- observations.json
|       |-- models/
|       |   |-- perimeter.json
|       |   `-- access-control/
|       |-- outputs/<tool>/
|       `-- evidence/
|           |-- <evidence-id>*
|           |-- findings.md
|           |-- burp-dumps/<dump>/
|-- credentials/credentials.json  scoped HTTP credentials, chmod 0600 when possible
|-- evidence/events.jsonl         global evidence event log
|-- evidence/orgs/<org>/hosts/<host>/
|   |-- metadata.json
|   |-- events.jsonl
|   `-- fingerprint.json
```

Runtime data is local file-backed state. Only `.gitkeep` placeholders should be
committed from `DATA/`.

## Representative Entity Schemas

These are representative shapes for the current workspace model. Exact MCP
input schemas are defined in `transport/stdio_server.py`.

### Scope Status

`workspace.ingest_data` does not block passive or offline data when scope is
missing or does not match, but it makes the status explicit.

```json
{
  "scopeStatus": "in_scope",
  "scopeReason": "Matched host scope entry app.example.com."
}
```

Allowed values: `in_scope`, `out_of_scope`, `scope_unset`.

### Workspace Target Context

```json
{
  "workspaceId": "client-web-2026",
  "target": "app.example.com",
  "scopeStatus": "in_scope",
  "scopeReason": "Matched host scope entry app.example.com.",
  "knownServices": [],
  "knownEndpoints": {
    "total": 12,
    "interesting": []
  },
  "interestingEndpoints": [],
  "authSurface": [],
  "stateChangingCandidates": [],
  "inputParameters": [],
  "candidateFindings": [],
  "confirmedFindings": [],
  "observations": [],
  "recentActions": [],
  "recommendedNextSteps": [],
  "missingInformation": []
}
```

### Evidence Event

Evidence events are JSONL records. Common secret-bearing fields are sanitized
before writing.

```json
{
  "createdAt": "2026-05-28T20:00:00Z",
  "type": "workspace.ingest",
  "summary": "Ingested sitemap data for app.example.com.",
  "data": {
    "workspaceId": "client-web-2026",
    "target": "app.example.com",
    "source": "sitemap",
    "scopeStatus": "in_scope",
    "evidenceId": "ev_20260528-200000_123456_sitemap",
    "rawPath": "DATA/workspaces/client-web-2026/targets/app.example.com/evidence/ev_..._raw.json",
    "entitiesCreated": {
      "services": 0,
      "endpoints": 8,
      "parameters": 15,
      "findings": 0,
      "actions": 0,
      "observations": 6
    }
  }
}
```

### Finding

```json
{
  "id": "finding-20260528-200000-123456-exposed-admin",
  "type": "finding",
  "title": "Exposed administrative route",
  "status": "candidate",
  "severity": "medium",
  "confidence": "low",
  "affectedAssets": ["app.example.com"],
  "evidenceIds": ["ev_20260528-200000_123456_sitemap"],
  "missingEvidenceIds": [],
  "reproductionSteps": ["Review GET /admin in the captured traffic."],
  "impact": "",
  "remediation": "",
  "operatorReviewed": false,
  "createdAt": "2026-05-28T20:00:00Z",
  "updatedAt": "2026-05-28T20:00:00Z"
}
```

Finding statuses: `candidate`, `confirmed`, `false_positive`, `accepted_risk`,
`fixed`.

### Active Approval Metadata

Active adapters record consistent approval metadata:

```json
{
  "approval": {
    "confirm": true,
    "operatorApproved": true,
    "approved": true,
    "approvalId": "approval-123",
    "approvalReason": "Run low-noise discovery against app.example.com.",
    "riskTier": "low"
  }
}
```

### Passive Burp-Derived Endpoint

`sitemap.from_dump` stores request/response context without replaying traffic
or storing secret values.

```json
{
  "type": "endpoint",
  "url": "https://app.example.com/api/graphql?debug=true",
  "method": "POST",
  "path": "/api/graphql",
  "queryParameters": ["debug"],
  "bodyParameters": [],
  "jsonParameters": ["operationName", "query", "variables.id"],
  "cookieNames": ["SESSIONID"],
  "authorizationSchemes": ["Bearer"],
  "requestContentTypes": ["application/json"],
  "statusCodes": [500],
  "contentTypes": ["application/json"],
  "redirectLocations": [],
  "apiRoute": true,
  "jsonEndpoint": true,
  "graphqlEndpoint": true,
  "stateChanging": true,
  "authBoundary": false,
  "errorSignals": ["http_500", "traceback"]
}
```

### Workspace Technology Component

`fingerprint.analyze_workspace` and `perimeter.analyze_workspace` use
structured technology components instead of raw protocol names. Protocol-only
service names such as `http` and `https` are not promoted to technology
components unless a product or stronger fingerprinting signal is present.

```json
{
  "type": "technology_component",
  "name": "nginx",
  "version": "1.22.1",
  "layer": "web_server",
  "confidence": "high",
  "source": "service",
  "reasons": ["Service metadata observed on port 443: nginx 1.22.1"],
  "evidenceIds": ["ev_20260603-120000_123456_nmap"]
}
```

### Canonical Login Portal

The perimeter model groups workflow/query variants into one portal record and
keeps protected resources separate from real login entrypoints.

```json
{
  "type": "login_portal",
  "representativeUrl": "https://app.example.com/portal/Login",
  "provider": "Unknown",
  "method": "GET",
  "variantCount": 4,
  "sampleUrls": [
    "https://app.example.com/portal/Login?PAGE_CODE=HOME&lang=es"
  ],
  "confidence": "high",
  "reasons": ["Form/input names suggest authentication."]
}
```

## Synapse MCP Dispatch

`synapse_mcp.transport.stdio_server` implements the MCP JSON-RPC boundary.

```text
initialize              advertises tools, resources, prompts, logging
tools/list              returns tool schemas
tools/call              dispatches into core modules and adapters
resources/list          exposes local state resources
resources/read          reads state resources and AGENTS.md
prompts/list            exposes synapse-main
prompts/get             returns AGENTS.md as a user prompt message
```

Exposed resources:

- `synapse://dumps`
- `synapse://scope`
- `synapse://credentials`
- `synapse://evidence/recent`
- `synapse://jobs/active`
- `synapse://workspaces`
- `synapse://prompt/main`

Dynamic workspace resources are also readable:

- `synapse://workspace/{workspace_id}`
- `synapse://workspace/{workspace_id}/targets`
- `synapse://workspace/{workspace_id}/target/{target}/summary`
- `synapse://workspace/{workspace_id}/target/{target}/services`
- `synapse://workspace/{workspace_id}/target/{target}/endpoints`
- `synapse://workspace/{workspace_id}/target/{target}/parameters`
- `synapse://workspace/{workspace_id}/target/{target}/findings`
- `synapse://workspace/{workspace_id}/target/{target}/actions`
- `synapse://workspace/{workspace_id}/target/{target}/observations`

Exposed prompt:

- `synapse-main`

## Core Modules

```text
core/paths.py
```

Resolves repository-local paths from environment variables:
`SYNAPSE_ROOT`, `SYNAPSE_DATA_DIR`, `SYNAPSE_DUMP_DIR`, and
`SYNAPSE_PROMPT_PATH`. Relative runtime paths resolve from the relevant
configured root rather than from the process working directory.

```text
core/background_jobs.py
```

Persists generic Synapse background job records under
`DATA/workspaces/<workspace-id>/jobs/` when a workspace is known. Job directory
names include timestamp, tool, target, and a short unique suffix so local
runtime state is easier to identify. The layer starts command-backed jobs with
stdout, stderr, return-code, process group, approval, target, workspace, and
tool metadata, clamps job timeouts to 30 seconds through 24 hours, runs an
in-process watchdog that terminates over-budget job process groups while the
MCP process is alive, supports lazy status finalization after process
completion, and exposes
list/status/cancel helpers. `jobs.list` can filter by `workspaceId`, and
active-only listing avoids finalizing already-terminal records while counting
running work. During execution it uses temporary `stdout.txt`, `stderr.txt`,
and `returncode.txt` sidecars; once a terminal job is finalized, their contents
are embedded in `job.json` and the sidecars are removed so the job directory
retains only the JSON record. Adapters register named finalizers so completed
jobs can ingest output and record workspace actions even after the MCP server
restarts. Worker result files are written atomically, and finalizers report
missing or corrupt worker result files as explicit error payloads. Worker result
paths are adapter-provided, so callers that support parallel same-target jobs
must keep their artifact names per-run.
If a restarted MCP process no longer has the original `Popen` handle for a
timed-out job, status refresh marks the job `timed_out` without sending signals
to a PID/process group it does not own.

```text
transport/stdio_server.py
```

Dispatches JSON-RPC requests for tools, resources, and prompts. `tools/call`
validates required arguments and simple declared JSON types before dispatch,
while leaving adapter-owned approval gates such as `confirm=true` to the
adapter. Malformed JSON lines return JSON-RPC parse errors. Tool execution uses
a small executor deadline wrapper so slow synchronous operations return a
structured `-32003` timeout error and the stdio loop can continue processing
later requests. The abandoned worker thread is left to finish; atomic state
writes prevent late completion from corrupting JSON files. The deadline layer
is a safety net; long-running adapters should still use `jobs.*` by default.

```text
core/scope.py
```

Stores the global authorized hosts, patterns, CIDRs, and notes in
`DATA/scope/scope.json`. Hosts are normalized from hostnames or URLs.
`check_target` returns the normalized host, whether it is in scope, matching
metadata, and the current scope payload. Active adapter guards can also check a
workspace's own `scope.json`; that workspace snapshot is authoritative when it
exists, with the global scope used only as fallback. Scope updates are logged as
evidence events.

```text
core/evidence.py
```

Writes operator-reviewed events to the global JSONL log and indexes
host-bearing events into organization/host folders. It also creates project and
host evidence directories and reads recent host context. Event data is sanitized
before writing so common secret fields such as authorization, cookie, token,
password, API key, and session values are replaced with `[REDACTED]`. Strings
shorter than the bounded scrub limit are also scanned for common secret-bearing
patterns such as Authorization, Cookie, Set-Cookie, Bearer tokens, and
password/passwd form or query fields. `evidence.tail` reads recent JSONL
entries from the end of the file so long engagement logs do not require
full-file reads.

```text
core/credentials.py
```

Stores scoped HTTP credentials locally. Supported types are `bearer`, `basic`,
`cookie`, custom `header`, and browser-derived `session`. Credential scopes
must already be authorized. List/get responses redact secrets; active HTTP tools
can request real headers internally with `credentialId`. Authentication profiles
describe an approved HTTP login flow and can refresh a cookie credential through
`credentials.authenticate`. Browser authentication profiles can run Playwright
or Selenium Remote flows through a background worker and refresh a target-aware
session credential with matching cookies, configured storage tokens, and safe
browser context headers for later `credentialId` use. POST is the default HTTP
authentication method; GET
credential submission requires `allowCredentialInUrl=true`. Header credentials
validate HTTP token header names and reject CR/LF in names or values. Browser
session cookie generation excludes cookies with empty or unknown domains.
Credential redaction fully masks secrets shorter than 20 characters and only
shows first/last four characters for longer values. Browser-auth worker
args/state/result files include the profile ID and a per-run nonce, are written
with private permissions where supported, strip known inline secret keys from
worker args, and remove the browser-auth args file during job finalization.

```text
core/dumps.py
```

Finds Burp-style dump directories under workspace evidence folders and loads
`history.jsonl` entries. A dump may be passed as the directory itself or the
history file path.

```text
core/cache.py
```

Compares local dump artifacts against current scope. Inspection is read-only.
Cleanup requires confirmation and removes only artifacts whose parsed hosts are
outside current scope; mixed or unknown-host artifacts are preserved or pruned
conservatively. Also exposes generated-artifact inspection and cleanup for
duplicate timestamped outputs plus replaceable raw evidence from sitemap,
crawler, and JS intelligence sources.

```text
core/fingerprint.py
```

Summarizes observed host behavior from two passive sources. `from_dump`
preserves the original dump-only path for traffic-derived technologies, headers,
auth hints, cookie names and flags, endpoint classes, response patterns,
possible OS family hints, and representative request lines. `analyze_workspace`
reads normalized workspace services, endpoints, response headers, response
cookie names, body-derived technology signals, and observations to produce
structured technology components with separate `name`, `version`, `layer`,
`confidence`, and evidence fields. Protocol-only service names such as `http`
and `https` are ignored unless a real product signal exists. Both paths save
`fingerprint.json` per organization/host; workspace analysis can also ingest
`technology_component` observations and refresh perimeter state.

```text
core/workspace.py
```

Stores engagement workspaces under `DATA/workspaces/`, with per-target raw
evidence and normalized entity files. `workspace.ingest_data` stores raw data,
parses supported sources, normalizes and deduplicates services, endpoints,
parameters, findings, actions, and observations, logs an evidence event, and
returns a compact `llmSummary` plus explicit `scopeStatus`/`scopeReason`
values. Entity normalization runs in two phases. Phase 1 is context-free
structural normalization at the parser/adapter boundary
(`_normalize_entity_structure`): canonical `type`, list-shaped list fields, and
finding/action id-to-key mirroring. Phase 2 is workspace-aware normalization
inside ingestion (`_normalize_entity_for_workspace`): created/updated
timestamps, default `affectedAssets`, `missingEvidenceIds` validation against
stored evidence, severity/status/confidence enum enforcement, and guaranteed
stable `key`/`id` values for findings and actions. Deduplication keys are
derived from stable content fields only (`key`, then ids, then content
discriminators) and never include mutable fields such as `evidenceIds`; parsers
that emit findings, such as the Nuclei parser, set content-derived keys so
re-ingesting the same result merges instead of duplicating. Merging unions
list-valued fields such as `evidenceIds`, `statusCodes`, `cookieNames`, and
`tags`, refreshes `updatedAt`/`lastSeenAt`, and escalates finding severity
upward unless the finding is operator-reviewed. Current
parsers cover ffuf JSON, Nuclei JSONL, Synapse site map JSON, crawler JSON,
nmap XML, Shodan, workspace-native adapter results, SSRF/open-redirect/
command-injection/SSTI/LFI/SSI/access-control analysis output, and operator
notes.
`workspace.prepare_target_context` returns a target planning summary without
loading raw evidence, including known services, interesting endpoints, auth
surface, state-changing candidates, input parameters, candidate/confirmed
findings, recent actions, recommended next steps, and missing information.
Finding lifecycle helpers create, update, promote, link evidence, mark reviewed,
and export finding context.

```text
core/documentation/
```

Documentation context and rendering layer. `models.py` defines report, finding
draft, evidence pack, coverage, normalized layer report, workspace report,
template, render-result, and redaction-policy models.
`builder.py` turns normalized workspace entities, action records, and evidence
metadata into structured contexts. `redaction.py` applies safe/internal/raw
policy controls with safe defaults that omit raw HTTP, request/response bodies,
and credentials. `templates.py` registers built-in Markdown templates, and
`html_templates/` stores standalone HTML report templates and mockups.
`renderer.py` renders deterministic Markdown for reports, assessment summaries,
findings, evidence packs, and coverage summaries. `layers.py` provides the
standard passive report-provider abstraction for perimeter, JavaScript,
authentication, and access-control layers. Each provider reads existing
workspace entities and model artifacts, then returns the same normalized shape:
summary values, sections, per-target context, evidence ids, gaps, and
recommended next steps. `layer_renderer.py` renders those normalized layer
contexts and all-layer workspace contexts as HTML or Markdown with shared table
and expandable tree helpers. `exporters.py` writes JSON, Markdown, or HTML
report exports under the workspace root `reports/` directory by default,
rejects repo-root-looking relative paths such as `DATA/workspaces/...`, and
requires `allowExternalOutput=true` for external paths.

The documentation layer consumes adapter output through the workspace model.
Adapters should not write report sections directly.

```text
core/js/
```

Static JavaScript intelligence primitives. `models.py` defines JS assets,
endpoint candidates, parameter candidates, static signals, and analysis result
shapes. `extractors.py` performs bounded regular-expression/static extraction
for client-side API endpoints, HTTP methods, API bases, GraphQL operations,
WebSocket URLs, browser storage keys, auth/CSRF header names, and object
identifier names. It does not execute JavaScript. `normalizer.py` converts
extracted candidates into workspace endpoint, parameter, and observation
entities with `source = "js_intelligence"`, `sourceAsset`, confidence, and
derived/inferred markers.

```text
core/perimeter.py
```

Passive external-perimeter inventory and reporting layer. It reads normalized
workspace services, endpoints, observations, findings, and actions; classifies
host assets, web applications, technology components by layer, canonical login
portals, protected resources, perimeter observations, and review candidates;
writes per-target `models/perimeter.json` plus workspace `perimeter-summary.json`; and
renders Markdown or HTML tables under the workspace root `reports/` directory
by default. Login portal grouping uses scheme, host,
normalized path, provider/form signature, and ignores common workflow/query
variants such as `PAGE_CODE`, `APP_CODE`, `lang`, `returnUrl`, `next`,
`continue`, and `RelayState`. It filters weak 404 auth-looking paths and keeps
resources that merely route through authentication as `protected_resource`.
Technology tables show name, version, confidence, source, and host coverage.
Login portal and candidate review tables include request-level context such as
representative URL, method, status, input/parameter names, variant/sample URLs,
candidate category, occurrence count, and the reason the item was flagged.
It does not send traffic.

```text
core/adapters/
```

Defines the formal Synapse adapter framework. `models.py` provides
`AdapterMetadata` with category, capability, safety, risk, output, limitation,
execution-mode, and reference fields. `base.py` provides the `SynapseAdapter` interface and a
controlled unsupported-method exception for adapters that do not implement a
given operation. `registry.py` keeps the application-level adapter registry and
registers built-in metadata for web, network, and OSINT adapters. `results.py`
defines the workspace-native adapter output contract: `AdapterResult`,
`WorkspaceEntityBundle`, typed service/endpoint/parameter/observation/finding/
action models, evidence references, recommended tests, and helper constructors
for candidate observations.

Adapter results intentionally mirror the persisted workspace entity files. A
new adapter can return a JSON result with an `entities` bundle and ingest it
through `workspace.ingest_data` using `source=adapter_result`; no source-specific
parser is required unless the adapter consumes an external tool format.

```text
examples/custom_adapter_template/
```

Runnable template for organization-specific adapters. It demonstrates metadata
declaration, a `SynapseAdapter` subclass, workspace-native `AdapterResult`
output, candidate observation creation, optional ingestion through
`workspace.ingest_data(source=adapter_result)`, explicit execution-mode
metadata, local registry registration, and
unit tests. The example adapter is passive and does not send traffic.

## Adapter Modules

The MCP server exposes `adapters.list` and `adapters.capabilities` so operators
can inspect registered adapter behavior, traffic impact, confirmation
requirements, and output expectations before running any tool.

The MCP server exposes `documentation.*` tools for template/layer discovery,
structured context building, coverage summaries, Markdown rendering, normalized
layer HTML reports, all-layer workspace HTML reports, default
assessment-summary rendering, and JSON context export. These tools do not send
network traffic.

The MCP server exposes `perimeter.*` tools for passive external-perimeter
classification and Markdown/HTML perimeter reporting from stored workspace
data. These tools do not send network traffic.

The MCP server exposes `js.*` tools for JavaScript asset discovery, approved
bounded asset fetching, static analysis, inferred endpoint normalization,
compact app-model summaries, and sitemap-style app-map reports. Only
`js.fetch_assets` sends traffic; the other JS tools operate on stored workspace
data and local JS asset files.

### Registered Adapters

`adapters.list` returns metadata for every registered adapter (registry name,
category, traffic impact, confirmation requirement, risk tier, and execution
mode). The current registered set, by registry name, is:

- `spec_import`
- `sitemap`
- `crawler`
- `ffuf`
- `nuclei`
- `sqli`
- `xss`
- `headers_cookies`
- `jwt`
- `csrf`
- `cors`
- `insecure_deser`
- `xxe`
- `graphql`
- `tls_posture`
- `ssrf`
- `open_redirect`
- `command_injection`
- `ssti`
- `lfi`
- `ssi`
- `access_control`
- `js_intelligence`
- `nmap`
- `shodan`

This list is kept in sync with `core/adapters/registry.py` by
`tests/test_tool_wrappers.py::ToolWrapperTests::test_implementation_map_documents_every_registered_adapter`.

### Adapter Implementation Notes

```text
adapters/command_utils.py
```

Shared guard helpers for active tools. It enforces `confirm=true`, checks scope,
executes commands with timeouts, captures truncated stdout/stderr, and logs
evidence events. When a `workspaceId` is supplied, active scope checks use the
workspace's own persisted scope before falling back to global scope. Tool
adapters write default outputs under the relevant workspace target evidence
folder and append execution records to `actions.json`.
Approval metadata uses a consistent `confirm`, `operatorApproved`,
`approvalId`, `approvalReason`, and `riskTier` structure. External output paths
require `allowExternalOutput=true`.

```text
adapters/web/sqlmap_analysis.py
adapters/web/sqlmap_adapter.py
```

Passive SQL injection triage over offline dumps. It parses HTTP requests,
extracts candidates from query strings, form bodies, JSON/XML scalar values,
cookies, selected headers, and path segments, scores them, and generates
validated sqlmap command suggestions. It blocks sqlmap options that enable OS
shell, file, registry, privilege-escalation, or direct exploitation features.
Synapse does not expose sqlmap execution. When `workspaceId`, `target`, and
`ingest=true` are provided, candidates are stored as `sqli_candidate`
observations through the adapter result model.

```text
adapters/web/xss_analysis.py
adapters/web/xss_adapter.py
```

Passive XSS triage over offline dumps. It parses requests and responses, checks
headers and content types, finds request sources, response sinks, reflections,
and likely browser contexts, and can generate manual payload/helper code.
`xss.execute_test` requires `confirm=true`, scope, and approval metadata, sends
allowlisted benign marker/tag reflection probes, records redacted request
headers plus HTTP exchange evidence, and does not execute browser JavaScript.
Optional workspace ingestion stores `xss_candidate`, `xss_reflection`, and
`xss_sink` observations through the adapter result model.

```text
adapters/web/crawler_adapter.py
```

Builds Burp-like site maps either passively from dumps or actively with a
bounded crawler. Passive mode reads dump requests/responses and extracts URLs,
links, forms, titles, request methods, path/query/body/JSON/cookie parameter
names, Authorization schemes, status codes, content types, redirects,
JSON/GraphQL/API-like endpoint signals, interesting error signals,
authentication boundaries, and state-changing methods. It records cookie names
and auth schemes, not secret values. Active mode requires `confirm=true`,
persisted target scope, max page/depth limits, request timeout, optional delay,
and optional `credentialId`. Active crawl requests go through `core/http`,
follow only persisted in-scope links and redirects, extract script route
literals by default, and support the same direct/proxy/disabled backend policy.
Active crawl output is ingested into the workspace layer per discovered host and
recorded in `actions.json` automatically; passive site maps are ingested and
recorded when `workspaceId` is supplied. Crawler endpoint records preserve
bounded fingerprinting signals such as selected response headers, response
cookie names, generator hints, script/CSS paths, and common app markers without
storing full bodies in workspace entities. Active crawling also follows click-like
navigation attributes, meta refresh targets, and bounded GET form submissions.
POST forms are recorded as workflow context by `crawler.crawl` but not
submitted. `crawler.extended` is the authenticated follow-up mode: it requires a
previous `crawler.crawl` action, scoped `credentialId`, and `confirm=true`, then
submits non-sensitive POST forms with generated test values, parses the
responses for more map context, and records every POST attempt in evidence and
target `actions.json`. Obvious admin, deletion, password, upload, import/export,
billing, role, or permission forms are skipped unless
`includeSensitivePostForms=true`.
Both passive and active outputs include `flowGraph`, a structured graph of host,
endpoint, and form nodes with request, navigation, redirect, and form-action
edges. The graph records HTTP methods, status codes, parameter names, and
submitted-versus-discovered state. `write_sitemap` emits sibling Mermaid
`.flow.mmd` and SVG `.flow.svg` files whose paths are returned as
`flowGraph.mermaidPath` and `flowGraph.svgPath`. Active crawl runs default to an
internal Python worker subprocess with the same state paths and return a
generic `jobId` for `jobs.status`. Blocking crawls refresh workspace
fingerprinting and perimeter summaries directly; background crawls defer that
refresh to `jobs.status` finalization after sitemap ingestion.

```text
adapters/web/js_intel.py
```

JavaScript workspace enrichment adapter. `js.discover_assets` passively finds
JavaScript asset URLs from stored sitemap/crawler/workspace data.
`js.fetch_assets` requires approval and scope, uses `core/http`
direct/proxy/disabled backend policy, and stores bounded JS assets under the
target `outputs/js-intelligence/` tree. `js.analyze_static` reads
stored JS files without executing them and writes static-analysis JSON. It runs
as a venv-aware background worker by default, with a default cap of 3 concurrent
JS analysis/normalization jobs and optional `normalizeAfter=true` chaining.
Manifest-relative `localPath` values are resolved relative to the manifest
before falling back to `SYNAPSE_ROOT`. `js.normalize_endpoints` ingests
JS-derived endpoints, parameters, and observations through the existing
workspace adapter-result path while keeping inferred endpoints distinct from
observed endpoints; it also runs as a background worker by default.
`js.build_app_model`
returns a compact agent/operator summary. `js.render_app_map` writes HTML,
Markdown, or JSON reports under the workspace `reports/` directory by default,
combining observed requests and JS-inferred requests in a sitemap-style tree
with source assets, parameters, confidence, and JS signals.

```text
adapters/web/ffuf_adapter.py
```

Builds and optionally runs constrained ffuf profiles. Command building requires
target scope and a local wordlist. Running requires `confirm=true`. Supported
profiles are:

- `low_noise`
- `medium`
- `pentest_aggressive`

Credential-backed headers are used only in the private execution command and
are redacted in returned commands. Successful JSON output is ingested into the
workspace layer and summarized when the run produces an output file.
Runs default to a generic Synapse background job and return a `jobId` for
`jobs.status`; pass `background=false` only for explicit blocking execution.

```text
adapters/web/nuclei_adapter.py
```

Builds and optionally runs adaptive Nuclei profiles. Profile selection supplies
policy defaults instead of fixed commands: `low_noise`, `medium`, and
`pentest_aggressive` control default severity, tags, rate limits, concurrency,
bulk size, per-request timeout, process-timeout budget, and how much workspace
context influences targets. Command
generation uses normalized workspace context when available to include relevant
URLs and tags such as API, GraphQL, auth-panel, exposure, and misconfiguration
signals. Operators can override target URLs, tags, severity, templates,
workflows, variables, rate controls, and the outer process timeout. Running
requires `confirm=true`, writes JSONL output under target evidence, records
`actions.json`, and ingests matches as `nuclei_result` observations plus
candidate findings. Timeout metadata is recorded explicitly, including
`timeoutSeconds` and `timedOut`. Runs use the generic background job layer by
default; pass `background=false` only for explicit blocking execution.

```text
adapters/web/ssrf_adapter.py
adapters/web/open_redirect_adapter.py
```

Workspace analyzers and bounded active validators for web vulnerability
candidates. SSRF analysis scores URL-like parameters, callback/webhook/import/
proxy paths, and high-value forms. `ssrf.execute_test` requires an
operator-controlled external callback URL, rejects localhost/private/metadata
callback targets, sends one approved canary payload, and records that
out-of-band verification is still required before confirmation. Open redirect
analysis scores redirect-like parameters, auth/callback/logout paths, and
continuation forms. `open_redirect.execute_test` sends one harmless external URL
payload and captures redirect responses without following them.

```text
adapters/web/ssti.py
adapters/web/lfi_rfi.py
adapters/web/ssi.py
adapters/web/active_probe.py
```

Workspace-first passive analyzers and approved active validators for reference
web assessment modules. SSTI analysis scores template/rendering parameters,
paths, and reflection/rendering observations, then can run confirmed benign
arithmetic and syntax-differential probes. LFI/RFI analysis scores file, path,
include, view, download, locale, theme, resource, URL, and traversal-like
inputs, then can run confirmed benign public-file and path-normalization
probes. SSI analysis scores `.shtml`/server-parsed paths, HTML/content
parameters, and SSI-relevant observations, then can run confirmed marker
comment and safe SSI echo probes. Passive output uses `AdapterResult` with
workspace observation entities. SSTI and SSI can build no-traffic manual replay
requests for allowlisted benign payloads; active tests require scope,
`confirm=true`, and approval metadata, and record both raw evidence and
`actions.json` entries.

`active_probe.py` is the shared helper for simple active HTTP parameter probes.
Use it when an adapter needs to coerce a workspace candidate into
URL/method/parameter/location fields, replace one query/form/JSON parameter
with a benign payload, apply a scoped `credentialId`, send a bounded request
through the central `core/http` client, and redact secret-bearing request
headers in returned evidence. It is not a
general active-testing framework: adapters that crawl, execute external tools,
write output files, replay complex workflows, or need custom result parsing
should keep specialized active logic while preserving the same scope,
confirmation, approval, redaction, evidence, and action-recording semantics.

```text
adapters/web/access_control.py
```

Flagship workspace-first access-control planner for BOLA, BOPLA, and BFLA
analysis. It extracts object identifiers from path segments, query parameters,
JSON/body/form parameter names, REST-style routes, and GraphQL-like context
without storing raw sensitive identifier values. It writes an adapter-specific
model under `DATA/workspaces/<workspace>/targets/<target>/models/access-control/`:
`objects.json`, `contexts.json`, and `matrix.json`. Standard workspace
observations are still created through `AdapterResult`, including
`access_control_object_candidate` and `access_control_test_candidate`, so agents
can reason over candidates through normal target context. The module records
authorized user/role context labels and credential IDs, builds test matrices
grouped by endpoint pattern, method, object type, role context, and
state-changing behavior, and emits detailed no-traffic test plans.
`access_control.execute_matrix_test` performs approved cross-context replay only
when `confirm=true` is supplied for a concrete request URL and explicit
contexts. It enforces scope, uses credential IDs when they are available, falls
back to unauthenticated replay for contexts without a usable target credential,
blocks state-changing methods unless `allowStateChanging=true`, compares
responses in memory, stores sanitized response summaries in `replays.json`,
writes raw adapter-result evidence, and records an action. Each replay stores a
deterministic `requestFingerprint` for the request/body/context shape and a
nonced `replayId` for the execution record. Replay does not follow redirects
unless `followRedirects=true` is passed, so a redirect to a login page stays
visible as a denial, and only 2xx responses count as granted access when
comparing a denied context against the allowed baseline. Identical 2xx
application-error JSON is downgraded unless success markers or data-bearing JSON
keys are present. Strong replay signals become
`possible_broken_access_control` observations.

```text
core/http/
```

Shared HTTP execution and comparison helpers. `models.py` defines bounded
request, response, cookie, and client-policy data carried across active
workflows. `backends.py` implements direct, proxy, and disabled execution
backends on top of `httpx`; `client.py` exposes the small
`send(request, policy=...)` entry point used by active probe helpers, crawler
traffic, credential refresh, and API-backed adapters. It also exposes an
optional context-manager session path so crawls can reuse one `httpx.Client`
across many requests while the default per-request behavior remains available.
`compare.py` is the
response-comparison helper for approved access-control replay. It compares
status, body length, content type, redirect location, selected headers, body
similarity, JSON key overlap, and sensitive-marker deltas. It intentionally
does not rely on exact body equality, and it redacts `Set-Cookie` header values
when reporting selected header differences.

```text
adapters/web/command_injection_adapter.py
```

Passive workspace analyzer and guarded active validator for command injection
candidates. Passive analysis scores command, shell, process, diagnostic, host,
domain, and target-like parameters or paths. It reads host `fingerprint.json`
when available and carries `possibleOs` into candidate output so generated
payloads use Unix or Windows echo syntax when supported by evidence. Test-plan
generation and `command_injection.prepare_replay` do not send traffic.
`command_injection.execute_test` requires `confirm=true`, scope, and approval
metadata, sends one benign marker request, supports `credentialId`, redacts
secret-bearing request headers from evidence, and records
`possible_command_injection` only when the marker is observed.

```text
adapters/web/spec_import.py
```

Passive API surface import. `spec_import.import_spec` parses OpenAPI 3,
Swagger 2.0, and Postman collections and normalizes documented endpoints,
parameters (with bounded `valuePreview`), request media types, and
`documented_auth_scheme` observations into the workspace through the generic
`adapter_result` ingestion path. Imported endpoints are marked inferred rather
than observed, so a path's presence in a spec is never treated as live traffic.
No secret values are persisted, and the adapter sends no traffic.

```text
adapters/web/headers_cookies.py
```

Passive security-header and cookie-hygiene analyzer. `headers_cookies.analyze_workspace`
reads response metadata already in the workspace (captured by crawler/dump
ingestion) and flags missing or weak `Content-Security-Policy`, HSTS,
`X-Frame-Options`, `X-Content-Type-Options`, and `Referrer-Policy`, plus insecure
cookie `HttpOnly`/`Secure`/`SameSite` flags. Cookie analysis uses names and flags
only; cookie values are never read or stored. Output defaults to host-scoped
dedupe with `affectedUrls`/`affectedCount`; `dedupeScope="endpoint"` preserves the
older per-endpoint rows. It sends no traffic.

```text
adapters/web/jwt_analysis.py
```

Offline JWT structural analysis. `jwt.analyze` inspects an operator-supplied
token for `alg:none`, weak built-in HMAC secrets (bounded wordlist; reports
secret length/class, never the value), suspicious `kid` shapes, missing or
oversized expiry, and privileged claims. The raw token and any matched secret are
never echoed or persisted. It is synchronous, offline, and sends no traffic; it
does not validate signatures against the server or forge tokens.

```text
adapters/web/csrf.py
```

Passive CSRF candidate analyzer. `csrf.analyze_workspace` pairs crawler-discovered
state-changing forms with cookie `SameSite` signals and flags forms that lack a
recognized anti-CSRF token field. `csrf.generate_test_plan` produces a no-traffic
manual validation outline. Detection is name-based, so double-submit-cookie or
header-token schemes may not be visible passively; absence of a token field is a
candidate, not proof.

```text
adapters/web/cors.py
```

Passive CORS analysis plus one bounded active probe. `cors.analyze_workspace`
reviews observed `Access-Control-Allow-Origin`/`Access-Control-Allow-Credentials`
responses. `cors.execute_test` is scope-checked and `confirm=true` gated, sends a
single Origin-reflection request, records evidence plus a workspace action with
redacted headers, and emits `possible_cors_misconfiguration` only when the probe
parser confirms the supplied origin is reflected. It is one of the few web
adapters that can send traffic, and only after explicit approval.

```text
adapters/web/xxe.py
```

Passive XXE candidate analyzer. `xxe.analyze_workspace` normalizes XML/SOAP/WSDL
accepting surfaces (using documented request media types where available) into
validation candidates, and `xxe.generate_test_plan` produces a no-traffic manual
test outline. Accepting XML is a candidate, not proof the parser resolves
external entities. `xxe.execute_test` requires `confirm=true`, scope, and
approval metadata, then sends a benign in-band XML entity expansion payload only;
it does not request files or trigger external entity callbacks.

```text
adapters/web/insecure_deser.py
```

Passive insecure-deserialization marker detector. `insecure_deser.analyze_workspace`
flags recognizable serialized object blob prefixes (e.g. Java, PHP, .NET, Python
pickle markers) in bounded parameter previews and cookie names, storing only the
ecosystem, field, and a truncated preview. It never deserializes data and sends
no traffic; a recognizable blob is a signal, not proof of an unsafe deserializer.

```text
adapters/web/graphql.py
```

Passive GraphQL detection plus one bounded introspection probe.
`graphql.analyze_workspace` identifies GraphQL endpoints from workspace data and
`graphql.generate_test_plan` outlines manual checks. `graphql.execute_test` is
`confirm=true` gated and scope-checked and sends a single introspection POST; a
successful `data.__schema` response normalizes GraphQL operations and arguments
into workspace endpoints and parameters (with operation identity folded into the
entity key so multiple operations on one `/graphql` URL do not collapse). It does
not execute discovered mutations.

```text
adapters/web/tls_posture.py
```

Passive TLS posture normalizer. `tls_posture.analyze_workspace` normalizes
expired-certificate, deprecated-protocol, and certificate-identity observations
from SSL data already collected by Shodan/perimeter ingestion. It performs no
live TLS handshake; deep cipher/protocol scanning belongs to external tools.

```text
adapters/infra/nmap_adapter.py
```

Builds and optionally runs constrained nmap profiles. Command building requires
target scope. Running requires `confirm=true`. Supported profiles are:

- `low_noise`
- `medium`
- `pentest_aggressive`

Nmap XML output is ingested into the workspace layer when the run produces the
expected `-oA` XML file. Runs default to a generic Synapse background job and
return a `jobId` for `jobs.status`; pass `background=false` only for explicit
blocking execution. Finalization refreshes workspace fingerprinting and
perimeter summaries after service data lands.

```text
adapters/infra/shodan_adapter.py
```

Provides passive query construction, Shodan InternetDB lookup, and API-backed
Shodan helpers. The Shodan API key is runtime-only in process memory. Shodan
network-touching lookups require `confirm=true`; `shodan.internetdb` and
`shodan.company_queries` do not need an API key. Shodan summaries can be
ingested as OSINT evidence and normalized into services, endpoints, DNS
observations, IP leakage candidates, CPEs, and possible CVEs. Ingested Shodan
data refreshes workspace fingerprinting and perimeter summaries for the
affected target.

## Tool Surface By Workflow

Adapter and documentation discovery:

- `adapters.list`
- `adapters.capabilities`
- `documentation.list_templates`
- `documentation.list_layers`

Project, scope, and workspace setup:

- `project.start`
- `scope.set`
- `scope.check_target`
- `workspace.create`
- `workspace.add_target`
- `workspace.prepare_target_context`
- `workspace.summary`
- `workspace.delete`

Evidence, ingestion, and finding lifecycle:

- `workspace.ingest_data`
- `workspace.create_finding`
- `workspace.update_finding`
- `workspace.promote_observation_to_finding`
- `workspace.link_evidence_to_finding`
- `workspace.mark_finding_reviewed`
- `workspace.export_finding_context`
- `evidence.log_event`
- `evidence.tail`
- `evidence.init_project`
- `evidence.host_context`
- `fingerprint.from_dump`
- `fingerprint.analyze_workspace`
- `fingerprint.read_host`

Credentials:

- `credentials.set`
- `credentials.set_auth_profile`
- `credentials.authenticate`
- `credentials.set_browser_auth_profile`
- `credentials.browser_auth_check_setup`
- `credentials.browser_authenticate`
- `credentials.validate_session`
- `credentials.list`
- `credentials.get`
- `credentials.delete`

Dumps and cleanup:

- `dumps.list`
- `cache.inspect_scope_data`
- `cache.clean_out_of_scope`
- `cache.inspect_generated_artifacts`
- `cache.clean_generated_artifacts`
- `jobs.list`
- `jobs.status`
- `jobs.cancel`

Documentation and reporting:

- `documentation.build_report_context`
- `documentation.build_finding_context`
- `documentation.build_finding_draft`
- `documentation.build_evidence_pack`
- `documentation.summarize_coverage`
- `documentation.build_layer_report_context`
- `documentation.build_workspace_report_context`
- `documentation.render_markdown`
- `documentation.render_layer_report`
- `documentation.render_workspace_report`
- `documentation.render_assessment_summary`
- `documentation.export_json`
- `perimeter.analyze_workspace`
- `perimeter.build_summary`
- `perimeter.render_report`

Site maps, crawling, and JavaScript intelligence:

- `sitemap.from_dump`
- `crawler.crawl`
- `crawler.extended`
- `js.capabilities`
- `js.discover_assets`
- `js.fetch_assets`
- `js.analyze_static`
- `js.normalize_endpoints`
- `js.build_app_model`
- `js.render_app_map`

Web application analysis and candidate triage:

- `sqli.analyze_workspace`
- `sqli.analyze_dump`
- `sqli.build_sqlmap_command`
- `xss.analyze_workspace`
- `xss.analyze_dump`
- `xss.generate_test_code`
- `xss.execute_test`
- `ssrf.analyze_workspace`
- `ssrf.generate_test_plan`
- `ssrf.execute_test`
- `open_redirect.analyze_workspace`
- `open_redirect.generate_test_plan`
- `open_redirect.execute_test`
- `command_injection.analyze_workspace`
- `command_injection.generate_test_plan`
- `command_injection.prepare_replay`
- `command_injection.execute_test`
- `ssti.capabilities`
- `ssti.passive_analyze`
- `ssti.plan_tests`
- `ssti.prepare_replay`
- `ssti.execute_test`
- `lfi.capabilities`
- `lfi.passive_analyze`
- `lfi.plan_tests`
- `lfi.execute_test`
- `ssi.capabilities`
- `ssi.passive_analyze`
- `ssi.plan_tests`
- `ssi.prepare_replay`
- `ssi.execute_test`
- `access_control.capabilities`
- `access_control.identify_objects`
- `access_control.record_context`
- `access_control.build_test_matrix`
- `access_control.plan_tests`
- `access_control.execute_matrix_test`

Adapters that declare `active_testing` expose the concrete approved execution
entrypoint in capability metadata as `executorTool` (for example
`command_injection.execute_test`, `access_control.execute_matrix_test`, or
`nmap.run_profile`).

Passive API, auth, and misconfiguration analyzers:

- `spec_import.capabilities`
- `spec_import.import_spec`
- `headers_cookies.capabilities`
- `headers_cookies.analyze_workspace`
- `jwt.capabilities`
- `jwt.analyze`
- `csrf.capabilities`
- `csrf.analyze_workspace`
- `csrf.generate_test_plan`
- `cors.capabilities`
- `cors.analyze_workspace`
- `cors.generate_test_plan`
- `cors.execute_test`
- `xxe.capabilities`
- `xxe.analyze_workspace`
- `xxe.generate_test_plan`
- `xxe.execute_test`
- `insecure_deser.capabilities`
- `insecure_deser.analyze_workspace`
- `graphql.capabilities`
- `graphql.analyze_workspace`
- `graphql.generate_test_plan`
- `graphql.execute_test`
- `tls_posture.capabilities`
- `tls_posture.analyze_workspace`

Web discovery scanners:

- `ffuf.profiles`
- `ffuf.build_command`
- `ffuf.run_profile`
- `nuclei.profiles`
- `nuclei.build_command`
- `nuclei.run_profile`

Infrastructure and service enumeration:

- `nmap.profiles`
- `nmap.build_command`
- `nmap.run_profile`

External OSINT:

- `shodan.session_key.set`
- `shodan.session_key.status`
- `shodan.session_key.clear`
- `shodan.company_queries`
- `shodan.internetdb`
- `shodan.host`
- `shodan.domain`
- `shodan.resolve`
- `shodan.reverse`
- `shodan.search_count`
- `shodan.search`
- `shodan.search_facets`
- `shodan.search_filters`
- `shodan.target_summary`

## Main Workflows

### Start or Resume an Engagement

```text
project.start
|-- saves scope
|-- creates or updates workspace
|-- creates org/host evidence folders
|-- returns first-run authentication guidance
`-- optionally fingerprints hosts from a dump

workspace.prepare_target_context + evidence.host_context + fingerprint.read_host
`-- recover normalized target context and prior host evidence before continuing
```

### Review Jobs, Fingerprints, And Perimeter

```text
jobs.list(activeOnly=true, workspaceId="<workspace>")
|-- jobs.status(jobId=...)
|-- fingerprint.analyze_workspace
|-- perimeter.analyze_workspace
|-- perimeter.build_summary
|-- perimeter.render_report
`-- documentation.render_workspace_report(format="html")
```

This is the default follow-up after crawl or recon ingestion. Completed crawl,
nmap, and Shodan runs refresh fingerprints and perimeter summaries during
finalization, but operators should still review those outputs before proposing
deeper technology/version validation.

### Analyze Existing Burp Traffic

```text
dumps.list
|-- sitemap.from_dump
|-- fingerprint.from_dump
|-- fingerprint.analyze_workspace
|-- perimeter.analyze_workspace
|-- sqli.analyze_workspace
|-- sqli.analyze_dump
|-- xss.analyze_workspace
`-- xss.analyze_dump
```

This path is passive and repeatable. It is the preferred first pass when a dump
exists.

### Prioritize Workspace Candidates

```text
workspace.prepare_target_context
|-- review prioritized observations and interestingCandidates
|-- ssrf.analyze_workspace
|-- open_redirect.analyze_workspace
|-- command_injection.analyze_workspace
|-- ssti.passive_analyze / lfi.passive_analyze / ssi.passive_analyze
|-- access_control.identify_objects / access_control.build_test_matrix
|-- ssrf.generate_test_plan
|-- open_redirect.generate_test_plan
|-- ssrf.execute_test
|-- open_redirect.execute_test
`-- access_control.plan_tests
```

Candidate analyzers are passive. They read normalized endpoints, parameters,
forms, services, and observations, then write hypothesis-level observations such
as `ssrf_candidate`, `open_redirect_candidate`, `ssti_candidate`, and
`access_control_test_candidate`. Operator-reviewed issues remain in
`findings.json`.

### Run Web Application Discovery

```text
scope.check_target
operator approval
confirm=true
|-- crawler.crawl
|-- crawler.extended
|-- ffuf.run_profile
|-- nuclei.run_profile
|-- jobs.status
|-- fingerprint.analyze_workspace
|-- perimeter.build_summary
|-- command_injection.execute_test
|-- ssti.execute_test
|-- lfi.execute_test
|-- ssi.execute_test
`-- access_control.execute_matrix_test
```

Active web adapters enforce scope and confirmation. Build-only tools still
require scope but do not send traffic. Access-control replay also requires
explicit contexts and an additional `allowStateChanging=true` gate before
non-GET/HEAD methods. Default outputs stay under workspace target evidence
folders; custom external paths require `allowExternalOutput`.

### Run Infrastructure Enumeration

```text
scope.check_target
operator approval
confirm=true
|-- nmap.run_profile
|-- jobs.status
|-- fingerprint.analyze_workspace
`-- perimeter.build_summary
```

Infrastructure adapters share the same scope, evidence, workspace, approval,
and action-recording model as web adapters.

### Use Credentials Safely

```text
scope.set or project.start
operator approval
credentials.set(confirm=true)
credentials.set_auth_profile(confirm=true)
credentials.authenticate(confirm=true)
credentials.set_browser_auth_profile(confirm=true)
credentials.browser_authenticate(confirm=true)
credentials.validate_session(confirm=true)
|-- crawler.crawl(... credentialId=...)
|-- ffuf.build_command/run_profile(... credentialId=...)
`-- nuclei.build_command/run_profile(... credentialId=...)
```

Credentials are returned redacted and are not written to evidence.

### Use Shodan

```text
shodan.company_queries                 no API call
shodan.internetdb(confirm=true)        no API key required
operator approval + API key
shodan.session_key.set(confirm=true)
|-- shodan.search_filters/search_facets
|-- shodan.host/domain/resolve/reverse/search/search_count/target_summary
`-- shodan.session_key.clear(confirm=true)
```

## Safety Model

- Scope is an authorization allowlist, not a relationship model.
- Active traffic requires both in-scope target validation and explicit approval.
  When a `workspaceId` is supplied, the workspace's own persisted scope is
  checked before global scope.
- Mutating local sensitive state requires approval.
- Shodan network-touching calls require approval because they contact an
  external service; API-backed calls may also consume credits.
- sqlmap is used for validated command generation and offline analysis support;
  execution is not exposed by the Synapse MCP.
- High-risk sqlmap options are blocked at command-build time.
- Secrets are redacted in normal responses and evidence, including common
  embedded secret strings in transcripts.
- Passive/offline ingestion does not block out-of-scope or unset-scope data, but
  it returns explicit scope status and warnings.
- Header credentials and GET auth profiles are guarded before storage.
- External output paths require explicit `allowExternalOutput`.
- Dump, generated-artifact, credential, and workspace deletion are inspect-first
  or approval-gated before mutation.

## Verification Surface

Automated tests currently cover the analysis adapters, workspace knowledge
layer, MCP dispatch, and key safety behavior:

- credential scope enforcement and redaction,
- workspace-owned active scope checks,
- worker result corruption/missing-file handling,
- background timeout clamps and workspace-filtered job listing,
- ffuf credential command redaction,
- SQLi dump analysis over request files,
- sqlmap blocked-option validation,
- XSS test-code generation and benign reflection probe ingestion,
- passive site map extraction from dumps, including rich Burp request/response
  context such as body/JSON/cookie parameters, auth schemes, redirects,
  GraphQL/API/JSON endpoints, auth boundaries, state-changing methods, and
  interesting errors,
- workspace create/list/summary/resource reads,
- workspace finding creation,
- workspace finding lifecycle updates, promotion, evidence linking, review, and
  export context,
- workspace ingestion, deduplication, observations, and target context,
- Shodan OSINT normalization and passive candidate observations,
- deeper crawler navigation, GET-form traversal, and POST-form modeling,
- SSRF and open redirect candidate analysis/test-plan generation plus bounded active probe ingestion,
- command-injection candidate analysis, OS-aware benign payload generation, and
  confirmed marker-test ingestion,
- ffuf, Nuclei, and nmap run ingestion hooks,
- adaptive Nuclei command generation from workspace context and Nuclei JSONL
  candidate ingestion,
- evidence secret redaction, ingestion scope status, credential GET/header
  restrictions, browser-auth sidecar hardening, and external-output guardrails,
- MCP workspace tool dispatch and resource reads.

Run them from the repository root:

```bash
bin/test
```
