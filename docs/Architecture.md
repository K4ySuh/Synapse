# Synapse Architecture

Synapse is organized around a required Synapse MCP boundary for local policy,
evidence, and non-Burp tools, plus an optional but highly recommended Burp MCP
boundary for live application state.

The Synapse MCP is built around a workspace-first knowledge pipeline. Guarded
adapters build or run tools, but structured output is stored as raw evidence,
parsed, normalized into target entities, deduplicated, and summarized for LLM
use.

## Runtime Topology

```text
MCP client
    |-- optional stdio --> MCPS/Burp-Mcp/bin/portswigger-burp-mcp
    |              `-- java -jar mcp-proxy.jar --sse-url <MCP_SSE_URL>
    |                  `-- Burp MCP extension
    |
    `-- stdio --> MCPS/Synapse-MCP/bin/synapse-mcp
                   |-- uses $SYNAPSE_PYTHON, active VIRTUAL_ENV, or .venv/bin/python
                   |-- core/
                   |   |-- paths.py
                   |   |-- errors.py
                   |   |-- scope.py
                   |   |-- credentials.py
                   |   |-- evidence.py
                   |   |-- dumps.py
                   |   |-- cache.py
                   |   |-- fingerprint.py
                   |   |-- perimeter.py
                   |   |-- js/
                   |   |-- background_jobs.py
                   |   |-- job_worker.py
                   |   |-- purple_team/
                   |   |-- http/
                   |   |   |-- models.py
                   |   |   |-- backends.py
                   |   |   |-- client.py
                   |   |   `-- compare.py
                   |   |-- documentation/
                   |   |   |-- models.py
                   |   |   |-- builder.py
                   |   |   |-- layers.py
                   |   |   |-- renderer.py
                   |   |   |-- layer_renderer.py
                   |   |   |-- templates.py
                   |   |   |-- exporters.py
                   |   |   |-- redaction.py
                   |   |   `-- assets.py
                   |   |-- adapters/
                   |   |   |-- models.py
                   |   |   |-- base.py
                   |   |   |-- registry.py
                   |   |   `-- results.py
                   |   `-- workspace.py
                   `-- adapters/
                       |-- command_utils.py
                       |-- web/
                       |   |-- crawler_adapter.py
                       |   |-- ffuf_adapter.py
                       |   |-- nuclei_adapter.py
                       |   |-- sqlmap_adapter.py
                       |   |-- sqlmap_analysis.py
                       |   |-- xss_adapter.py
                       |   |-- xss_analysis.py
                       |   |-- active_probe.py
                       |   |-- surface_hygiene.py
                       |   |-- candidate_dedupe.py
                       |   |-- ssti.py
                       |   |-- lfi_rfi.py
                       |   |-- ssi.py
                       |   |-- access_control.py
                       |   |-- js_intel.py
                       |   |-- ssrf_adapter.py
                       |   |-- open_redirect_adapter.py
                       |   |-- command_injection_adapter.py
                       |   |-- cve_intel.py
                       |   |-- spec_import.py
                       |   |-- headers_cookies.py
                       |   |-- jwt_analysis.py
                       |   |-- csrf.py
                       |   |-- cors.py
                       |   |-- insecure_deser.py
                       |   |-- xxe.py
                       |   |-- graphql.py
                       |   `-- tls_posture.py
                       |-- infra/
                       |   |-- nmap_adapter.py
                       |   `-- shodan_adapter.py
                       `-- social/
                           `-- pretext_generator.py
```

## Boundary Decisions

Burp remains separate because it is an optional live desktop application
integration with its own extension server, session state, and UI operations.
Synapse workflows that use offline dumps, stored workspace state, scoped
evidence, crawl/recon adapters, passive triage, and reporting do not require
the Burp MCP to be installed.

The Synapse MCP owns:

- authorized scope storage and checks,
- workspace-owned scope snapshots for active adapter authorization,
- workspace and target state,
- scoped HTTP credential storage and redacted retrieval,
- evidence logging and host context,
- offline dump discovery and cleanup,
- host fingerprinting from captured traffic and normalized workspace state,
- passive external-perimeter classification and reporting,
- JavaScript asset intelligence, static request extraction, inferred endpoint
  enrichment, and JS-enriched app-map reporting,
- Burp-like site map and workflow graph generation from dumps or scoped
  crawling,
- passive Burp dump ingestion for request/response context such as parameters,
  auth boundaries, redirects, API/JSON/GraphQL endpoints, and error signals,
- web application analysis and passive candidate triage,
- constrained web content discovery and infrastructure scan profiles,
- Shodan runtime-key handling and approved third-party exposure queries with
  per-asset workspace normalization,
- report, finding draft, evidence-pack, coverage, and internal HTML report
  contexts rendered through local-first templates.

Adapter framework metadata and result models live under `core/adapters/`. The
framework defines the first-class adapter description model, base interface,
unsupported-method contract, registry, execution-mode metadata, and
workspace-native result schema used by MCP discovery tools and new adapters.
Active wrappers default to generic `jobs.*` background execution unless their
metadata marks them as deliberately synchronous and bounded. Adapter modules
remain organized by operating domain: `adapters/web/` owns web application
crawling, content discovery, offline web analysis, passive API/spec import
(`spec_import`), and web candidate analyzers such as SSRF, open redirect,
command injection, security headers/cookies, JWT, CSRF, CORS, XXE, insecure
deserialization, GraphQL, and TLS posture. It also owns multi-source CVE
correlation and verification (`cve`), which maps fingerprinted components to
candidate CVEs through online intelligence (NVD, CISA KEV, public PoC indexes,
Shodan) and verifies them through bounded, approved replay. Several web
candidate analyzers (`cors`, `graphql`, `xss`, `xxe`, `ssrf`, `open_redirect`,
`command_injection`, `ssti`, `lfi`, `ssi`, `cve`, and `access_control`) expose
bounded, operator-approved active probes. `adapters/infra/`
owns network/service enumeration and external exposure/OSINT adapters such as
nmap and Shodan. Shared active-tool guardrails live in
`adapters/command_utils.py`, and shared active HTTP execution policy lives in
`core/http/`.

The intended data flow for structured output is:

```text
tool output or external data
    |-- store raw evidence
    |-- report target scope status
    |-- parse source-specific data
    |-- parse generic adapter results when they provide an entities bundle
    |   `-- phase 1: context-free structural normalization (type, lists, id/key)
    |-- phase 2: workspace-aware normalization (timestamps, assets,
    |   evidence validation, enum enforcement, stable keys)
    |-- deduplicate per workspace target by stable content-derived keys
    `-- return compact LLM summary and evidence references
```

Parsers and adapters never produce the final persisted workspace shape on
their own. Phase 1 makes entities structurally sane without workspace context;
phase 2 completes workspace-authoritative fields during ingestion; merge is a
pure deduplication step that unions list fields, refreshes seen timestamps,
and escalates non-operator-reviewed finding severity, but never invents
missing authoritative fields.

Site-map and crawler output also includes a workflow graph:

```text
site map hosts, URLs, forms, redirects, and observed requests
    |-- build host, endpoint, and form nodes
    |-- build request, navigation, redirect, and form-action edges
    |-- preserve methods, status codes, parameters, and submitted/discovered state
    `-- write JSON flowGraph plus sibling Mermaid .flow.mmd and SVG .flow.svg files
```

Cross-host discoveries remain relation edges even when the destination is
outside the owning workspace scope. Those destinations appear as related nodes
with scope and followed-state metadata; the active crawler does not send
traffic to them unless workspace scope authorizes traversal.

JavaScript intelligence adds a static client-side enrichment flow:

```text
stored sitemap/crawler/workspace endpoints
    |-- passively discover JavaScript asset URLs
    |-- fetch approved in-scope JS assets through core/http policy
    |-- statically extract endpoints, methods, API bases, GraphQL, WebSockets,
    |   storage keys, auth/CSRF header names, and object identifiers
    |-- normalize inferred endpoints and parameters with sourceAsset and confidence
    `-- render JS-enriched app maps combining observed and inferred requests
```

JS-derived endpoints are not equivalent to observed traffic. They are stored
with `source = "js_intelligence"`, `derived=true`, `inferred=true`, and
`observed=false`; references to already observed endpoints become observations
instead of changing the observed endpoint record.

The default post-ingestion flow for crawl and recon data is:

```text
crawl, nmap, Shodan, sitemap, nuclei, or operator data
    |-- ingest normalized workspace entities
    |-- run workspace fingerprinting for affected targets
    |-- write/update organization host fingerprint.json
    |-- ingest technology_component observations
    |-- refresh per-target models/perimeter.json
    `-- refresh workspace perimeter-summary.json
```

This keeps technology and perimeter reporting based on normalized target state
rather than one-off raw tool output. It also preserves the older
`fingerprint.from_dump` path for compatibility with traffic-only projects.

Nmap ingestion detects high-volume inventories dominated by `tcpwrapped`
services. It retains raw rows and emits `scan_interference`, but excludes those
rows from planning, fingerprinting, perimeter, and CVE correlation until a
cleaner scan or operator review establishes real services. Shodan search and
target-summary ingestion distribute services to each discovered hostname/IP
rather than copying them onto the query seed; DNS and asset relations remain
visible from the seed context.

The intended data flow for documentation is:

```text
workspace entities, evidence metadata, and action records
    |-- build report/finding/evidence-pack/coverage/layer context
    |-- apply internal presentation metadata
    |-- render a template or normalized layer HTML report
    `-- export JSON, Markdown, or HTML
```

Adapters produce workspace entities and evidence; `core/documentation/` owns
delivery-oriented presentation. The shared report styling and banner assets
live in `core/documentation/assets.py` and are reused by every HTML export,
including the perimeter report and the JS app map. Seven normalized passive
report layers for perimeter, JavaScript, authentication, access control, web
vulnerabilities, CVE exposure, and engagement (phishing pretext candidates and
purple-team detection coverage) share the same top-level behavior: read
existing workspace state and model artifacts, expose summary/sections/gaps/next
steps, and render HTML by default without sending active traffic. The engagement
layer gates content on the report mode: the high-level view shows only aggregate
pretext counts and omits detection coverage entirely, while the operator view
carries the pretext body and the detection-gap matrix.

See [Reporting Model](Reporting-Model.md) for the internal Operator /
High-Level view rules, the presentation-density toggle, and the contract that
keeps workspace data rich while reports remain derived views.

Retired standalone MCP packages are not part of the current architecture.
SQLi and XSS analysis are now internal Synapse MCP modules.

## Data Model

Runtime data is local, file based, and rooted under `SYNAPSE_ROOT/DATA` by
default. Relative data and dump paths are resolved from configured Synapse
roots rather than the process working directory, which prevents accidental
`DATA/` creation under MCP client launch directories.

```text
DATA/
|-- scope/                global authorization allowlist
|-- credentials/          scoped credential store (0600 where supported)
|-- evidence/             global and host-indexed evidence event logs
`-- workspaces/<id>/      workspace scope snapshot, jobs, outputs, and
    `-- targets/<host>/   per-target entities, models, outputs, and evidence

reports/                  local rendered reports and report-decision archives;
                          implicit filenames are workspace-qualified
```

The full annotated layout, including every entity file and output folder, is
maintained in the [Implementation Map](Implementation-Map.md#data-layout).

Only `.gitkeep` placeholders should be committed from runtime data directories.
The credential store is local runtime data and should not be committed.

## Safety Model

- Active Burp behavior is controlled by the PortSwigger Burp MCP extension.
- Active adapter scope checks use the owning workspace's persisted scope when a
  `workspaceId` is supplied, with global scope as a fallback only when the
  workspace has no scope snapshot.
- Active crawling requires `confirm=true` and an authorized in-scope target. By
  default it may follow other persisted in-scope hosts discovered during the
  crawl; set `includeInScopeHosts=false` for strict single-host crawling.
  Cross-host references outside workspace scope are recorded as relations but
  are not fetched.
- Extended crawling with POST form submission requires a previous crawl,
  `credentialId`, and `confirm=true`; each submitted POST is recorded as
  evidence and a workspace action, and sensitive admin-like forms are skipped by
  default.
- ffuf, Nuclei, and nmap run tools require `confirm=true` and authorized scope.
- Stored HTTP credentials must be bound to authorized hosts. Tool responses and
  evidence events use redacted credential metadata, while active HTTP tools use
  the secret only at request/command execution time.
- Browser-derived session credentials are stored through the same credential
  layer and resolve cookies per request target so SSO and application-domain
  cookies are not flattened into one host-agnostic header. Cookies with an
  unknown or empty origin domain are not replayed.
- Browser-derived session credentials also preserve safe browser context
  headers such as user agent, language, and accept preferences so follow-up
  HTTP requests resemble the successful browser session without storing
  secret-bearing headers.
- Evidence event data is sanitized for common secret fields and common embedded
  secret-bearing strings before it is written.
- Authentication profiles default to POST; GET credentials require explicit
  `allowCredentialInUrl=true`.
- Browser authentication profiles run through worker subprocesses by default.
  They require explicit approval, can use Playwright or Selenium Remote, and
  store only redacted profile/session metadata in evidence and job records.
  Browser-auth worker args/state files are written with private file
  permissions where supported; known inline secret keys are stripped from worker
  args and the args file is removed during finalization.
- Header credentials validate HTTP header names and reject CR/LF in names and
  values.
- Active adapter outputs default into workspace target evidence folders; custom
  external paths require `allowExternalOutput=true`.
- `js.fetch_assets` is the only JavaScript intelligence tool that sends
  traffic. It requires in-scope targets and explicit approval unless the HTTP
  backend is disabled. It runs synchronously, so it reuses one pooled HTTP
  client and is bounded by a default 20-asset batch and a `totalBudgetSeconds`
  wall-clock budget (default 30) that clamps each request timeout and keeps the
  call well under the tool deadline; assets skipped by the budget are reported
  in `errors`. JS static analysis and app-map rendering do not execute
  JavaScript or perform vulnerability testing.
- Shodan network-touching tools require `confirm=true`; API-backed calls use a
  runtime-only API key.
- SQLmap execution is not exposed by the Synapse MCP. The Synapse MCP builds
  validated commands and analyzes offline dumps.
- Command-injection execution is limited to one approved benign marker request
  against an in-scope HTTP target.
- Workspace ingestion stores raw local evidence and returns compact summaries;
  raw evidence is consulted only on demand. Passive/offline ingestion records
  `in_scope`, `out_of_scope`, or `scope_unset` rather than blocking data.
- High-risk sqlmap options that interact with OS files, shells, or registry
  state are blocked during command generation.
- Scope is an authorization allowlist, not proof that assets are related.
- Dump cleanup is inspect-first and requires explicit confirmation.
