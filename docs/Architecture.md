# Synapse Architecture

Synapse is organized around a required Synapse MCP boundary for local policy,
evidence, and non-Burp tools, plus an optional but highly recommended Burp MCP
boundary for live application state.

The Synapse MCP is built around a workspace-first knowledge pipeline. Guarded
adapters build or run tools, but structured output is stored as raw evidence,
parsed, normalized into target entities, deduplicated, and summarized for LLM
use.

## Runtime Topology

The frozen transport and both modern application projections reach canonical
operations through one protocol-independent execution boundary. Phase 5 adds a
startup-only capability-pack catalog around that Registry; it does not add a
second execution or policy path:

```text
legacy stdio projection       production SDK adapter (stdio / authenticated HTTP)
             \                       compact / direct                         /
              -> frozen selected capability catalog
              -> ActionRegistry.execute(action_id, request)
                   -> runtime availability
                   -> request-effective ActionEffects
                   -> immutable AuthorizationIntent / ExecutionPlan
                   -> profile policy evaluator
                        |-- legacy pass-through
                        `-- locked Authority repository transaction
                              -> typed decision + dispatch reservation
                   -> registered executor (same sealed plan + trusted receipt)
                   -> dispatch result/continuation ledger update
                   -> canonical output-model validation
```

The compact facade has exactly eleven stable application operations. Its
modern `context.query` operation enters the transport-independent Context
Compiler directly; executable operations still enter the Registry. The direct
projection is generated in canonical Registry order. The Phase 3C
official-SDK adapter publishes exactly one selected projection. Startup surface
selection is trusted configuration and is independent from wire negotiation,
client metadata, and authority. Dynamic facade inputs cannot submit a
principal, grant, authority profile, session, or request state.

`ActionEffects` independently describes authorized-target/third-party traffic,
local write domains, local change/destruction, possible remote state change,
credential/secret use, and replay safety. A descriptor declares the maximum;
an input-aware resolver narrows it before policy. Resolver uncertainty applies
the maximum with an explanation. Availability is evaluated before both policy
and execution.

High-level capability packs are separate from `ActionDescriptor.pack`, which
remains the stable first segment of `ActionId`. The standard built-in catalog
owns all 174 actions once across `core`, `web`, `infra`, `reporting`, `purple`,
and `intelligence`; a checked ownership artifact preserves that accounting.
Manifest providers contribute descriptors only through startup assembly, the
selected catalog and Registry freeze before serving, and invalid installed
entry points fail explicitly. External actions are modern-only and are never
implicitly added to the frozen legacy or default 174-action direct surface.

`AuthorizationIntent` is protocol-independent and distinct from a grant. It
records the current workspace and scope digest plus the requested exact targets
or explicit whole-workspace-scope expansion, seed targets, redirect policy,
methods, provider/proxy route, credential references, and exact local output
destinations. `ActionRegistry` seals it with the effective effects and validated
input fingerprint as one `ExecutionPlan`; policy and executor receive that same
immutable instance. Caller input describes a request and cannot manufacture a
grant.

Authority-aware profiles load the selected workspace repository for every
decision. JSON-v1 workspaces retain the crash-atomic private authority file and
workspace lock. Activated workspaces use one SQLite transaction for authority
decision, budget consumption, dispatch reservation, repository revision, and
audit; raw opaque handles are represented by digests. Both stores contain grant
revision history, exact step-ups, opaque request states,
dispatch-total/rate-window/active budgets, audit decisions, dispatch state, job
continuation bindings, and reconciliation. They contain fingerprints and
credential references, never request bodies or credential values. The minimum
dispatch state machine is
`authorized -> dispatched -> succeeded|failed|unknown` and
`authorized -> cancelled`; unknown state-changing work is never replayed.

```text
MCP client
    |-- optional stdio --> MCPS/Burp-Mcp/bin/portswigger-burp-mcp
    |              `-- java -jar mcp-proxy.jar --sse-url <MCP_SSE_URL>
    |                  `-- Burp MCP extension
    |
    `-- stdio --> MCPS/Synapse-MCP/bin/synapse-mcp
                   |-- uses $SYNAPSE_PYTHON, active VIRTUAL_ENV, or .venv/bin/python
                   |-- app/
                   |   |-- actions/ (174 canonical descriptors and Registry)
                   |   |-- capability_packs/ (manifest contract, ownership,
                   |   |                       discovery, frozen assembly)
                   |   |-- context.py (revision-aware budgeted compiler)
                   |   `-- facade/ (compact/direct services, catalog, resources)
                   |-- transport/modern/ (official-SDK stdio/HTTP adapter,
                   |                     identity, keyring, HTTP security)
                   |-- state/ (Phase 4 SQLite runtime/readiness boundary)
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
Operational discovery metadata for registered adapter actions is projected at
runtime from Action Registry v2. The core adapter registry retains only adapter
identity, description, references, outputs, and limitations; its provider seam
preserves the `core`/`app` dependency boundary. Adapter discovery never
authorizes an action.

The canonical output boundary parses legacy JSON, validates the declared
Pydantic output model, and returns that model in `Success.payload`. Six native
pack executors retain field-level output models; the remaining compatibility
executors use distinct JSON-value-checked object models with a typed common
status/background/job/result/error core until their retained implementation
wrappers are physically retired. A separate compatibility
payload preserves the frozen legacy serialization. This prevents legacy
strings from becoming the application contract.

`app/facade/` adds strict transport-neutral input and common outcome contracts,
bounded catalog search, exact schema description, passive/active dispatch,
review/report/task routing, and generated direct descriptors. Passive dispatch
fails before Registry execution when the descriptor's maximum effects include
traffic, credential or secret use, remote mutation, or local destruction;
workspace/evidence writes remain truthfully visible and may be allowed.
Approval-required work becomes an opaque operation handle bound to the trusted
principal, authority session, and workspace, then resumes through the durable
Phase 2 request state exactly once.

Local files are removed from model-facing results and represented by random
resource references. The server-held record binds the principal, authority
session, workspace, artifact type, and content version; every read repeats the
binding, allowed-root, and version checks. Directory issuance and resolution
also bound file count, total/per-file bytes, relative-path bytes, and depth
before/during hashing. Raw filesystem paths are not part of the public
reference. The transport-neutral service remains in-memory by default; the
Phase 3C adapter supplies locked, crash-atomic private persistence under
`DATA/modern-adapter/` so bound operation and resource records survive restart
and can be shared by workers.

Phase 4 state foundations and the activated runtime are transport-independent
under `state/`. Every
connection records and verifies the actual stdlib or reviewed fallback runtime,
refuses SQLite below 3.51.3 and known unsupported/network filesystems, and
reasserts WAL, foreign keys, FULL synchronous writes, and a bounded busy
timeout. Migration `0001` establishes workspace-local relational control,
engagement, knowledge, evidence, execution, authority, audit, and migration
state. One revision transaction commits domain changes, change-log rows, and
append-only audit together. Immutable artifact bytes are streamed into a
bounded, fsynced, collision-checking SHA-256 namespace before metadata commits;
live database backups use the selected SQLite binding's online backup API.
Migration `0002` adds normalized runtime linkage for entity evidence,
authority decisions/revisions, tasks, dispatches/results, durable resource
references, and checkpoint leases. Activated workspace use cases commit their
domain rows, CAS revision, change log, and audit together. Background workers
open connections per operation; dead running/finalizing processes become
reconciliation-required truth and are never redispatched automatically.

ADR-0005 fixes one database and artifact namespace per workspace, with
credential secrets kept outside SQLite and protocol rollback separated from
state-engine rollback. The deterministic migrator inventories JSON-v1 sources,
captures immutable mutable-state snapshots, records each idempotent stage both
externally and in SQLite, verifies relational/content equivalence, and leaves
activation as a separate operator action. Activation flips one atomic selector
and makes legacy JSON writes fail closed. Pre-first-v2-write rollback restores
the exact prior selector; later rollback is refused to prevent data loss.
Canonical bundles carry versioned relational JSON and a verified CAS artifact
manifest. After Phase 4 acceptance, genuinely new workspaces bootstrap
directly into v2; an existing workspace with no selector remains JSON v1 and
is never migrated implicitly. There is no dual-write. Once selected,
SQLite-v2 is authoritative under both legacy and modern protocol profiles.
Canonical bundle import selects v2 only after semantic and artifact
verification. Durable model-facing resources resolve through workspace CAS rows and
hashed principal/session/reference bindings rather than server paths.

The Phase 4 Context Compiler is an application service with no MCP dependency.
It asks the selected repository for one snapshot containing current scope,
authority, normalized domain rows, artifact metadata, and the requested
change-log interval. Its closed result protects revision and safety data,
classifies lifecycle truth without promoting candidates, and packs sections in
a fixed stable order. The published `utf8_bytes_v1` counter measures the final
canonical compact UTF-8 facade envelope through an application-injected
encoder; if the protected minimum exceeds the request, the compiler
returns that measured minimum instead of dropping safety warnings. Large
evidence bodies are never embedded. Full queries return CAS-backed links, while
future or pruned delta cursors fail or require an explicit full refresh. The
legacy `workspace.prepare_target_context` action does not use this compiler.

The modern HTTP boundary authenticates one high-entropy bearer token by
server-held digest, then resolves principal/workspace to a server-held authority
binding. Host and Origin checks, forwarded-header trust, and TLS termination are
startup policy; non-loopback binding requires explicit remote enablement and a
persistent keyring. Successful authenticated HTTP responses are private/no-
store. Public SDK discovery cache hints are limited to projection metadata that
is identical for every caller.

The credential store uses a single file-lock-scoped mutation primitive for the
complete read-modify-write cycle. Atomic replacement, `0600`, file/directory
fsync, and redaction remain intact; concurrent updates cannot read stale state
before taking the lock.
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

Crawler finalization does not equate a zero-exit worker with target coverage.
The job keeps its process status while its compact result independently reports
`complete`, `partial`, or `no_coverage` plus attempted-request, HTTP-response,
successful-fetch, visited, blocked-redirect, queued, and categorized error
counts. Only successful fetches contribute to the visited-page inventory.

`jobs.status` is a continuation operation, not a pure read. Refresh may persist
the job, observe terminal state, run the creation-time finalizer, update
workspace/evidence, and remove sidecars. Job creation stores the originating
action/correlation, frozen scope/target envelope, effects, and plan fingerprint;
the seal also binds the job ID, finalizer identity/data, result/cleanup paths,
and process sidecar paths. Every refresh path validates it before reading a PID,
writing a return code, finalizing, or cleaning up, and concurrent polling applies
finalization once. `background_jobs.snapshot()` is the internal effect-free read.

CVE intelligence responses use a DATA-local provider/query-hash cache rather
than target-local caches. Per-query file locks deduplicate concurrent callers,
while source-and-credential-tier token buckets persist a shared request budget
across MCP processes. A target correlation still writes its own evidence for a
cache hit. Successful query snapshots remain reusable when a later query is
rate-limited, and only a fully successful discovery source participates in
candidate retirement.

Provider health and candidate provenance are separate models. Aggregate
`sourceStatus` belongs to the adapter run. Each successful provider/query hash
creates a source-result record containing its normalized query, exact resolved
URL, HTTP status, stable result ID, cache state, and target-local evidence ID.
Discovery and enrichment attach only their matching records to a candidate, so
a later component request cannot overwrite earlier traceability.

Template-bearing CVE source configuration is validated when the adapter loads
and again at resolution time. The PoC index accepts exactly the `year` and
`cveId` fields, validates a representative absolute URL, and derives the year
only from a strict CVE identifier. Invalid environment or runtime templates
produce a disabled `configuration_error` source before any provider request.

CVE version-range matching is only one layer of applicability. NVD
configuration-tree platform CPEs and explicit advisory conditions become
controlling prerequisite facts, evaluated against independent normalized
target context. A contradictory deployment produces a retained but
non-reportable refutation; missing facts produce a prerequisite-gap observation
and keep active replay disabled. When later fingerprint evidence satisfies the
same facts, snapshot reconciliation updates and revives the existing candidate
instead of creating a parallel identity.

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

URL-bearing crawl/sitemap data crosses an additional hygiene boundary before
agent-facing output and workspace normalization. Canonical identities contain
scheme, host, path, and sorted parameter names; sensitive or high-entropy query
values are replaced and fingerprinted, malformed encoded parameter fragments
are repaired, and form/candidate identities use the canonical page/action/
method/input-name surface. Any retained raw external input stays in the bounded
evidence artifact with sensitive-data metadata.

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
    |-- passively discover JavaScript asset URLs and crawler-retained bodies
    |-- reuse valid URL+content-hash cache entries, or fetch missing/refresh-approved assets through core/http policy
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

reports/<workspace>/      local rendered reports, scope-group/batch manifests,
                          report runs, and report-decision archives
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
- Migrated crawler outputs are resolved to exact physical JSON/Mermaid/SVG paths
  before dispatch, distinguish create from overwrite/pruning, and cannot be
  redirected by a later symlink substitution. Background args, result, state,
  and execution-plan sidecars are also exact local-output destinations; only
  the cleanup-marked destinations may be pruned by the finalizer.
- Migrated HTTP execution disables environment proxies, fixes the explicit
  direct/proxy/provider route in the execution plan, and validates every
  normalized redirect before the next connection. Cross-origin redirects strip
  target Authorization/Cookie headers; proxy secrets are credential references.
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
