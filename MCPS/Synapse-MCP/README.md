# Synapse MCP

Local stdio MCP gateway for Synapse.

Synapse MCP is the scalable MCP boundary for tools other than Burp. Burp remains
a separate MCP because it is provided by PortSwigger and has its own live
application state. Synapse MCP centralizes scope, workspace knowledge,
evidence, dump handling, and policy-aware adapters for analysis tools.

For the full project layout, see [Architecture](../../docs/Architecture.md).
For setup and workflow steps, see [Operations](../../docs/Operations.md).

## Execution Profiles And Authority

The default Codex configuration uses the `modern-compact` stdio profile. The
frozen `legacy` server remains independently available as rollback/bootstrap;
its active tools retain their exact `confirm=true` behavior. Migrated actions
run under server-owned `observe`, `supervised`, or `full_delegated` contexts.
Those
profiles evaluate a sealed Registry plan against durable workspace-local
Authority Grants and atomically reserve a dispatch before the executor runs.
Caller input cannot select or enlarge the profile, grant, step-up, request
state, dispatch, or continuation.

All 174 legacy names are mapped to canonical descriptors across 40 packs before
execution. The checked-in generated inventory preserves exact name/order/schema
projection and serializer ownership; the retained implementation adapter stays
available as the per-action rollback path.

Phase 3B added protocol-independent surfaces under `synapse_mcp.app.facade`.
`modern-compact` has exactly eleven bounded engagement/context/catalog/action/
review/artifact/report/task operations; `modern-direct` deterministically
projects all 174 descriptors. Both validate nested inputs and outputs and enter
the same Registry policy, authority, executor, and ledger path. Passive dynamic
dispatch fails closed on traffic, credentials/secrets, remote mutation, or
destructive effects. Local file results become opaque, versioned references
reauthorized against principal, authority session, and workspace on every
read.

Retained action outputs are described by action-specific public field
contracts derived from canonical serializer source and frozen representative
results. `modern-direct` publishes each exact facade envelope and canonical
result contract through the standard MCP `outputSchema`; supplemental Synapse
metadata is not the primary contract. Compact tools publish all typed outcome
kinds, including their approval carrier, while documenting the narrow dynamic
boundary for runtime-selected actions.

Phase 3C projects either surface through `synapse-mcp-modern` using the pinned
official SDK. It supports stdio and authenticated Streamable HTTP, persists
operation and artifact reference records for restart/multi-worker use, and
seals resume state with an operator rotation keyring bound to the authenticated
principal and stable server audience. Phase 3D adopts compact stdio for Codex;
the old spike entry point is a deprecated forwarding alias.

Authority state lives at
`DATA/workspaces/<workspace>/authority/state.json`. Manage it with the local
`synapse-authority` console entry point described in
[Operations](../../docs/Operations.md); no `authority.*` MCP tools exist.
Covered full-delegated work does not require caller confirmation. Uncovered
work returns approval-required (`-32001`) without dispatch; scope denial remains
`-32002`. Supervised modern calls resume through the official SDK
`request_state` carrier when negotiated. Compatible older revisions return a
typed application result with an opaque handle and resume through
`tasks.control`; mutable environment state is not a resume channel.
The SDK's sealed client token uses persistent rotation keys in production;
explicit ephemeral keys are limited to local single-process development. The
distinct raw authority request remains durable in the workspace repository.
Dispatch budgets count actions, not outbound HTTP requests.

## Runtime Python

Run this MCP through `MCPS/Synapse-MCP/bin/synapse-mcp`. The launcher sources
`config/synapse.env` and uses `SYNAPSE_PYTHON` when set, otherwise it prefers
the active console `VIRTUAL_ENV`, then the repository virtual environment at
`$SYNAPSE_ROOT/.venv/bin/python`; it fails with an actionable diagnostic if no
candidate exists. Browser authentication depends on that venv
path so Playwright/Selenium come from the console or project environment
instead of distro Python packages.

When invoking the installed `synapse-mcp` package console script directly,
set `SYNAPSE_ROOT` or `SYNAPSE_PROMPT_PATH` if you want the full repository
`AGENTS.md` operating policy. If no root or prompt is configured, the server
keeps MCP prompt/resource calls functional with a packaged target-neutral
fallback prompt; the repository launcher remains the preferred Beta runtime.

## Exposed Tools

- `adapters.list`
- `adapters.capabilities`
- `documentation.list_templates`
- `documentation.list_layers`
- `documentation.build_report_context`
- `documentation.build_layer_report_context`
- `documentation.build_workspace_report_context`
- `documentation.plan_scope_groups`
- `documentation.prepare_validation_batch`
- `documentation.build_finding_context`
- `documentation.build_finding_draft`
- `documentation.build_evidence_pack`
- `documentation.summarize_coverage`
- `documentation.render_markdown`
- `documentation.render_layer_report`
- `documentation.render_workspace_report`
- `documentation.render_workspace_report_batches`
- `documentation.render_assessment_summary`
- `documentation.export_json`
- `perimeter.analyze_workspace`
- `perimeter.build_summary`
- `perimeter.render_report`
- `scope.set`
- `scope.check_target`
- `workspace.create`
- `workspace.add_target`
- `workspace.ingest_data`
- `workspace.prepare_target_context`
- `workspace.summary`
- `workspace.delete`
- `workspace.create_finding`
- `workspace.update_finding`
- `workspace.promote_observation_to_finding`
- `workspace.link_evidence_to_finding`
- `workspace.mark_finding_reviewed`
- `approve_pretext_candidate`
- `mark_detection_outcome`
- `workspace.set_entity_reportable`
- `workspace.record_candidate_validation`
- `workspace.curate_candidate`
- `workspace.export_finding_context`
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
- `dumps.list`
- `cache.inspect_scope_data`
- `cache.clean_out_of_scope`
- `cache.inspect_generated_artifacts`
- `cache.clean_generated_artifacts`
- `sqli.analyze_workspace`
- `sqli.analyze_dump`
- `sqli.build_sqlmap_command`
- `xss.analyze_workspace`
- `xss.analyze_dump`
- `xss.generate_test_code`
- `xss.execute_test`
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
- `insecure_deser.capabilities`
- `insecure_deser.analyze_workspace`
- `xxe.capabilities`
- `xxe.analyze_workspace`
- `xxe.generate_test_plan`
- `xxe.execute_test`
- `graphql.capabilities`
- `graphql.analyze_workspace`
- `graphql.generate_test_plan`
- `graphql.execute_test`
- `tls_posture.capabilities`
- `tls_posture.analyze_workspace`
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
- `cve.capabilities`
- `cve.sources`
- `cve.set_source_endpoint`
- `cve.reset_source_endpoint`
- `cve.session_key.set`
- `cve.session_key.clear`
- `cve.session_key.status`
- `cve.correlate`
- `cve.plan_tests`
- `cve.prepare_replay`
- `cve.execute_test`
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
- `js.capabilities`
- `js.discover_assets`
- `js.fetch_assets`
- `js.analyze_static`
- `js.normalize_endpoints`
- `js.build_app_model`
- `js.render_app_map`
- `jobs.list`
- `jobs.status`
- `jobs.cancel`
- `sitemap.from_dump`
- `crawler.crawl`
- `crawler.extended`
- `ffuf.profiles`
- `ffuf.build_command`
- `ffuf.run_profile`
- `nuclei.profiles`
- `nuclei.build_command`
- `nuclei.run_profile`
- `nmap.profiles`
- `nmap.build_command`
- `nmap.run_profile`
- `shodan.session_key.set`
- `shodan.session_key.clear`
- `shodan.session_key.status`
- `shodan.host`
- `shodan.internetdb`
- `shodan.domain`
- `shodan.resolve`
- `shodan.reverse`
- `shodan.search_count`
- `shodan.search`
- `shodan.search_facets`
- `shodan.search_filters`
- `shodan.target_summary`
- `shodan.company_queries`
- `evidence.log_event`
- `evidence.tail`
- `evidence.init_project`
- `evidence.host_context`
- `fingerprint.from_dump`
- `fingerprint.analyze_workspace`
- `fingerprint.probe_versions`
- `fingerprint.read_host`
- `project.start`

The `js.*` tools provide JavaScript intelligence. `js.fetch_assets` is the only
JS tool that sends traffic and requires explicit approval unless the HTTP
backend is disabled. Static analysis never executes JavaScript. Normalized
JS-derived endpoints use `source = "js_intelligence"`, carry `sourceAsset` and
confidence, and are marked inferred/derived so they remain separate from
directly observed traffic. `js.render_app_map` outputs the application map
combining observed workspace requests with JS-inferred requests, source
assets, parameters, and JS signals. Its HTML output is the JavaScript
Intelligence layer report (the same document as
`documentation.render_layer_report(layer="js")` for that target); Markdown and
JSON outputs keep the compact app-map format.

When `crawler.crawl(analyzeScripts=true)` successfully retrieves an eligible
JavaScript response, the body is retained in the canonical JS asset cache under
its normalized URL plus content hash. The cache index carries crawl approval,
evidence, response metadata, content hash, size, and local path. Asset discovery
reuses these records, and `js.fetch_assets` skips valid cached bodies without
requiring a second traffic approval. `refresh=true` explicitly opts into a
confirmed re-fetch.

## Design

```text
Codex
  ├── burp MCP                  # separate live Burp boundary
  └── synapse MCP               # shared policy/workspace/evidence/adapters
        ├── core/scope.py
        ├── core/workspace.py
        ├── core/credentials.py
        ├── core/evidence.py
        ├── core/dumps.py
        ├── core/cache.py
        ├── core/fingerprint.py
        ├── core/perimeter.py
        ├── core/js/                  # static JS intelligence models/extractors
        ├── core/purple_team/         # ATT&CK technique and detection-gap correlation
        ├── core/background_jobs.py
        ├── core/adapters/            # adapter framework: registry, base classes, typed entity models
        ├── core/documentation/       # report contexts, templates, renderers
        └── adapters/                 # concrete integrations (web + infra)
            ├── command_utils.py        # shared adapter guards/helpers
            ├── web/                    # web app discovery and vuln triage
            │   ├── spec_import.py
            │   ├── crawler_adapter.py
            │   ├── ffuf_adapter.py
            │   ├── nuclei_adapter.py
            │   ├── sqlmap_adapter.py
            │   ├── xss_adapter.py
            │   ├── headers_cookies.py
            │   ├── jwt_analysis.py
            │   ├── csrf.py
            │   ├── cors.py
            │   ├── insecure_deser.py
            │   ├── xxe.py
            │   ├── graphql.py
            │   ├── tls_posture.py
            │   ├── ssrf_adapter.py
            │   ├── open_redirect_adapter.py
            │   ├── command_injection_adapter.py
            │   ├── cve_intel.py
            │   ├── ssti.py
            │   ├── lfi_rfi.py
            │   ├── ssi.py
            │   ├── access_control.py
            │   ├── js_intel.py
            │   └── active_probe.py
            ├── infra/                  # infrastructure and OSINT adapters
            │   ├── nmap_adapter.py
            │   └── shodan_adapter.py
            └── social/
                └── pretext_generator.py
```

Web application testing and infrastructure/OSINT operations are separated under
adapter domains while sharing the same scope, evidence, credential, and
workspace layers. Web scanning integrations such as Nuclei live under
`adapters/web/`; network or external exposure integrations should live under
`adapters/infra/`. Both domains should feed the workspace ingestion pipeline
instead of becoming disconnected MCP servers.

The adapter framework itself — the registry, base classes, and typed entity
models that concrete integrations build on — lives in `core/adapters/`, distinct
from the top-level `adapters/` tree that holds the integrations. Use
`adapters.list` and `adapters.capabilities` to enumerate what the registry
currently exposes.

## Internal Layout

```text
synapse_mcp/
|-- transport/stdio_server.py
|-- core/
|   |-- http/
|   |-- documentation/
|-- adapters/
|   |-- command_utils.py
|   |-- web/
|   `-- infra/
`-- __init__.py
```

Tests live under `tests/` and should be run from the repository root. They cover
adapter analysis, credential redaction, workspace ingestion and resources,
documentation context generation/rendering, active-tool ingestion hooks, and
MCP dispatch.

## Documentation Layer

Documentation tools consume normalized workspace state instead of reading
arbitrary files directly. The flow is:

```text
workspace entities and evidence metadata
`-- documentation context builder
    |-- built-in Markdown template renderer
    `-- normalized layer/workspace report renderer
        `-- JSON, Markdown, or HTML export
```

The documentation layer exposes structured report, finding, evidence-pack,
coverage, normalized layer, and all-layer workspace contexts as internal
operator artifacts. The Operator / High-Level split is a presentation-density
toggle, not a confidentiality or redaction boundary. Built-in Markdown templates cover assessment and
finding-oriented deliverables; seven normalized passive providers render
perimeter, JavaScript, authentication, access control, web vulnerability, CVE,
and engagement layer reports as HTML or Markdown.
`documentation.render_assessment_summary` renders the default
assessment summary report with actions, technologies, findings, pretext-candidate
coverage, and pending observations. Pretext bodies/personas render only in
internal mode; high-level mode shows aggregate pretext counts. Detection coverage
is internal-only. Raw HTTP and request/response bodies are omitted by default;
external output paths require `allowExternalOutput=true`.
Documentation tools accept public `redactionMode` values `operator`,
`operator_raw`, and `high_level`. Legacy `internal` and `raw` remain compatible
and select the same underlying policies; deprecated `safe` remains accepted.
Contexts expose `redaction.presentation` separately from `redaction.mode`, and
render results expose `presentation` separately from `redactionPolicy`.
Rendered reports default to `reports/<workspace>/`; implicit filenames are
local to that workspace-owned report directory. HTML
embeds its report assets and has no external runtime dependency.
Scope-group planning responses are compact and paginate groups with
`groupCursor`/`groupLimit`; complete targets and relations remain in the local
manifest instead of flooding MCP context.
Batch rendering separately bounds written files with `partCursor`/`maxParts`
(one part by default), so a dense target group cannot generate every report
part in one call.

## Adapter Policy

Web and infrastructure adapters are separated by primary operating domain, not
by risk level. `adapters/web/` contains web crawling, content discovery, offline
web analysis, passive web vulnerability candidate triage, reference SSTI/LFI/SSI
modules, access-control planning/replay, and active probe helpers.
`adapters/infra/` contains network/service enumeration and Shodan OSINT. Shared
external command safety helpers remain in `adapters/command_utils.py`.

New adapter code must import from the domain paths under `adapters/web/`,
`adapters/infra/`, or the social-engineering helpers under `adapters/social/`.
The previous flat adapter module layout is no longer supported.

Use `adapters.list` and `adapters.capabilities` to inspect registered adapter
metadata, traffic behavior, confirmation requirements, limitations, and output
types before planning an operation. Adapter metadata includes `executionMode`;
active wrappers should be `async_default` through the generic `jobs.*` layer
unless they are deliberately tiny bounded operations marked `sync_only`. New
adapters that declare `active_testing` also expose `executorTool`, the concrete
MCP tool to call for approved execution. New adapters should prefer
workspace-native `AdapterResult` output so observations, candidate findings,
actions, evidence references, and recommended tests merge through the normal
workspace ingestion path.

ffuf and nmap are exposed through named profiles, not generic shell command
execution. Build tools are passive. Run tools require `confirm=true` and the
target must match the active workspace's persisted scope when a `workspaceId`
is supplied. Global scope is used only as a fallback for active tools that do
not have workspace scope.

The persisted scope is an authorization allowlist, not a relationship model.
Operators may place unrelated hosts from separate projects in the same scope
file. Clients should ask whether newly added or coexisting assets are related,
unrelated, or grouped by separate engagements before making cross-asset pivots,
organization assumptions, or shared-context findings. Record that context in
scope notes, workspace scope, or evidence when it affects analysis.

Use `cache.inspect_scope_data` at the start of a new analysis session to compare
local Burp dumps against the current scope file. If it finds artifacts for hosts
that are no longer in scope, review the reported
`deleteCandidates` with the operator first, then call
`cache.clean_out_of_scope` with `confirm=true` only after approval. The cleaner
removes artifacts whose parsed hosts are all out of scope and prunes supported
mixed structured artifacts down to current in-scope hosts. Unknown-host artifacts
are kept and reported.

Use `workspace.delete` for operator-approved removal of a local workspace. The
first call returns a deletion plan; pass `confirm=true` only after approval to
erase `DATA/workspaces/<workspace-id>/`. This does not remove global evidence
indexes under `DATA/evidence/orgs/`.

Use `project.start` at the beginning of an engagement to create the organization
and hostname evidence folders, persist scope, and optionally fingerprint hosts
from an offline Burp dump. The fingerprint is saved per host as
`DATA/evidence/orgs/<organization>/hosts/<hostname>/fingerprint.json` and
summarizes observed technologies, headers, auth hints, cookies by name, endpoint
classes, and representative request lines without storing cookie values.
`project.start` also creates or updates a workspace, using `workspaceId` when
provided or the organization name by default. Its response includes first-run
authentication guidance so the operator can describe complex or multi-step
login flows before storing credentials or refreshing cookies.

Large-scope control-plane responses are bounded by default. `project.start`,
`scope.set`, and `scope.check_target` return scope counts and a five-entry
inventory preview; `workspace.summary` returns aggregate entity counts and a
five-target preview. Pass a string offset in `cursor` with a bounded `limit`
(`inventoryLimit` for `project.start` and `scope.set`) to retrieve subsequent
pages. `includeInventory=true` is the explicit full-inventory compatibility
mode.

Use `workspace.ingest_data` for external or manually supplied data. Supported
parsers include ffuf JSON, Nuclei JSONL, Synapse site map JSON, crawler JSON,
nmap XML, Shodan summaries, workspace-native adapter results, SSRF/open-
redirect/command-injection/SSTI/LFI/SSI/access-control candidate analyses, and
operator notes. The raw data is stored locally, normalized into target
entities, deduplicated, and returned as a compact `llmSummary` with evidence
references. Ingestion also returns `scopeStatus` (`in_scope`, `out_of_scope`,
or `scope_unset`) plus a reason and warning when passive/offline data is not
currently authorized. Use `workspace.prepare_target_context` before planning
next steps so the agent reads normalized services, interesting endpoints,
auth/state-changing surfaces, parameters, observations, findings, recent
actions, recommended next steps, and missing information instead of raw logs.

Crawler and sitemap URL normalization treats scheme, host, path, and sorted
query-parameter names as the canonical identity. Known authentication/session
values and high-entropy query values are replaced before tool summaries and
workspace entities are built; one-way fingerprints preserve correlation where
needed. Malformed encoded `name=value` query fragments are normalized to the
actual parameter name. Raw externally supplied crawl material remains only in
the referenced evidence artifact and is marked as potentially sensitive.

Use `sitemap.from_dump` to build a Burp-like site map passively from an offline
dump. Use `crawler.crawl` only after scope is set and operator approval is
available through `confirm=true`; by default it may follow links and redirects
to other persisted in-scope hosts discovered during the crawl. Set
`includeInScopeHosts=false` for strict single-host crawling. It writes default
results under the target workspace evidence folder.
Passive dump ingestion extracts richer Burp context, including request methods,
query/body/JSON/cookie parameter names, Authorization schemes, status codes,
content types, redirects, JSON/GraphQL/API-like endpoint signals, interesting
errors, auth boundaries, and state-changing methods. It stores cookie names and
auth schemes instead of secret values.
The active crawler follows normal links, common click-like navigation attributes
such as `data-href` and JavaScript `location` handlers, meta refresh targets,
and GET form submissions. `crawler.crawl` records POST forms as workflow
context but does not submit them. `crawler.extended` is the approved
authenticated follow-up mode for bounded POST-form mapping; it requires a
previous crawl, scoped `credentialId`, and `confirm=true`, skips sensitive forms
by default, and records every submitted POST as evidence and a workspace action.
Cross-host links, redirects, form actions, and JavaScript references outside
the owning workspace scope remain in `flowGraph` and normalize to
`asset_relation` observations with `followed=false`; they are not fetched.
Interesting sitemap-derived leads are stored as priority-scored candidate
observations in `observations.json` and surfaced through
`workspace.prepare_target_context` as `interestingCandidates`; they are not
written to `findings.json` until reviewed by an operator.
Both passive and active site-map outputs include `flowGraph`, a structured
workflow graph with host, endpoint, and form nodes plus request, navigation,
redirect, and form-action edges. Edge metadata carries HTTP methods, observed
status codes, query or form parameter names, and whether the request was
actually submitted or only discovered. Mermaid and SVG flowcharts are written
beside the JSON output and returned as `flowGraph.mermaidPath` and
`flowGraph.svgPath`.
Pass `workspaceId` to `sitemap.from_dump` to ingest passive results.
`crawler.crawl` ingests active crawl results automatically and records the run in
the target `actions.json`.

Use `fingerprint.analyze_workspace` and `perimeter.analyze_workspace` after
initial crawl, nmap, Shodan, nuclei, or dump ingestion to classify observed
technology and external-perimeter state. Workspace fingerprinting reads
normalized services, endpoints, response headers, response cookie names,
technology signals, and observations, then writes structured
`technology_component` observations with separate name/version/layer/confidence
fields. The perimeter layer groups host assets, web applications, normalized
technology rows, canonical login portals, protected resources, and review
candidates. Login grouping ignores common workflow/query variants such as
`PAGE_CODE`, `APP_CODE`, `lang`, `returnUrl`, `next`, `continue`, and
`RelayState`, and weak 404 auth-looking routes are filtered out. These tools
are passive and read stored workspace data. `perimeter.render_report` can emit
Markdown or HTML tables for operator review.

Use `spec_import.import_spec` to passively load an OpenAPI/Swagger/Postman
specification (format auto-detected) and normalize documented endpoints,
parameters, and authentication schemes into the workspace. It sends no traffic;
documented endpoints are stored `source="spec_import"` and marked inferred (not
observed), and documented auth schemes are stored as `documented_auth_scheme`
observations without secret values. This enriches the same `endpoints`/
`parameters` that every downstream vuln and access-control analyzer reads.

Use `headers_cookies.analyze_workspace` after crawler/dump ingestion to passively
flag missing or weak response security headers (Content-Security-Policy,
Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options,
Referrer-Policy) and insecure cookie flags (missing HttpOnly/Secure, weak
SameSite). These are passively-verified facts, so they are recorded as confirmed
(not-yet-operator-reviewed) findings — one per host and issue, collapsing every
affected URL — rather than test candidates. It reads only response metadata already recorded in the workspace and
uses cookie names and flags only — cookie values are never stored or read.

Use `jwt.analyze` to statically inspect an operator-supplied JWT offline: it
flags `alg:none`, signatures reproducible with a bounded built-in weak-secret
list, `kid` headers carrying path/SQL metacharacters, missing expiry, and
privileged claims. It sends no traffic and never stores or echoes the token or
any matched secret value; optional ingestion records only redacted observations.

Use `csrf.analyze_workspace` after crawler/dump ingestion to passively flag
eligible state-changing forms (POST/PUT/PATCH/DELETE) that lack a normalized
anti-CSRF token name. `requesttoken`, `_token`, common framework verification,
authenticity/form tokens, and nonce variants are recognized. Login, logout,
recovery, and registration are modeled separately from authenticated state
changes. Login requires an operator-reviewed session-switch scenario, explicit
baseline approval, a valid target-scoped credential reference, and approval ID;
recovery/registration requires concrete unauthorized impact plus evidence.
Forms without those prerequisites and tokenized forms are stored as non-
reportable classifications, while weak SameSite adjusts eligible candidate
priority. Use `csrf.generate_test_plan` to produce a workflow-specific manual
reproduction outline; it sends no traffic and does not submit forms.

Use `cors.analyze_workspace` after crawler/dump ingestion to passively flag
CORS policies from observed headers using browser response-sharing semantics.
Public wildcard reads, wildcard-plus-credentials, fixed public origins, and
credentialed allowlists without observed attacker control are informational;
credentialed `null` policies and observed exact cross-origin matches remain
validation candidates. `cors.execute_test` sends exactly one bounded Origin
probe against an in-scope target and requires `confirm=true` and operator
approval. Only an exact attacker-controlled origin plus credential acceptance
produces a reportable `possible_cors_misconfiguration`. Wildcard plus
credentials becomes non-reportable `invalid_noncredentialed_wildcard` because a
browser rejects credentialed wildcard sharing. The normalized verdict is reused
by the result, action, and workspace observation so labels cannot contradict.
`cors.generate_test_plan` prepares the probe without sending traffic.

Use `insecure_deser.analyze_workspace` to passively flag recognizable serialized
object markers in bounded parameter previews and cookie names. It records only
ecosystem, field name, and a truncated preview; it never deserializes values or
sends traffic.

Use `xxe.analyze_workspace` to passively identify XML/SOAP-accepting endpoints
from request content types, XML-shaped body previews, and WSDL/SOAP metadata.
`xxe.generate_test_plan` produces a guarded manual outline only and sends no
traffic.

Use `graphql.analyze_workspace` to passively flag likely GraphQL endpoints.
`graphql.execute_test` sends exactly one approved introspection POST to an
in-scope target and, when `data.__schema` is returned, normalizes discovered
operations and arguments into workspace endpoints and parameters. It does not
execute discovered operations or mutations.

Use `tls_posture.analyze_workspace` to normalize expired certificate,
deprecated protocol, and self-signed/mismatch issues from already-ingested SSL
summaries into confirmed (not-yet-operator-reviewed) findings. It performs no
live TLS handshake or external scanner execution.

Use `ssrf.analyze_workspace` after sitemap/crawler/Shodan ingestion to passively
score URL-like parameters, callback/webhook/import/proxy paths, and high-value
forms. It stores `ssrf_candidate` observations when ingestion is enabled. Use
`ssrf.generate_test_plan` to prepare canary/collaborator payloads and
guardrails without traffic. `ssrf.execute_test` sends one approved external
canary URL to an in-scope parameter and records evidence, but out-of-band
callback verification is still required before treating SSRF as confirmed.

Use `open_redirect.analyze_workspace` after sitemap/crawler ingestion to
passively classify canonical redirect surfaces using observed `Location`
responses, client navigation sinks, redirect-specific routes, and
authentication continuation context. An absolute URL value alone is not a
redirect signal. WordPress oEmbed inputs and uncorroborated search configuration
are stored as non-reportable surface classifications, with oEmbed retained for
SSRF review. Reportable surfaces are deduplicated by canonical method, route,
location, and parameter, and stale candidates are suppressed on re-analysis.
Use `open_redirect.generate_test_plan` to prepare harmless redirect payloads
without traffic. `open_redirect.execute_test` sends one approved harmless
external URL payload and captures redirect responses without following
redirects.

Use `credentials.set` to store reusable HTTP credentials only after authorized
scope is persisted. Credentials are bound to one or more scoped hosts, saved
under `DATA/credentials/credentials.json`, and returned only in redacted form by
`credentials.list`, `credentials.get`, tool metadata, and evidence events.
Supported types are `bearer`, `basic`, `cookie`, `header`, and browser-derived
`session`. HTTP-oriented tools can opt in by accepting `credentialId`; currently
`crawler.crawl`,
`ffuf.build_command`, `ffuf.run_profile`, `nuclei.build_command`,
`nuclei.run_profile`, `command_injection.execute_test`, `ssti.execute_test`,
`lfi.execute_test`, and `ssi.execute_test` support it. Access-control replay
uses credential IDs through stored context records rather than direct secret
headers.
Header credentials reject invalid header names and CR/LF in names or values.
Cookie credentials can be refreshed from an approved stored login recipe with
`credentials.set_auth_profile` and `credentials.authenticate`; authentication is
active traffic and requires `confirm=true`. Authentication profiles default to
POST; GET credential submission requires `allowCredentialInUrl=true` after the
operator explicitly accepts that URL/log exposure risk.
Browser-heavy, SSO, MFA, JavaScript, or token-brokered flows can use
`credentials.set_browser_auth_profile` and
`credentials.browser_authenticate`. Browser auth runs in a background worker by
default, captures cookies and approved storage metadata into a redacted session
credential, and can validate the session against a protected URL. Playwright is
the local default provider; Selenium Remote is available for managed browser or
grid environments when optional browser dependencies are installed.

Current ffuf profiles:

- `low_noise`
- `medium`
- `pentest_aggressive`

Current Nuclei profiles:

- `low_noise`
- `medium`
- `pentest_aggressive`

Nuclei command generation is adaptive: the selected profile provides policy
defaults for severity, tags, rate limits, concurrency, and target selection, and
`nuclei.build_command` adjusts target URLs and tags from workspace context when
available. Operators can override target URLs, tags, severities, templates,
workflows, rates, and variables. `nuclei.run_profile` requires `confirm=true`,
ingests JSONL output, and stores matches as candidate findings plus
`nuclei_result` observations. Nuclei runs return a generic Synapse background
`jobId` by default; poll with `jobs.status(jobId=...)`.

XSS validation is staged and mode-enforced. `xss.generate_test_code` defaults
to low-risk `reflection_marker` mode, returning one exact 4-80 character ASCII
alphanumeric wire value, encoding metadata, and no browser helper.
`context_breakout` is an explicit medium-risk syntax test without execution
handlers, while `execution` is an explicit high-risk payload set. The same
planner allowlist drives `xss.execute_test`: supplied markers are never
rewritten, only an exact planned payload is accepted, and an approval risk tier
below the selected mode is rejected before traffic.

Command-injection analysis is workspace-driven. `command_injection.analyze_workspace`
tokenizes parameter and path names at semantic boundaries and requires a
command/diagnostic parameter concept plus independent route, observed-request,
JavaScript execution-API, or OS command-response corroboration before emitting
a reportable candidate. Contextual host-like names mixed with known business
vocabulary are suppressed; weak single-signal surfaces are retained only as
non-reportable `command_injection_discovery` observations. Host fingerprints
carry Unix/Windows payload hints when available.
`command_injection.generate_test_plan` returns only benign echo-style marker
payloads. `command_injection.prepare_replay` builds a redacted, no-traffic
manual replay request for one allowlisted benign payload. `command_injection.execute_test`
requires scope, `confirm=true`, and approval metadata, sends one bounded marker
request, supports `credentialId`, and records a possible issue only when the
marker is observed.

SSTI, LFI/RFI, and SSI are workspace-first reference modules. Each exposes a
capability tool, passive workspace analysis, no-traffic test planning, and an
approved active validation path. SSTI and SSI can also build no-traffic manual
replay requests for allowlisted benign payloads. Active validation requires scope,
`confirm=true`, approval metadata, bounded benign payloads, and redacted
credential-bearing headers when `credentialId` is used.

Access-control analysis is workspace-first and no-traffic until replay is
explicitly approved. Identification classifies framework tokens, public
taxonomy fields, unshaped identifiers, dependency/example-only inferences, and
consistently observed 404/410 routes as non-reportable. BOLA/BOPLA candidates
require a concrete object-reference shape and authorization-relevant protected
operation; BFLA requires privileged-function semantics. First-party sources
receive more weight, and contradictory reachable status evidence prevents a
404/410 refutation. Only current reportable objects feed BOLA/BOPLA/BFLA matrix
entries; classifications and stale candidates remain inspectable outside the
active validation queue. The adapter records authorized user/role contexts and
emits manual test plans. Matrix construction preserves exact supplied/recorded
IDs: BOLA/BOPLA needs two authenticated peers and BFLA needs privileged plus
non-privileged authenticated roles. Unsupported comparisons are persisted as
blocked `access_control_coverage_gap` records; an explicitly anonymous context
may create a separate `ANONYMOUS_BASELINE`, but it never substitutes for a
missing authenticated role. `access_control.execute_matrix_test` performs approved
cross-context replay only for a concrete request URL and explicit contexts,
enforces scope and credential handling, fails authenticated contexts that lack
a usable target credential without downgrading them, rejects blocked gaps and
context-ID mismatches,
blocks state-changing requests
unless `allowStateChanging=true`, stores sanitized response summaries, and
records possible broken-access-control observations when comparison signals are
strong.

Current nmap profiles:

- `low_noise`
- `medium`
- `pentest_aggressive`

`ffuf.run_profile` ingests JSON output into the workspace layer when an output
file is produced. `nmap.run_profile` ingests XML output when the expected
`-oA` XML file is produced. ffuf, nmap, crawler, and Nuclei use background jobs
by default and the same `jobs.status` polling path; pass `background=false` only
for explicit blocking execution. Background jobs enforce their outer timeout
with a process-group watchdog while the MCP process is alive; synchronous
blocking command runs also terminate their process group on adapter timeout.
Nonzero exits, missing/corrupt worker results, and finalizer failures remain
terminal `failed` jobs with `finalized=true`; concurrent polling finalizes a
job once. `jobs.status` is modeled as a continuation because polling can
persist, finalize, ingest, log evidence, and remove sidecars. Each new job
stores the originating action/correlation, frozen scope and target envelope,
effects, and plan fingerprint. The seal also binds finalizer identity/data and
result, cleanup, stdout, stderr, and return-code paths; every refresh/finalization
path validates that record before using them or applying effects.
`background_jobs.snapshot()` is the internal effect-free read.
Crawler job process status and assessment coverage are separate. A worker that
exits normally remains `status=completed`, while `resultDisposition` reports
`complete`, `partial`, or `no_coverage`. Default job summaries include attempted
requests, successful fetches, HTTP responses, visited pages, errors, blocked
redirects, and categorized error counts. A failed seed attempt is attempted but
is not a visited page.
Nmap imports dominated by `tcpwrapped` rows emit `scan_interference`; raw rows
remain stored but are excluded from planning, fingerprinting, perimeter, and
CVE correlation.
ffuf, Nuclei, nmap, crawler, and sitemap
outputs default under
`DATA/workspaces/<workspace>/targets/<host>/outputs/`; custom
external output paths require `allowExternalOutput=true`.

The migrated crawler resolves exact JSON/Mermaid/SVG plus background
args/result/state/plan destinations before dispatch, distinguishes create from
overwrite/pruning, and pins background workers to a derived, sealed continuation
of the same immutable plan. `includeInScopeHosts=true` explicitly means
potential coverage of the frozen workspace scope; `false` remains seed-origin
only. The shared HTTP client disables environment proxies, fixes direct/proxy
selection in the plan, resolves proxy secrets only from credential references,
and validates every redirect before its next connection.

The stdio transport has MCP-level call deadlines as a recovery guard. A slow
synchronous `tools/call` returns error `-32003` and the server remains available
for follow-up requests. The timed-out worker thread may still finish later, so
state writes use atomic patterns and long-running work should use `jobs.*`.
Prefer background jobs for anything that may run longer than the configured
`SYNAPSE_MCP_TOOL_TIMEOUT_SECONDS` budget.

`cve.correlate` skips NVD product-only queries for version-unknown components
by default and records `cve_version_precision_gap`. An explicit
`includeVersionUnknown=true` run still suppresses candidates that lack KEV,
public-PoC, or exploit-reference corroboration. Results are ranked and bounded
by `maxCandidates`, with all suppression counts returned.
Provider responses are cached once per source/endpoint/query hash under
`DATA/cache/cve-intelligence/` and reused across targets with target-local
evidence. Cross-process source/credential-tier token buckets honor
`Retry-After`, apply bounded retry/backoff, and expose cache, network, attempt,
retry, and remaining-delay state in `sourceStatus`. A rate-limited source is
resumable and is never treated as a successful negative snapshot.
NVD configuration OS CPEs and explicit advisory preconditions are evaluated
separately from version ranges. Candidates expose version confidence,
deployment disposition, controlling facts, and direct-replay eligibility.
Contradicted deployments are stored as non-reportable refutations; unknown
facts emit prerequisite gaps and block replay preparation/execution until the
affected reachable code path is established.
The PoC source template is startup-validated and must contain exactly
`{year}/{cveId}`. `cve.sources` exposes startup/current configuration status and
effective enablement. Invalid environment or runtime templates produce
`configuration_error` without traffic, and path construction accepts only
strict CVE identifiers.
Aggregate provider health stays in top-level `sourceStatus`. Candidate
provenance uses matching per-query `sourceResults`, keyed by provider and a
canonical endpoint/query hash and carrying exact URL, HTTP status, stable ID,
cache state, and target-local evidence ID. Discovery and enrichment results
cannot inherit the final unrelated component request.

Findings have an explicit lifecycle. `workspace.create_finding` records an
operator-reviewed finding by default, while
`workspace.promote_observation_to_finding` converts a hypothesis from
`observations.json` into a candidate finding. Use `workspace.update_finding`,
`workspace.link_evidence_to_finding`, `workspace.mark_finding_reviewed`, and
`workspace.export_finding_context` to manage status, evidence IDs, review state,
impact/remediation fields, and report context.

Every candidate observation joins a common validation lifecycle
(`proposed → testing → confirmed | refuted | inconclusive`) shared across all
DATA-model layers. `workspace.record_candidate_validation` records the outcome —
per `vulnClass` on a consolidated web `test_candidate`, or top-level on any
single-class `*_candidate` (including access-control candidates). A refuted
candidate is retained but marked `retired`/non-reportable once nothing reportable
remains, and a refuted class is never resurrected by a later re-scan. A confirmed
candidate stays reportable and returns a finding draft to promote via
`workspace.promote_observation_to_finding`.

Passive analyzers stay deliberately conservative (score thresholds plus a per
host/class cap) so they cannot flood the workspace with low-signal candidates.
`workspace.curate_candidate` lets the agent add or remove vulnerability classes on a
surface `test_candidate` precisely — identifying it by `candidateId` or by
`url`/`method`/`parameter`/`location`, creating it if needed — so accurate candidates
can be built from normal observations instead of adapters blanketing every parameter.
Removing a class marks it refuted and drops it from `candidateFor`.

Pretext candidates are stored as draft workspace entities with provenance links
to source observations. `approve_pretext_candidate` requires `confirm=true` to
move a candidate to `approved`; parsing and ingestion never auto-approve.
High-level reports render only aggregate pretext counts and never include the
subject, sender persona, or body template.

Purple-team detection outcomes are recorded with `mark_detection_outcome`.
Actions may carry an optional `mitreTechniqueId`; when that ID is present in the
static technique reference table, marking an outcome generates or updates one
`detection_gap` entity for the action. Detection coverage renders only in the
internal report view.

Every persisted entity (services, endpoints, parameters, findings, actions,
observations, pretext candidates, and detection gaps) carries an `isReportable`
flag, `true` by default.
`workspace.set_entity_reportable` flips it — by identity or by bulk attribute
selector — so operators can discard reviewed false positives from the generated
reports while the records stay in workspace state for later granular analysis.
Non-reportable records are excluded at the report boundary only; agent-facing
context, counts, and resource reads keep the full state. Each disposition is
appended to a small archive at
`reports/<workspace>/report-decisions.json`. Rendered reports and this archive
live in the workspace-owned report directory, not inside workspace state.

Shodan network-touching tools require `confirm=true` because they contact an
external service; API-backed calls may also consume credits. Set the API key at
runtime with `shodan.session_key.set`; the key is held only in the running
Synapse MCP process, is not returned in responses, and is not written to
evidence or config. It disappears when the MCP process exits, or earlier with
`shodan.session_key.clear`. `shodan.target_summary` combines DNS/domain
relations, hostname resolution, bounded host lookup, InternetDB enrichment,
open ports, TLS/HTTP metadata, and possible CVEs for one hostname or IP.
Ordinary DNS resolution is not labeled an IP leak. `shodan.internetdb` requires
approval but does not require an API key. `shodan.company_queries` only builds
useful queries and does not call the API. `shodan.search_filters` and
`shodan.search_facets` expose Shodan query metadata for planning.

Pass `workspaceId` or `ingest=true` to Shodan host, InternetDB, domain, search,
or target-summary calls when the result should update workspace knowledge.
Synapse stores canonical compact OSINT evidence even when `raw=true`, preserves
TLS/HTTP/module/CPE/provider-CVE metadata, and normalizes services and likely
HTTP endpoints under each discovered asset rather than the search/query seed.
DNS and asset relations remain attached to the seed for scope mapping.
