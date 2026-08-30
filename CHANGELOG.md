# Changelog

All notable, shipped changes to Synapse are recorded here. This is the shared,
committed history for the project. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/); entries are grouped as
**Added**, **Changed**, **Fixed**, and **Removed**.

> Day-to-day, per-developer implementation notes live in `docs/Version-Log.md`,
> a local, gitignored scratch log provisioned from `docs/Version-Log.template.md`
> on setup. At ship time, the relevant entries from that local log are summarized
> into this file.

## [Unreleased]

Post-demo Beta workflow hardening. This set keeps large authorized workspaces
complete while bounding control-plane responses, candidate review, and report
generation; it also tightens passive candidate semantics across the web and CVE
layers.

The staged modernization foundation now includes the frozen compatibility
baseline, a complete 174-action canonical registry, protocol-independent
compact/direct services, and an integrated Phase 2 Authority Engine with
durable dispatch and continuation truth.

### Added

- **Phase 5F provider-neutral operational acceptance.** Added an offline
  deterministic corpus and aggregate eight-verdict acceptance runner for pack assembly,
  multi-process work-item concurrency, authority/execution linkage,
  compact/context budgets, direct and coordinated operational workflows,
  installed cold start, and legacy rollback. Concurrent processes model
  separately connected operators/accounts without consuming a single model
  subscription. The objective-driven Codex runner is an optional one-repetition
  diagnostic, pins the coordinator and specialists to Luna/low with low
  verbosity, disabled reasoning summaries, and capped retained tool output,
  guards higher-usage overrides, and checkpoints clean repetitions. Older live
  Codex benchmark runners now share the Luna/low one-repetition defaults while
  their checked historical Sol evidence remains unchanged.
  Fixtures are fictional/private, external traffic is disabled, committed
  evidence is sanitized, and generic conformance retains its prior
  classification. The deferred complete-phase adversarial review passed across
  authority/claim attacks, recovery without replay, evidence atomicity,
  compatibility surfaces, packaging, and rollback boundaries.

- **Phase 5E operational instructions and Codex distribution.** Split the
  former 640-line combined root manual into a 94-line repository policy plus
  scoped MCP, authority, state, adapter, and test instructions. Repository and
  installed MCP launches now serve the same 6,289-byte package-owned operational
  prompt while preserving legacy prompt/resource discovery shapes and explicit
  prompt overrides. Wheel and sdist artifacts include the complete Codex
  skill/reference tree and standard, core-only, modern-direct, and legacy config
  templates; `synapse-codex-assets` locates/validates installed assets and an
  offline distribution gate proves both archive installs plus 174-action
  standard and 42-action core-only installed runtime startup. Codex integration
  files remain outside core application behavior.

- **Phase 5D Codex multi-agent playbooks.** Added an eight-skill Codex operating
  package with a simple-work router, bounded engagement coordinator, and
  bootstrap, perimeter, web, access-control, CVE, and reporting specialists.
  Shared methodology requires canonical workspace/job/work-item recovery, live
  Registry discovery, passive-first execution, server-held scope/authority,
  conservative candidate/finding semantics, evidence-backed progress, and
  explicit completion or blocking. Added a deterministic package validator for
  stale metadata, missing links, copied schemas/catalogs, and contradictory
  terminology plus fictional end-to-end coordination scenarios. The package
  adds no MCP operation, action contract, provider-specific behavior, or
  engagement data.

- **Phase 5C shared operational work items.** Added SQLite-v2-backed objectives,
  parent/dependency state, atomic exclusive or non-exclusive claims, heartbeat
  leases, optimistic versions, progress/result/blocker/handoff records, typed
  workspace references, stale-claim recovery, and canonical bundle support.
  `tasks.control` retains job/operation-handle behavior and adds `work.*`
  lifecycle operations while compact stays at eleven operations, 23,297
  application bytes, and at most 24,639 official-SDK wire bytes. Compact schema
  annotations are omitted without changing runtime validation or defaults.
  Work-item-aware `context.query` returns bounded specialist
  recovery state, and optional action linkage records Registry/effect/authority/
  dispatch/job/result lineage. Coordination identity grants no authority;
  expired claims never replay active or unknown execution. Existing JSON-v1
  workspaces remain compatible and require explicit v2 activation for work-item
  mutations.

- **Phase 5A deterministic capability-pack assembly.** Added immutable
  provider-neutral manifests, one-time external entry-point discovery,
  dependency/application compatibility validation, exact single action
  ownership, a checked 174-action ownership map, read-only catalog resource
  contract, isolated 42-action core assembly, and frozen post-start Registry
  lifecycle. Native and generated descriptors now return provider values
  instead of mutating the global Registry on import. The standard catalog keeps
  all 174 IDs and frozen order across six high-level operational packs; pack
  identity remains separate from the 40 canonical action namespaces, external
  actions remain modern-only and unselected by default, and every selected
  action still crosses the same Registry policy/effect/execution path.

- **Phase 5B built-in capability migration.** Added trusted one-shot modern
  pack selection with all built-ins as the default and a real 42-action
  `core`-only startup that avoids unselected implementation imports. Compact
  remains eleven operations, default direct and frozen legacy remain 174
  actions, and search/describe/execute share the selected Registry. Discovery
  now distinguishes high-level `capabilityPack` ownership from the stable
  action namespace `pack`, filters canonical effects, availability, target,
  risk, credential, scope, and task properties, and links selected pack
  resources without expanding the main prompt. Compact-only fixtures were
  refreshed at 23,482 application bytes and at most 24,824 official-SDK wire
  bytes; legacy and direct fixtures are unchanged.

- **Phase 4 acceptance and State Store v2 adoption.** Genuinely new workspaces
  now initialize workspace, scope, targets, revision, change log, and audit
  transactionally in SQLite-v2 before an atomic selector install; interrupted
  creation resumes without duplicate truth. Existing JSON-v1 workspaces never
  migrate automatically and retain their adapter, fixtures, pre-cutover
  snapshots, frozen launcher, and open-ended operator-controlled migration
  timeline. Canonical bundle import selects v2 only after semantic and artifact
  verification. Added the private-root, fictional-target, disabled-traffic
  `bin/run-phase4-acceptance` gate covering deterministic migration/resume,
  v2 restart/concurrency/crash truth, backup and bundle recovery, legacy MCP
  over v2, modern budgets/deltas/omissions, rollback refusal, environment/wire
  measurements, Inspector discovery, and secret hygiene. Generic MCP
  conformance remains explicitly `partial_fail`, and exact transport smoke is
  kept separate from the live objective Codex workflow benchmark.
- **Phase 4D revision-aware Context Compiler.** Modern compact
  `context.query` now reads one committed repository snapshot and returns a
  strict, deterministic context model with current revision, optional
  `sinceRevision` deltas, protected scope/authority/contradiction safety,
  lifecycle-separated facts and candidates, gaps, tasks/actions,
  non-executable recommendations, and explicit omissions. Canonical UTF-8 byte
  accounting enforces historical budgets with a typed `budget_too_small`
  result when protected data cannot fit. Large evidence stays in the
  workspace CAS behind principal/session/workspace-bound resource links. The
  legacy `workspace.prepare_target_context` contract is unchanged; refreshed
  compact official-SDK fixtures remain below the 24,834-byte ceiling for every
  supported negotiated revision.
- **Phase 4C transactional runtime adoption.** Activated workspaces now route
  workspace/entity/relation, evidence/artifact, finding/review, authority,
  dispatch, task/finalization, resource-reference, revision, and audit truth
  through the SQLite-v2 repository bundle under both legacy and modern protocol
  profiles. Use-case transactions combine domain changes with CAS revisions,
  uniqueness, evidence/result links, and audit; bounded pre-commit contention is
  retryable while ambiguous commit and post-process-death work require explicit
  reconciliation without redispatch. Modern resources use durable
  workspace-bound CAS references whose model, principal, session, and source
  values are stored only as opaque digests. Added bounded WAL status/manual
  checkpoint and online backup operations, plus deterministic 100-round
  multiprocess dispatch, finalization, and same-entity races and real-process
  crash tests. JSON-v1 remains unchanged for unactivated/frozen workspaces and
  credential bodies remain in their confined store.
- **Phase 4B deterministic migration and cutover.** Added a transport-neutral
  operator service and `synapse-state`/`bin/state` CLI for read-only
  inventory/dry-run, immutable pre-cutover snapshots, restartable idempotent
  JSON-v1-to-SQLite-v2 stages, complete relational/content verification,
  explicit activation, rollback only before the first v2-only revision, and
  status inspection. Canonical versioned export/import bundles verify
  workspace identity, duplicate keys, traversal, schema, and SHA-256 artifact
  content. Credential bodies, bearer/cookie values, encryption/request-state
  keys, and raw opaque handles remain outside SQLite and exports; activation
  installs a fail-closed JSON-v1 write barrier and never creates dual-write.
- **Phase 4A State Store v2 foundations.** Added transport-independent
  repository bundles with JSON-v1-default selection, a hashed `0001` SQLite
  schema spanning workspace, knowledge, evidence, execution, authority, audit,
  and migration state, verified WAL/foreign-key/FULL-sync connections, atomic
  workspace revisions and change/audit commits, local-filesystem refusal, and
  selected-binding online backup. Added a bounded, streaming, fsynced,
  collision-checking workspace-local SHA-256 artifact store with canonical
  directory manifests and install-before-metadata ordering. Production
  workspaces remain JSON v1; this checkpoint performs no migration, activation,
  credential-secret movement, or dual-write.
- **Phase 4 entry readiness.** Added a transport-independent State Store v2
  runtime probe with a hard SQLite 3.51.3 floor, actual linked-version evidence,
  and a maintained APSW fallback across the Python 3.10–3.13 CI matrix.
  ADR-0005/0006 now fix per-workspace database/artifact isolation,
  credential-secret exclusion, rollback boundaries, conservative context
  counting, protected envelopes, and revision semantics before migration work.
- **Phase 3 adversarial corrective gates.** Added a Codex-only objective-driven
  seven-workflow benchmark whose prompt supplies no MCP tool names, action IDs,
  exact arguments, or call counts, plus an exact transport/safety smoke for
  malformed input, unavailable capability, policy/scope/credential denial,
  cross-binding attacks, restart/resume, and replay. Sanitized per-case
  evidence records revisions, capabilities, effects, dispatches, latency/token
  telemetry, duplicate behavior, and resource/evidence integrity while raw
  handles and client streams stay local.
- **Opaque retained-source bridge.** Workspace-owned dump directories and
  source files can be returned and passed back as principal/session/workspace/
  version-bound resource references. Directory manifests are bounded, reject
  symbolic links, and never publish server paths.
- **Phase 3D stable-Codex closure and compact default.** Added exact checked
  payload fixtures, reproducible surface measurement, and sanitized client,
  Inspector, conformance, and adversarial evidence. After preserving the
  blocked historical two-client attempt, amended closure to the operator's
  supported client and verified stable Codex 3/3 through passive read,
  supervised interruption, trusted exact step-up, MCP restart, opaque-handle
  resume, trace continuity, and exactly-once dispatch without experimental
  protocol flags or external target traffic. `modern-compact` stdio is now the
  generated Codex default; legacy remains rollback/bootstrap and direct
  remains diagnostic. ADR-0004 is Accepted.
- **Stable application-level approval resume.** Older negotiated MCP revisions
  retain a typed `approval_required` result with an opaque operation handle;
  `tasks.control(operation=resume)` restores the sealed request after operator
  step-up. Server instructions now distinguish this path from protocol-native
  `input_required`, and a restart/replay regression proves one dispatch.

- **Phase 3C production modern MCP adapter.** Replaced the three-action spike
  with the exact eleven-tool compact and generated 174-tool direct projections
  over the pinned official Python SDK 2.0.0, stdio, and authenticated
  Streamable HTTP. Added deterministic complete schemas, structured outcomes,
  opaque resource links, persistent principal/workspace-bound operation and
  artifact records, server-held authority bindings, rotating principal/audience-
  bound request-state keys, strict remote/TLS/proxy/host/origin startup policy,
  private HTTP caching, trace continuity, and real subprocess coverage. At the
  Phase 3C boundary the legacy launcher remained unchanged and default; the
  spike command is a deprecated forwarding alias.

- **Phase 3B compact and direct application services.** Added an exact
  eleven-operation compact facade plus a deterministic 174-operation direct
  projection over the canonical Registry. Bounded catalog search and exact
  description expose schemas, effects, risk, scope, credentials, availability,
  approval rules, and safe examples. Dynamic execution revalidates inputs and
  outputs, rejects caller authority fields and legacy confirmation, preserves
  policy/ledger semantics, gates passive work on canonical maximum effects,
  resumes supervised work exactly once through opaque operation handles, and
  returns local files only through reauthorized workspace/principal-bound
  resource references. The transport-neutral compact metadata is 21,648 bytes.

- **Phase 3A canonical action surface.** Added a generated, checked-in inventory
  for all 174 frozen legacy tools across 40 packs, complete canonical
  descriptors and aliases, typed inputs and JSON-object outputs, truthful
  optional-binary availability, deterministic projection, and a protocol-free
  retained-implementation bridge with per-action rollback. Exact legacy names,
  order, descriptions, schemas, result behavior, and the 99,337-byte compact
  payload remain frozen.

- **Phase 2 durable authority integration.** Added workspace-local crash-atomic
  grant/revision storage, exact step-ups, opaque resumable request states,
  dispatch-total/rate-window/active budgets, decision audit, legal dispatch
  transitions, continuation bindings, reconciliation, and a trusted local
  `synapse-authority` management entry point. Authority-aware Registry profiles
  now execute covered full-delegated work without caller confirmation and keep
  uncovered or scope-denied work non-dispatched.
  Trusted operators can list pending requests and approve an exact request from
  server-held state; the official SDK resume carrier restores the original
  request identity and dispatches it once.

- **Phase 2 Authority Grant decision model.** Added immutable, serializable
  grants, budgets, exact step-up authorization, stable policy decisions/reasons,
  and pure coverage checks over sealed execution plans. Coverage distinguishes
  exact versus whole-scope targets, redirects, providers, local outputs,
  methods, credential references, multidimensional effects, risk, lifecycle,
  modes, and budget ceilings; Stage B now persists and enforces this model.

- **Phase 1.1 execution truth gate.** Added protocol-independent
  `AuthorizationIntent`, target/scope/output envelopes, provider routes,
  continuation lineage, and immutable fingerprinted execution plans shared by
  Registry policy and runtime.

- **Modernization correction gate.** Action Registry v2 now routes explicitly
  by canonical ID, validates six real typed output contracts, resolves
  multidimensional request effects, evaluates runtime availability before
  policy, and supplies canonical operational metadata for migrated adapters.
- **Official MCP SDK feasibility vertical.** The precursor isolated
  `mcp==2.0.0` spike proved protocol `2026-07-28`, stdio, loopback Streamable
  HTTP, and authority-aware supervised resume before replacement by Phase 3C.
  A deterministic local HTTP fixture proves crawl discovery, vulnerable/safe
  CORS controls, header/cookie analysis, ingestion, and evidence traceability.

- **Typed Action Registry foundation.** Protocol-independent action contracts,
  canonical identities, policy metadata, typed outcomes, registry consistency
  checks, and five action packs now project six legacy actions through the
  application seam while preserving the frozen 174-tool surface.
- **Modernization verification and handoff material.** Exact legacy contracts,
  workflow benchmarks, architecture guards, the proven action-migration guide,
  Phase 1 review/handoff records, and the tracked draft Phase 2 Authority Engine
  design checkpoint make the staged program reproducible across clones.
- **Bounded workspace audit batches.** Stable related-asset scope groups,
  snapshot-stable passive validation queues, and target/record/part cursors for
  resumable report runs under `reports/<workspace>/`. Full manifests remain
  local while MCP responses return compact paginated summaries.
- **Shared URL hygiene.** Canonical URL and parameter identities redact dynamic
  authentication/session values, collapse equivalent request surfaces, and let
  crawler-fetched JavaScript be reused by static analysis.

### Changed

- **Codex-only Phase 3 acceptance.** Stable Codex is the sole active named-agent
  gate for Phase 3. Independent client evidence is outside that release gate,
  so no universal cross-agent claim is made; provider-neutral contracts and
  later cross-agent acceptance remain project objectives. Generated client
  configuration now emits only Codex profiles and frozen legacy rollback.
- **Candidate precision.** Command injection, XSS, access control, open redirect,
  CORS, and CSRF now require semantic or workflow-specific corroboration instead
  of relying on broad name/path heuristics. Active validation preserves the
  requested safety mode and exact actor context.
- **CVE correlation reliability.** Provider rate coordination, deployment
  prerequisite checks, valid PoC endpoint templates, and per-query provenance
  improve applicability and source-status accuracy.
- **Report organization and presentation.** Reports and decision archives are
  workspace-owned; public `operator`, `operator_raw`, and `high_level`
  presentation labels map consistently to compatibility policies.

### Removed

- **Alternate-agent Phase 3 paths.** Removed alternate-client preflight,
  authentication, parsing, model, and MCP configuration branches from both live
  runners, along with the optional alternate-agent config output.
- **Closed Phase 2 working documents.** Removed the auxiliary truth/correction
  gate, design checkpoint, execution plan, inventories, status, and handoff
  documents after closure. The original local modernization plan and durable
  ADR-0003/ADR-0009 decisions remain.

### Fixed

- **Phase 5B adversarial capability boundary.** Capability manifests and
  built-in ownership maps are now deeply immutable at their declared sequence
  and mapping boundaries. Installed manifests fail startup on invalid global
  dependency graphs or duplicate action/resource ownership even when
  unselected; caller-supplied external manifests cannot claim built-in origin;
  malformed providers return typed pack errors; assembled catalogs must match
  their exact frozen Registry; and modern runtime construction cannot create a
  second, conflicting process Registry after startup selection.
- **Phase 4 adversarial operability corrections.** Canonical State Store
  bundles now capture revision and relational truth from one WAL snapshot and
  verify the digest of artifact bytes copied into the bundle. Activated writes
  reconcile lost commit acknowledgements against revision/audit receipts and
  expose non-retryable metadata when durability cannot be proved. Modern
  `context.query` budgets now measure the final canonical facade envelope, and
  repository policy consistently describes per-workspace SQLite-v2 as the
  default for new workspaces with JSON-v1 retained for compatibility and
  migration.
- **Phase 4 entry residuals.** Existing Phase 3 benchmark evidence now validates
  offline without rewriting historic client metadata, missing live clients fail
  cleanly, runtime-resolution tests are checkout-independent, and the retained
  output generator follows the shared interpreter policy. Background benchmark
  postflight waits on terminal-and-finalized truth, while opaque directory
  resources reject bounded file-count, total/per-file byte, relative-path, and
  depth overruns before or during hashing.
- **Phase 3 contract and authority truth.** Replaced inferred authorization
  effects with audited explicit declarations for all 174 actions and an
  observed-effect no-network harness; removed model authority over external
  output and recursive censorship of legitimate nested security data; published
  action-specific standard output envelopes, including truthful array roots;
  and kept frozen legacy discovery exact at 174 tools / 99,337 bytes.
- **Phase 3 resume and modern runtime integrity.** Standalone modern processes
  now bind retained implementations, standard results/errors identify protocol
  revision and surface, and sequential/concurrent application and native
  approval resumes converge on one dispatch with a typed replay denial.
- **Deterministic baseline isolation.** Provider rate-limit tests use an
  injected coordination clock, and workflow benchmarks wait for background
  runtime handles plus intentionally timed-out tool workers before releasing
  process-global isolated state.

- **Phase 2 final authority closure.** Separated canonical authorization
  identity from the complete correlation-bearing plan seal, bound idempotency
  keys to one logical request, and restored original correlation/idempotency
  metadata from durable request state. Correlation churn, changed payloads,
  revised/revoked grants, concurrent resumes, and replay can no longer bypass
  unknown-dispatch or step-up protections. The modern adapter now consumes the
  official SDK `request_state` context instead of a mutable environment value.
- **Background job sidecar cleanup.** Process observation is read-only, so a
  polling observer can no longer recreate `returncode.txt` after a concurrent
  watchdog/finalizer has committed terminal state and removed runtime sidecars.

- Target credential headers are re-resolved for every redirect/discovered
  origin and never inherit across uncovered origins; proxy credentials use a
  separate exact provider scope and `Proxy-Authorization` cannot become a
  target header. Background job transitions are revision-safe, race winners are
  durable, finalization/cleanup is single-application, and no process wait
  occurs while holding the workspace state lock. Restart recovery never signals
  an unauthenticated persisted PID or applies uncertain continuation effects.

- `jobs.status` now declares refresh/finalizer/workspace/evidence/cleanup
  effects instead of pure read; jobs preserve and validate creation-time
  continuation authority, including bound finalizer and local-path metadata,
  and repeated polling remains single-application.
- Background crawler effects now include worker workspace ingestion and job
  cleanup. Exact external and worker-sidecar outputs distinguish
  create/overwrite/prune and cannot be redirected after policy by traversal,
  record mutation, or symlink substitution.
- Migrated HTTP execution now validates every redirect before connection,
  fixes explicit proxy/provider selection, ignores environment proxies, and
  strips sensitive target headers on cross-origin redirects.

- Credential and authentication-profile mutations now lock the complete
  read-modify-write cycle, preventing lost updates under concurrent upsert and
  delete operations while preserving atomic replacement and private modes.
- Contract-fixture path leakage detection is path-aware across POSIX, Windows,
  and UNC forms without matching natural-language substrings; crawler ingestion
  now preserves observed cookie flags for passive analysis.

- Scope, credential, and private JSON writes now use shared crash-atomic
  replacement with bounded reentrant locking and exact private-file modes;
  workspace writes reuse the same primitive without changing their established
  synchronization behavior.
- Large scope/project/workspace responses are compact and explicitly paginated.
- Crawl jobs expose per-target partial failures instead of reporting only an
  aggregate successful job state.
- Browser-rejected wildcard credential CORS responses are no longer labeled as
  credentialed-read candidates, and tokenized/authentication CSRF workflows no
  longer become blanket candidates.

## [0.6.0-beta.0] — 2026-07-10

Beta operational-precision release. This release reduces candidate noise,
models deterministic passive issues separately from heuristic candidates,
consolidates cross-adapter candidates, adds vulnerability-to-CVE correlation,
reworks Shodan normalization, preserves cross-asset crawl relations, and
relocates rendered reports.

### Added
- **CVE intelligence layer.** New `cve` web adapter with config-driven
  multi-source discovery and enrichment (NVD 2.0), runtime-only provider keys,
  source-endpoint overrides, cached source evidence, `cve_candidate`
  observations, and confirmation-gated active replay. Correlation is gated on
  applicability (product/version match via NVD `configurations`), web-pentest
  relevance (web-exploitable CWE classes and network attack vector), and
  reachability (the crawled web surface, not infra-only banners); all
  drop/suppress tallies are surfaced. A `cve` documentation layer renders
  suggested CVEs and confirmed CVE findings, presenting raw exploit references
  only in Operator-detail columns.
- **Client-side JS library detection.** Curated detector for common high-CVE
  browser libraries (jQuery, jQuery UI, Bootstrap, AngularJS, React, Vue, Lodash,
  Moment, Handlebars, DOMPurify, Axios, CKEditor, TinyMCE) from asset filenames
  and source license banners, mapped to CPEs and fed directly into CVE
  correlation as `technology_component` observations.
- **`fingerprint.probe_versions`.** Confirmation-gated, bounded GET probe that
  enriches already-identified technology components with exact versions/CPEs and
  records exchange evidence and actions.
- **Per-entity reportability.** `isReportable` flag (default true) on all entity
  layers, a report-boundary filter that keeps agent/adapter paths on full state,
  and a `workspace.set_entity_reportable` tool (identity or bulk attribute
  selector) with a sticky decision archive.
- **Candidate validation lifecycle.** `validationStatus`
  (proposed/testing/confirmed/refuted/inconclusive) on every candidate,
  `workspace.record_candidate_validation`, and `workspace.curate_candidate` for
  agent-driven add/remove of vulnerability classes on a request surface. Refuted
  classes are retained-and-marked and stay refuted across re-scans; confirmed
  returns a finding draft.
- **Consolidated cross-adapter candidates.** Injection adapters that flag the
  same request surface `(method, url, location, parameter)` now merge into a
  single `test_candidate` with a unioned `candidateFor` list and per-class
  `candidateDetails`, credited once per class in inventory and coverage.
- **Phishing pretext candidates.** A `pretext_candidate` entity type and social
  adapter that normalize generated pretexts, keep provenance links to the source
  observations that justified them (with unresolved refs flagged as
  `missingEvidenceIds`), and require an explicit `approve_pretext_candidate`
  confirmation before a draft becomes approved. Pretext bodies and personas are
  operator-only: the high-level report shows only aggregate counts by
  sophistication tier and status.
- **Purple-team detection-gap correlation.** Actions can carry a MITRE ATT&CK
  `mitreTechniqueId`; `mark_detection_outcome` records whether the blue team
  detected a tagged action and derives a `detection_gap` entity (criticality and
  expected detection sources frozen from a static technique reference at
  generation time). Detection outcomes are internal-only.
- **Engagement report layer.** A consolidated "Engagement Coverage" layer in the
  workspace/layer reports surfaces pretext candidates and a detection-coverage
  matrix, honoring the operator/high-level split at the data level.
- **Cross-asset relation model.** Crawls and Shodan results preserve related
  host/IP/domain edges as `asset_relation` observations. Active crawls record
  out-of-workspace-scope links without fetching them, while flow graphs retain
  the related endpoint and actual followed state.
- **Scan-interference diagnostics.** High-volume Nmap inventories dominated by
  `tcpwrapped` rows are retained as raw services but excluded from planning,
  fingerprinting, and perimeter correlation with an explicit
  `scan_interference` observation.

### Changed
- **Passive hygiene now produces findings.** `headers_cookies` and `tls_posture`
  emit confirmed findings (one per host+issue, with union-merged affected URLs)
  instead of candidate observations. TLS expired-certificate and
  deprecated-protocol issues are classed medium; identity issues stay score-based
  low/info.
- **Reports relocated.** Rendered reports and their report-decision archives now
  write to a top-level `reports/` directory rather than inside each workspace
  folder. Implicit report filenames are workspace-qualified to prevent
  cross-workspace overwrites.
- **Shodan adapter precision.** Host, InternetDB, domain, search, and target
  summary calls normalize canonical data even when `raw=true`; preserve TLS,
  HTTP, CPE, CVE, module, DNS, and asset-relation metadata; resolve hostnames
  before host lookup; and ingest discovered services under the discovered
  asset rather than the query seed. Registry metadata now correctly identifies
  third-party traffic and confirmation requirements.
- **CVE breadth policy.** Version-unknown components emit a precision gap and
  skip NVD product-only queries by default. Explicit broad runs retain only
  KEV/PoC/exploit-corroborated candidates, and candidate output is ranked and
  capped with suppression counts. Successful refreshes retire unreviewed
  candidates no longer returned, preserve history, and revive them if they
  reappear; provider failures never retire prior candidates.
- **Local report model.** Operator and High-Level views are internal
  presentation modes. Generated HTML no longer requests external web fonts and
  remains self-contained at runtime.
- **Transport validation.** MCP calls enforce declared enums, numeric bounds,
  array item types, and `oneOf` shapes while rejecting private worker fields
  from external calls.
- **Injection precision controls.** Per-adapter minimum-score thresholds and a
  per-host candidate cap, both operator-overridable.
- **Fingerprint version parsing.** Generator-style version strings (e.g.
  `Drupal 10 (https://www.drupal.org)`) are parsed into name/version and
  synthesized into CPEs; CVE range matching now handles partial (major-only)
  versions.

### Fixed
- **CVE candidate flood.** Runs that previously produced 100+ low-value CVE
  candidates are now gated down to applicable, web-relevant, reachable ones, and
  version-less component duplicates are collapsed so keyword lookups can't
  resurrect out-of-version CVEs.
- **Background job terminal state.** Concurrent polling no longer races on one
  temporary record; nonzero commands, missing/corrupt worker output, missing
  finalizers, and finalizer exceptions finish as finalized failures.
- **Crawler scope precedence.** Cross-host traversal uses the owning workspace
  scope before global scope and does not materialize out-of-scope form actions
  as normal endpoints.

## [Alpha] — 2026-07-02

Initial release: local-first MCP control plane with the Workspace → Target →
Finding entity model, the guarded adapter framework, access-control
(BOLA/BFLA/BOPLA) testing, and the operator/high-level report model.
