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
baseline, typed application action contracts, a registry-projected six-action
vertical slice, and crash-atomic state prerequisites. The Phase 2 Authority
Engine checkpoint is published as an explicitly unapproved draft so development
can continue from the same Git state without implying architectural sign-off.

### Added

- **Modernization correction gate.** Action Registry v2 now routes explicitly
  by canonical ID, validates six real typed output contracts, resolves
  multidimensional request effects, evaluates runtime availability before
  policy, and supplies canonical operational metadata for migrated adapters.
- **Official MCP SDK spike and functional vertical.** An isolated
  `mcp==2.0.0` extra proves three actions over protocol `2026-07-28`, stdio, and
  loopback Streamable HTTP without treating legacy confirmation as authority.
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

### Fixed

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
