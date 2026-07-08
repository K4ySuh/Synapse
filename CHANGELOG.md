# Changelog

All notable, shipped changes to Synapse are recorded here. This is the shared,
committed history for the project. The format is loosely based on
[Keep a Changelog](https://keepachangelog.com/); entries are grouped as
**Added**, **Changed**, **Fixed**, and **Removed**.

> Day-to-day, per-developer implementation notes live in `docs/Version-Log.md`,
> a local, gitignored scratch log provisioned from `docs/Version-Log.template.md`
> on setup. At ship time, the relevant entries from that local log are summarized
> into this file.

## [Beta] — 2026-07-08

Candidate-model redesign and CVE intelligence. This release reduces candidate
noise, models passive issues as findings, consolidates cross-adapter candidates,
adds vulnerability-to-CVE correlation, and relocates rendered reports.

### Added
- **CVE intelligence layer.** New `cve` web adapter with config-driven
  multi-source discovery and enrichment (NVD 2.0), runtime-only provider keys,
  source-endpoint overrides, cached source evidence, `cve_candidate`
  observations, and confirmation-gated active replay. Correlation is gated on
  applicability (product/version match via NVD `configurations`), web-pentest
  relevance (web-exploitable CWE classes and network attack vector), and
  reachability (the crawled web surface, not infra-only banners); all
  drop/suppress tallies are surfaced. A `cve` documentation layer renders
  suggested CVEs and confirmed CVE findings, omitting raw exploit references from
  high-level/safe views.
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

### Changed
- **Passive hygiene now produces findings.** `headers_cookies` and `tls_posture`
  emit confirmed findings (one per host+issue, with union-merged affected URLs)
  instead of candidate observations. TLS expired-certificate and
  deprecated-protocol issues are classed medium; identity issues stay score-based
  low/info.
- **Reports relocated.** Rendered reports and their report-decision archives now
  write to a top-level `reports/` directory rather than inside each workspace
  folder.
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

## [Alpha] — 2026-07-02

Initial release: local-first MCP control plane with the Workspace → Target →
Finding entity model, the guarded adapter framework, access-control
(BOLA/BFLA/BOPLA) testing, and the operator/high-level report model.
