# Codex Task Batch — CVE Detection, Testing & Documentation Layer

> Implementation scaffolding for a Codex hand-off. Do **not** reference this file from product
> docs (README, Architecture, Operations, Adapter-Development, Reporting-Model); record shipped
> outcomes in `Version-Log.md` only.

## Shared context (read once, applies to every task)

**What we're building.** A CVE layer that (1) turns fingerprint components into candidate CVEs via
multi-source online intelligence, (2) lets the operator verify them through the standard
confirm-gated replay path, and (3) surfaces a "suggested CVE / what-could-we-exploit" section in
the report model.

**Decisions already locked — do NOT re-decide these:**

- **Data source: pluggable multi-source online intelligence**, each source gated + cached and
  modeled on `adapters/infra/shodan_adapter.py` (runtime-only session keys, `require_confirmed`,
  fetches routed through `core.http.http_client` so tests stub them, results normalized and
  ingested into the local workspace). Two stages:
  - **Discovery** (component → candidate CVE ids): **NVD 2.0** (keyed by CPE/keyword, CVSS + refs)
    and **Shodan** (`possibleCves` already in the workspace).
  - **Enrichment** (per CVE id → exploit/severity intel): **CISA KEV** (single JSON feed,
    authoritative "actively exploited"), **PoC-in-GitHub index** (nomi-sec static JSON,
    unauth-friendly, cacheable) — both default-on; plus **opt-in** **GitHub live search** (needs a
    token) and **searchsploit** (local Exploit-DB, auto-skipped if the binary is absent).
  - Default active sources: `nvd, shodan, poc_github_index, cisa_kev` (from `SYNAPSE_CVE_SOURCES`).
    `github_search` and `searchsploit` are opt-in. The set is operator-selectable per call.
- **Provider is pluggable.** Sources live behind a small internal contract
  (`DISCOVERY_SOURCES` / `ENRICHMENT_SOURCES` dicts) so a future source (Vulners, CIRCL) is one
  function, not a rewrite. Each source fetches through one stubbable entrypoint and **degrades
  independently**: one source failing/rate-limited/tokenless must not fail the others or the run.
- **Endpoints are config-driven and agent-recoverable, never hardcoded.** URLs change; the agent
  must be able to route around a dead source instead of just failing. Every source endpoint
  resolves at call time with precedence **runtime override → `config/synapse.env` env var → baked
  default** (a `_resolve_source_config()` helper inside `cve_intel.py`; no new core module — same
  local-env pattern as `NMAP_BIN`/`NUCLEI_BIN`). The recovery loop the agent/operator uses:
  (a) `cve.sources` reports the resolved endpoints + last per-source status; (b) `cve.set_source_endpoint`
  points a source at a new URL at runtime (unpersisted, like the session keys); (c) re-run
  `cve.correlate` with `refresh`. Per-source status carries the **URL tried, HTTP status, and error
  detail** so the agent can diagnose (404 → path moved, 403 → needs token, timeout → network).
  Overrides swap the endpoint of a **known-schema** source; a genuinely new provider schema is a
  code-level plug via the source dicts (this deliberately avoids an arbitrary-fetch/parse surface).
- **Only `{product, version, cpe, cveId}` leave the workspace.** Never send target hostnames,
  paths, or secrets to any third party. KEV/PoC-index are static feeds; GitHub search sends only
  the CVE id.
- **Execution model: one-click confirmed replay.** The CVE layer *prepares* a parameterized,
  scope-checked verification; the operator approves; `cve.execute_test` runs one bounded benign
  request under `confirm=true` (mirroring `ssti.execute_test`). PoC/exploit references are stored
  as **evidence/intel only — never fetched-and-executed as code.** Heavy template scanning is
  delegated to the *existing* `nuclei` tool via a surfaced template id, not reimplemented.
- **Local-first is about the data model, not egress** (see the AGENTS.md Core Identity
  clarification): online lookups are fine; results become local `cve_candidate` observations and
  CVE findings with provenance.

**Two derived fields carry the whole layer's meaning — keep them distinct:**
- `confidence` = **applicability** (does this CVE apply to this component?), driven by fingerprint
  version precision (Task 1): exact version → `high`; range/product-only → `low`;
  Shodan-asserted → `medium`.
- `exploitMaturity` = **exploitability**, driven by enrichment:
  `in_the_wild` (CISA KEV) > `public_poc` (any GitHub/searchsploit PoC) >
  `exploit_referenced` (NVD reference tagged `Exploit`) > `none`.

**Guardrails (every task):** no new DB, no new report/execution engine, no autonomous loop; keep
changes small and legible; extend existing helpers (`candidate_observation`, `AdapterResult`, the
`_section`/`_candidate_section` builders, `require_confirmed`/`require_in_scope`/`approval_metadata`,
`store_http_exchange_evidence`, `build_manual_replay`) rather than inventing abstractions.
Redaction happens only at the report boundary.

**Two doc-sync gates `bin/test` enforces — any task that adds a tool or adapter MUST update the
docs or the build fails:**
- `tests/test_tool_wrappers.py::test_mcp_readme_tool_list_matches_runtime_schema` → every runtime
  tool must be listed in `MCPS/Synapse-MCP/README.md`.
- `tests/test_tool_wrappers.py::test_implementation_map_documents_every_registered_adapter` →
  every registered adapter must appear in `docs/Implementation-Map.md`.

**Run `bin/test` (from repo root) after every task; it must stay green.**

**Execution order (dependency + rising blast radius). Tasks 1–4 are a working CVE layer; Task 5
is a precision booster that can land later without blocking the layer.**

---

## TASK 1 — Synthesize CPEs and version-precision on fingerprint components

**FILES**
- `MCPS/Synapse-MCP/synapse_mcp/core/fingerprint.py`
- `MCPS/Synapse-MCP/tests/test_perimeter.py` (add beside
  `test_workspace_fingerprint_and_perimeter_normalize_technologies`, ~line 494)

**GOAL / CURRENT GAP**
`_workspace_components()` produces components with `name`/`version`/`layer` but no CPE except when
an external `cpe_observed` observation exists (fingerprint.py:362–363). CVE discovery keys on CPE
(or product+version), so today there's nothing precise to look up.

**WHY IT MATTERS**
Without a CPE / explicit version precision, the CVE adapter (Task 2) can't query deterministically
and can't distinguish an exact-version match (actionable) from a product-only guess (noise).
Version precision is the biggest driver of CVE candidate `confidence`.

**EXPECTED BEHAVIOR**
- Add `_synthesize_cpe(name: str, version: str) -> str` with a curated vendor/product map covering
  the products fingerprint already names (Apache httpd→`cpe:2.3:a:apache:http_server`,
  nginx→`cpe:2.3:a:nginx:nginx`, Microsoft IIS, PHP, ASP.NET, WordPress, Drupal, Joomla, jQuery,
  Angular, Express, Node.js, Oracle APEX/ORDS, Java Servlet). Produce CPE 2.3 form; use the real
  version when present, else `*`. Unknown products → return `""` (no guess).
- In `_add_component`, record `cpe` (from `_synthesize_cpe`) and `versionPrecision`: `"exact"` when
  `version` is non-empty, else `"unknown"`. Carry both into the component dict, into the
  `technology_component` observation emitted by `analyze_workspace` (observation dict at
  fingerprint.py ~438–449), and into `technologyComponents` in the saved `fingerprint.json`.
- Keep `_component_key` unchanged (still `layer|name|version`) — CPE is derived, not identity.

**REGRESSION TESTS**
- `test_component_gets_synthesized_cpe_and_exact_precision`: service product `Apache httpd`
  version `2.4.49` → component/observation `cpe == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"`,
  `versionPrecision == "exact"`.
- `test_versionless_component_gets_wildcard_cpe_and_unknown_precision`: WordPress signal with no
  version → `cpe` version segment is `*`, `versionPrecision == "unknown"`.
- `test_unknown_product_has_empty_cpe`: unmapped product → `cpe == ""`, precision `"unknown"`.

**NON-GOALS**
No network calls. No full CPE dictionary — only a curated map for products fingerprint already
recognizes. Don't touch `_component_key` or dedupe. No active probing (Task 5).

---

## TASK 2 — `cve` adapter: multi-source correlation → `cve_candidate` observations

**FILES**
- `MCPS/Synapse-MCP/synapse_mcp/adapters/web/cve_intel.py` (new)
- `MCPS/Synapse-MCP/synapse_mcp/core/adapters/registry.py` (register `cve` metadata)
- `MCPS/Synapse-MCP/synapse_mcp/transport/stdio_server.py` (import module; add `TOOL_SCHEMAS`
  entries + dispatch branches)
- `config/synapse.env` (add the `SYNAPSE_CVE_*` endpoint + enabled-set env vars with baked defaults)
- `MCPS/Synapse-MCP/README.md` (tool list), `docs/Implementation-Map.md` (adapter entry),
  `docs/Version-Log.md`
- `MCPS/Synapse-MCP/tests/test_cve_intel.py` (new)

**GOAL / CURRENT GAP**
Nothing correlates fingerprint components against known CVEs. Shodan already surfaces
`possibleCves` (shodan_adapter.py:360) but they're buried in an OSINT blob — not first-class, not
enriched with exploit intel, not tested, not reportable.

**WHY IT MATTERS**
This is the detection half: the operator needs "these components map to these CVEs, at this
applicability confidence, with this exploit maturity (KEV / public PoC / none), and here are the
PoC references."

**EXPECTED BEHAVIOR**

*Source framework (pluggable, each independently stubbable + degrading):*
- **Config-driven endpoints (no hardcoded constants).** Add these to `config/synapse.env` with
  baked defaults: `SYNAPSE_CVE_NVD_URL` (`https://services.nvd.nist.gov/rest/json/cves/2.0`),
  `SYNAPSE_CVE_KEV_URL` (the CISA KEV feed JSON), `SYNAPSE_CVE_POC_GITHUB_URL` (the nomi-sec
  PoC-in-GitHub raw-JSON base, with `{year}`/`{cveId}` interpolation), `SYNAPSE_CVE_GITHUB_SEARCH_URL`
  (`https://api.github.com/search/repositories`), and `SYNAPSE_CVE_SOURCES`
  (`nvd,shodan,poc_github_index,cisa_kev`). A `_resolve_source_config(source)` helper resolves each
  endpoint at call time with precedence **`_ENDPOINT_OVERRIDES[source]` (runtime dict) → env var →
  baked default**, and returns which layer it came from (`resolvedFrom`). No module-level URL
  constants that bypass this helper.
- `_SESSION_KEYS: dict[str, str]` plus a provider-keyed session-key trio:
  `cve.session_key.set(provider, apiKey, confirm)`, `cve.session_key.clear(provider, confirm)`,
  `cve.session_key.status()` (lists which providers are configured; never echoes key values).
  Providers: `"nvd"`, `"github"`.
- One fetch entrypoint per source so tests `patch.object(cve_intel, "_fetch_<source>")`:
  - Discovery: `_discover_nvd(components, args)`, `_discover_shodan(components, args)` →
    `list[dict]` of `{cveId, cvss, severity, summary, references, component, version, cpe, source}`.
  - Enrichment: `_enrich_cisa_kev(cve_ids, args)`, `_enrich_poc_github_index(cve_ids, args)`,
    `_enrich_github_search(cve_ids, args)`, `_enrich_searchsploit(cve_ids, args)` →
    `dict[cveId, {knownExploited, pocReferences:[{source,url,stars?}], exploitReferences, notes, source}]`.
  - Registries: `DISCOVERY_SOURCES`, `ENRICHMENT_SOURCES`. The default enabled set comes from
    `SYNAPSE_CVE_SOURCES` (baked default `nvd,shodan,poc_github_index,cisa_kev`), overridable per
    call via the `sources` arg. `github_search` needs a `"github"` token (skip with status
    `"skipped: no token"` when absent). `searchsploit` runs the local binary if present, else status
    `"skipped: searchsploit not installed"`.

*Tool `cve.correlate(workspaceId, target, confirm, sources?, refresh?, minCvss?, ingest?)`:*
- `require_confirmed` (touches third parties). Read `technology_component` observations via
  `workspace._load_target_entities` (now carrying `cpe`/`version`/`versionPrecision` from Task 1)
  plus existing Shodan `possibleCves`/vuln observations.
- Run selected **discovery** sources → merge into a set of `(cveId, component, version, cpe)`
  candidates (union CVSS/summary, prefer the highest CVSS when sources disagree). Then run selected
  **enrichment** sources over the discovered CVE id set and fold results in. **Cache** each source
  response as evidence keyed by `(source, query)`; reuse on re-run unless `refresh` is set (the KEV
  feed is fetched once per run and cached).
- Emit one `cve_candidate` observation per `(component, CVE)` via
  `candidate_observation(candidate_type="cve_candidate", ...)`, with:
  - `value = cveId`; **`candidateId = f"cve_{cveId}_{slug(component)}_{slug(version)}"`** (REQUIRED —
    the observation dedupe key resolves `candidateId` before the value discriminator; without it
    re-runs duplicate).
  - metadata: `cveId, cvssScore, cvssSeverity, component, version, cpe, discoverySources (list),
    knownExploited (bool, KEV), pocReferences (list[{source,url,stars?}]), pocCount,
    exploitReferences, exploitMaturity, publishedDate, summary (≤300 chars), nucleiTemplate ("" unless
    known), testable (bool)`. Run-level `sourceStatus` is a per-source dict of
    `{status: "ok"|"error"|"skipped", url, httpStatus?, detail, resolvedFrom: "override"|"env"|"default"}`
    so the agent can diagnose and route around a broken endpoint.
- **Confidence contract (applicability):** `versionPrecision=="exact"` → `confidence="high"`;
  range/product-only → `confidence="low"`; Shodan-only-asserted → `confidence="medium"`. A
  high-confidence candidate is still a *candidate*, never auto-promoted.
- **Priority (from CVSS, then exploit maturity):** base tier from CVSS (critical ≥9.0, high 7.0–8.9,
  medium 4.0–6.9, low <4.0; `priority_score = round(cvss*10)`). Then: `knownExploited` ⇒
  `priority="critical"` + tag `"known-exploited"`; else `public_poc` ⇒ bump one tier (max `high`)
  + tag `"public-poc"`. Deterministic.
- **`exploitMaturity`** precedence: `in_the_wild` (KEV) > `public_poc` (any GitHub/searchsploit PoC)
  > `exploit_referenced` (NVD ref tagged `Exploit`) > `none`.
- Ingest via `workspace.ingest_data(..., "adapter_result", "passive_analysis", ...)` like
  `ssti.passive_analyze`. Return the candidate list, `sourceStatus`, and `cveDataAvailable` (True
  when ≥1 discovery source returned).
- **Degrade:** wrap every source call; a source failure records its `sourceStatus` and continues;
  `correlate` never raises on network/source failure.

*Adapter metadata (registry.py):* `name="cve"`, `category="web"`, capabilities
`["passive_analysis","test_planning","active_testing","result_ingestion","finding_generation"]`,
`sends_traffic=True`, `requires_confirmation=True`, `touches_third_party=True`,
`default_risk_tier="medium"`, `execution_mode="sync_only"`,
`produces=["observations","candidate_observations","findings","evidence"]`, limitations naming the
online dependency and that "presence in NVD/PoC index ≠ exploitable on this target."

*Tools to register (schema + dispatch, mirror ssti/shodan blocks):* `cve.capabilities`,
`cve.correlate`, `cve.session_key.set`, `cve.session_key.clear`, `cve.session_key.status`, and the
endpoint-recovery trio `cve.sources` (report resolved endpoints + last per-source status),
`cve.set_source_endpoint(source, url, confirm)` (runtime override, unpersisted), and
`cve.reset_source_endpoint(source, confirm)`. Update README tool list + Implementation-Map +
Version-Log.

**REGRESSION TESTS** (stub each `_fetch_*`/`_discover_*`/`_enrich_*`; use `isolated_state`)
- `test_correlate_requires_confirm`: no `confirm` → raises `confirm=true`; no source fetched.
- `test_correlate_merges_discovery_and_enrichment`: NVD returns CVE-X for an exact-version
  component; KEV marks it exploited; PoC-index returns two repos → one `cve_candidate` with
  `confidence="high"`, `knownExploited=True`, `exploitMaturity="in_the_wild"`, `priority="critical"`,
  `pocCount==2`. Re-run ingest → still **one** observation (dedupe holds via `candidateId`).
- `test_public_poc_bumps_priority_without_kev`: no KEV, PoC-index has a repo → `exploitMaturity=="public_poc"`,
  priority bumped one tier, tag `"public-poc"`.
- `test_correlate_degrades_per_source`: `_enrich_poc_github_index` raises, others ok →
  `sourceStatus["poc_github_index"]` starts with `"error"`, `cveDataAvailable==True`, candidates
  still emitted, no exception.
- `test_github_search_skipped_without_token` and `test_searchsploit_skipped_when_absent`: statuses
  are `"skipped: ..."`, run succeeds.
- `test_source_endpoint_resolution_precedence`: with a baked default, then a monkeypatched
  `SYNAPSE_CVE_NVD_URL` env, then a `cve.set_source_endpoint("nvd", ...)` override →
  `_resolve_source_config("nvd")` returns the override and `resolvedFrom == "override"`; after
  `cve.reset_source_endpoint("nvd")` it falls back to env (`resolvedFrom == "env"`).
- `test_source_status_reports_url_and_http_status_on_failure`: stub a source fetch to return HTTP
  404 → `sourceStatus[source]` has `status == "error"`, the tried `url`, and `httpStatus == 404`
  (enough for an agent to infer "path moved"); the run still succeeds with other sources.
- `test_cve_sources_tool_reflects_override`: after `cve.set_source_endpoint`, `cve.sources` shows the
  new URL and `resolvedFrom == "override"`.
- Adapter-list test: `cve` appears in `adapters.list`.

**NON-GOALS**
No target hostnames/secrets to any third party. No promotion to findings here. No new HTTP engine
(reuse `core.http`). No executing PoC code. `github_search`/`searchsploit` are opt-in, never
default-on.

---

## TASK 3 — CVE test planning + one-click confirmed replay

**FILES**
- `MCPS/Synapse-MCP/synapse_mcp/adapters/web/cve_intel.py`
- `MCPS/Synapse-MCP/synapse_mcp/transport/stdio_server.py`, `README.md`, `docs/Version-Log.md`
- `MCPS/Synapse-MCP/tests/test_cve_intel.py`

**GOAL / CURRENT GAP**
Candidates from Task 2 can't yet be verified through Synapse's guarded path.

**WHY IT MATTERS**
This is the "confirmed → operator workflow → one-click execute" half, kept inside the
operator-control gates, with the multi-source PoC/KEV intel as the decision evidence.

**EXPECTED BEHAVIOR** (mirror `ssti.plan_tests`/`prepare_replay`/`execute_test`)
- `cve.plan_tests(candidate|candidateId, ...)` — **no traffic.** Returns a ranked plan: the safe
  verification approach; whether a `nucleiTemplate` exists (and the exact
  `nuclei.build_command`/`nuclei.run_profile` invocation for it); `knownExploited` and
  `exploitMaturity` up front; `pocReferences` grouped by source as **read-only intel**; expected
  signals; and explicit guardrails ("benign verification only; confirm=true required; do not fetch
  or execute PoC code"). Also state the promotion path (`workspace.promote_observation_to_finding`).
- `cve.prepare_replay(...)` — **no traffic.** Translates the candidate (and, where present, the
  request shape implied by a PoC reference) into a single parameterized benign verification request
  via `build_manual_replay`, for operator review. Raw PoC URLs are echoed as references, never
  dereferenced.
- `cve.execute_test(...)` — `require_confirmed` + `require_in_scope`; send one bounded benign
  verification request (or a small capped set) through `http_client.session`, capture with
  `store_http_exchange_evidence`, classify `possible_cve` vs `inconclusive` from a
  candidate-specific signal, ingest the assessment, and `record_action` (tool `cve.execute_test`) —
  structurally identical to `ssti.execute_test`. For CVEs whose only safe verification is a nuclei
  template, `execute_test` returns a `delegateToNuclei` payload (template id + built command)
  instead of firing, so the operator runs it through the existing `nuclei` tool. **Never runs
  downloaded code.**
- On promotion, the finding key incorporates the CVE id + affected asset for stable dedupe; the
  finding links the verification exchange evidence and the PoC reference(s).
- Register `cve.plan_tests`, `cve.prepare_replay`, `cve.execute_test` (schema + dispatch); update
  README + Version-Log.

**REGRESSION TESTS**
- `test_plan_and_prepare_replay_send_no_traffic`: patch `http_client`; `plan_tests`/`prepare_replay`
  send nothing and the plan names guardrails, `exploitMaturity`, PoC references, and any nuclei
  template.
- `test_execute_test_requires_confirm_and_scope`: missing `confirm` raises; out-of-scope target
  errors before any request.
- `test_execute_test_records_evidence_and_action`: stubbed HTTP response → assessment ingested,
  exchange evidence stored, action recorded.

**NON-GOALS**
No fetching/executing PoC code. No new execution engine — direct benign request or delegate to
existing `nuclei`. No auto-promotion to findings.

---

## TASK 4 — `cve` documentation/report layer ("Suggested CVEs & Exploitability")

**FILES**
- `MCPS/Synapse-MCP/synapse_mcp/core/documentation/layers.py`
- `MCPS/Synapse-MCP/tests/test_documentation.py`
- `docs/Version-Log.md`

**GOAL / CURRENT GAP**
The report model (`DEFAULT_LAYERS`, `_providers`, `list_layers`) has no CVE view — the operator
can't see "what could we exploit" in a report.

**EXPECTED BEHAVIOR**
- Add layer `"cve"` to `list_layers()`, to `DEFAULT_LAYERS`, to `_providers()`, and to
  `_normalize_layer` (aliases `cves`, `vulnerability_intel`, `cve_intel`).
- `_cve_layer(args)` builds a `LayerReportContext` (mirror `_web_vulnerabilities_layer`) reading
  `cve_candidate` observations and CVE-derived findings per target, with sections:
  1. **"Suggested CVEs (Candidate Exposure)"** — `_candidate_section` grouped by severity, sorted so
     `known-exploited` / `in_the_wild` rows lead: columns `[Host, Severity, Component, Version, CVE,
     CVSS, Confidence, Exploit Maturity, KEV, PoCs, Testable, Evidence, Exploit Reference, Reason]`.
  2. **"Confirmed CVE Findings"** — `_section` table `[Host, Severity, CVE, Component, Status,
     Evidence]`.
  - `gaps`: none run yet / N high-confidence candidates awaiting verification / N KEV-listed
    candidates present. `recommended_next_steps`: verify KEV/high-confidence candidates via
    `cve.prepare_replay`/`execute_test` before promotion.
- **Redaction:** add `"Exploit Reference"` to `SAFE_OMITTED_COLUMNS` so the high-level view hides raw
  PoC/exploit URLs (operator view keeps them); run candidates/summary through `redact(..., policy)`
  like the other layers. The `KEV` / `Exploit Maturity` columns stay in both views (they're
  severity signal, not operator-only identifiers).

**REGRESSION TESTS + TEST-CONTRACT CHANGES (call out — these fail against the old contract):**
- Adding `cve` to `DEFAULT_LAYERS` changes `summary.layerCount` (5→6) and the layers list in the
  workspace report. **Update** `test_documentation_renders_normalized_layer_and_workspace_reports`
  and any assertion in `test_documentation.py` pinning the layer set/count to the new contract.
- If any test asserts `list_layers` returns 5 entries, update to 6.
- New `test_cve_layer_ranks_kev_and_hides_exploit_refs_in_safe_view`: seed a KEV candidate + a
  plain candidate → KEV row sorts first; operator view shows the Exploit Reference column
  populated; safe view omits it; both list the CVEs and Exploit Maturity.

**NON-GOALS**
No new report engine or template. Every canonical section renders an explicit empty-state when
there's no CVE data. Redact only at the boundary; never weaken workspace data.

---

## TASK 5 — Active fingerprint version probing (precision booster; independent)

**FILES**
- `MCPS/Synapse-MCP/synapse_mcp/core/fingerprint.py` (or a small `adapters/web/` helper if cleaner)
- `MCPS/Synapse-MCP/synapse_mcp/transport/stdio_server.py`, `README.md`,
  `docs/Implementation-Map.md`, `docs/Version-Log.md`
- `MCPS/Synapse-MCP/tests/test_perimeter.py` or `test_web_discovery_adapters.py`

**GOAL / CURRENT GAP**
`analyze_workspace` is fully passive; many components land with `versionPrecision="unknown"`, which
caps CVE applicability confidence at `low`.

**WHY IT MATTERS**
Fingerprint imprecision was called out directly. A bounded active probe upgrades product-only
guesses to exact versions — turning low-confidence CVE noise into high-confidence, testable
candidates.

**EXPECTED BEHAVIOR**
- New tool `fingerprint.probe_versions(workspaceId, target, confirm, maxRequests?=8)` —
  `require_confirmed` + `require_in_scope`. For components already identified on the target, issue a
  **bounded** set of GET requests to a **fixed benign allowlist** of version-revealing surfaces
  (root `/` for `Server`/`X-Powered-By`, `<meta name="generator">`, and per-app-family benign
  version markers), parse versions, and enrich matching components: `confidence="high"`,
  `versionPrecision="exact"`, synthesized exact CPE (reuse Task 1 `_synthesize_cpe`). Store each
  exchange with `store_http_exchange_evidence`; ingest enriched `technology_component` observations;
  `record_action`.
- Hard-cap total requests at `maxRequests` (default 8); GET only; in-scope only; benign paths only;
  no auth-state changes.
- Register the tool (schema + dispatch); update README + Implementation-Map + Version-Log.

**REGRESSION TESTS**
- `test_probe_versions_requires_confirm_and_scope`.
- `test_probe_versions_upgrades_precision`: stub HTTP returning `Server: Apache/2.4.49` at root for
  a product-only component → component becomes `versionPrecision="exact"`, version `2.4.49`, exact
  CPE, evidence stored.
- `test_probe_versions_respects_request_budget`: no more than `maxRequests` requests issued.

**NON-GOALS**
No brute-forcing, no auth flows, no destructive/version-file fuzzing beyond the fixed benign
allowlist. No exceeding the request cap. Does not touch the CVE adapter — only improves its inputs.
