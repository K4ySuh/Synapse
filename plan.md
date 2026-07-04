# Synapse candidate-model redesign — implementation plan

Working branch: **Beta** (off `main` @ 269b6dc "Alpha Release").
Run tests with `bin/test` (uses repo `.venv`). Keep the local, gitignored
`docs/Version-Log.md` updated as phases land. Never commit real client data;
`reports/` and `DATA/` are gitignored.

## Locked operator decisions
1. Passive hygiene issues (headers/cookies/TLS) = real **findings**, not candidates. (DONE, Phase 1)
2. Refuted candidates are **retained + marked**, not deleted.
3. Adapters auto-emit candidates (tightened + consolidated); the agent can also curate.

## Progress
- `7632a9c` isReportable flag + report-boundary suppression + set_entity_reportable + decision archive.
- `ca5d78d` Phase 0: reports + `<wid>.report-decisions.json` write to top-level `reports/` (paths.REPORTS_DIR).
- `8fdd0ea` Phase 1: headers_cookies + tls_posture emit findings via `results.passive_finding()`.
- `57c2e44` Phase 1 follow-up: expired/deprecated TLS findings = medium severity.
- Phase 2: injection candidates consolidated into one `test_candidate` per surface with
  union-merged `candidateFor`/`candidateDetails` (`results.surface_candidate`, workspace merge,
  perimeter inventory + report candidate, coverage, web-vuln layer, regression tests).
- **NEXT: Phase 3 (below).**

---

## Phase 2 — consolidate injection candidates into one `test_candidate` per surface

**Problem.** Each injection adapter (`lfi`, `sqli`/sqlmap, `ssrf`, `ssti`) emits its own
`*_candidate` observation per parameter, keyed by a class-prefixed candidateId
(`ssrf_<method>_<slugurl>_<param>`, `lfi_candidate_...`, etc.). The same parameter becomes
3–4 separate observation entities → candidate flood + duplicate evidence.

**Target.** ONE observation per surface `(method, url, parameter, location)` with:
- `type = "test_candidate"`
- `candidateFor: ["sqli","ssrf","lfi","ssti", ...]`  (union-merged across adapters)
- `candidateDetails: {<class>: {reasons, priority, priorityScore, testPlanSummary, confidence}}`
- top-level `priority`/`priorityScore` = max across classes; `reasons` = union; `value=url`.

### Files & changes
1. **`core/adapters/results.py`** — add `surface_candidate(...)` factory (export in
   `core/adapters/__init__.py` like `passive_finding`). It MUST compute a class-independent
   candidateId so every adapter collides on the same surface:
   `candidate_id = f"tc_{stable_slug(method)}_{stable_slug(url)}_{stable_slug(location)}_{stable_slug(parameter)}"[:170]`
   (put `stable_slug` import from `synapse_mcp.adapters.web.active_probe` — or pass the id in
   from each adapter using a shared helper in `adapters/web/` to avoid a core→adapters import;
   PREFER a small helper `adapters/web/surface_candidate.py` so core stays adapter-agnostic).
   Returns an ObservationEntity with the fields above; `candidateFor=[vuln_class]`,
   `candidateDetails={vuln_class: {...}}`.
   - NOTE the two-phase contract: no workspace context in the factory (context-free).

2. **`core/workspace.py`** — merge support:
   - Add `"candidateFor"` to `_MERGE_UNION_FIELDS` and `_ENTITY_LIST_FIELDS`.
   - In `_merge_entity_fields`, add:
     - `candidateDetails` dict-merge: `merged.setdefault("candidateDetails", {})` then for each
       sub-key not present, set it (each adapter writes only its own class key → no conflict).
     - `priorityScore` → max: `merged[name] = max(int(merged.get(name,0) or 0), int(value or 0))`.
     - `priority` → rank-escalate using OBSERVATION_PRIORITIES order (info<low<medium<high<critical),
       mirroring the existing `severity` escalation block.
   - `_entity_key` needs NO change: the generic `candidateId` branch already yields
     `test_candidate:tc_...` which merges by surface. VERIFY with a test.

3. **Adapters `lfi_rfi.py`, `sqlmap_adapter.py`, `ssrf_adapter.py`, `ssti.py`** — change each
   `build_result` to emit `surface_candidate(vuln_class="lfi"|"sqli"|"ssrf"|"ssti", url, method,
   parameter, location, reason, priority, priority_score, test_plan_summary, evidence_ids, ...)`
   instead of `candidate_observation(candidate_type="<x>_candidate", ...)`.
   Keep the internal `candidates` list (raw dicts) unchanged so `result["candidates"]`,
   `plan_tests`, and `execute_test` keep working. Record a passive action per adapter (as in
   Phase 1) so coverage still credits the module (see consumer #4).
   - `classify_candidate` in lfi still produces subtypes (rfi/path_traversal/file_download);
     fold these into the lfi class OR keep as candidateFor entries `["lfi"]` with the subtype in
     candidateDetails. Recommended: single class `"lfi"`, subtype in candidateDetails.

4. **`core/perimeter.py`**
   - `candidate_inventory(entities, target)`: special-case `type == "test_candidate"`: for each
     `cls in observation.get("candidateFor", [])`, `byModule[cls] += 1`; set
     `item["candidateModules"] = candidateFor`, `item["candidateModule"] = candidateFor[0] if any`.
     `total = len(items)` (surfaces), so byModule may sum > total (intended).
   - Leave `WEB_VULN_OBSERVATION_PREFIXES` for the still-per-type observations (csrf, cors,
     open_redirect, xxe, graphql, insecure_deser, ssi, jwt, xss, command_injection) — only the
     four injection adapters consolidate in this phase.
   - `_observation_report_candidate` / `_is_report_candidate_observation`: make sure a
     `test_candidate` is treated as a report candidate (add "test_candidate" handling), and its
     rendered category shows `candidateFor`.

5. **`core/documentation/builder.py` (coverage)** — in `summarize_coverage`, when an observation
   `type == "test_candidate"`, add each `candidateFor` class to `passive_modules` and
   `target_passive_modules` (so per-module passive coverage is preserved). The `follow_up`
   `endswith("_candidate")` branch still fires (test_candidate ends with `_candidate`).

6. **`core/documentation/layers.py` (`_web_vulnerabilities_layer`)** — the inventory items now
   carry `candidateModules`/`candidateFor`; render one row per surface with a "Candidate For"
   column listing the classes. Update `moduleCounts`/`candidateCount` to count surfaces and
   per-class as appropriate.

### Regression tests (name them)
- Ingest a `test_candidate` for the same `?url=` from lfi + ssrf + sqli (3 separate ingests) →
  **one** observation entity, `candidateFor == ["lfi","ssrf","sqli"]` (order-insensitive),
  `candidateDetails` has all three keys, `priorityScore == max`.
- `candidate_inventory` byModule has lfi/ssrf/sqli each = 1, `total == 1`.
- Coverage: passive_modules includes lfi/ssrf/sqli from the single test_candidate.
- Each injection adapter: `analyze_workspace` ingests `test_candidate` (not `*_candidate`);
  `result["candidates"]` internal shape preserved.
- Update ALL existing injection-adapter tests asserting `type == "sqli_candidate"` etc. to
  `type == "test_candidate"` + `candidateFor`. Grep: `grep -rn "_candidate\"" tests/`.

### Gotchas
- Existing tests in `test_web_discovery_adapters.py` (sqli/ssrf/ssti/lfi classes) assert the
  old types and candidateIds — expect broad but mechanical churn. Flag each as a contract change.
- `perimeter` open_redirect candidates (the oembed false-positive case) are NOT injection
  adapters and stay as `open_redirect_candidate` observations. Do not consolidate those here.
- Keep `isReportable` behavior intact — consolidated candidate is still one entity that can be
  suppressed by `set_entity_reportable`.

---

## Phase 3 — candidate validation lifecycle (refute/retire, confirm→finding)

**Target.** Each `test_candidate` carries per-class validation state in
`candidateDetails[cls]["validationStatus"] ∈ {proposed, testing, confirmed, refuted, inconclusive}`
(default `proposed`).

### Files & changes
1. **`core/workspace.py`** — add `record_candidate_validation(workspace_id, target,
   surface_selector, vuln_class, outcome, evidence_ids=..., notes=...)`:
   - Finds the surface `test_candidate` (reuse `_entity_matches_selector` / surface candidateId).
   - Sets `candidateDetails[cls]["validationStatus"] = outcome`, stamps decidedAt.
   - On `refuted`: remove `cls` from `candidateFor`. If `candidateFor` becomes empty → set the
     observation `isReportable = False` and `retired = True` (retain per decision #2), archive a
     line to the workspace decision archive.
   - On `confirmed`: leave candidateFor; return a suggested finding draft (do NOT auto-create;
     operator/agent promotes via existing `promote_observation_to_finding`, extended to be
     class-aware). OR auto-create a candidate-status finding — DECIDE in spec (recommend: return
     draft, let promote handle it, to keep operator in the loop).
   - Add MCP tool `workspace.record_candidate_validation` (transport schema + dispatch + README).
2. **`adapters/web/{lfi_rfi,ssrf_adapter,ssti,sqlmap_adapter}.py` `execute_test`** — after running
   the benign-payload test, call `record_candidate_validation(... outcome=...)`:
   - all benign payloads negative / `inconclusive` with no signal → `refuted` for that class
     (per operator: "seeing none work should instantly remove the candidate").
   - signal observed → `confirmed`.
   Keep dangerous payloads operator-gated (`confirm=true`); benign markers agent-runnable.
3. **Reports** — `candidate_inventory` / web_vuln layer must exclude `refuted`/`retired`
   candidates (they're already isReportable=false if fully retired; also skip classes whose
   validationStatus==refuted when listing candidateFor).

### Regression tests
- `record_candidate_validation(refuted)` on the only class → candidateFor empty, isReportable
  false, retired true, excluded from candidate_inventory, still present in `_load_target_entities`.
- Refute one of three classes → that class drops from candidateFor; other two remain.
- Confirmed → draft/finding path; candidate stays reportable.
- `execute_test` with no signal marks the class refuted end-to-end.

---

## Phase 4 — precision thresholds + agent curation

### Files & changes
1. **Passive candidate thresholds/caps** in each injection adapter's `find_candidates`: raise the
   minimum score to emit a candidate; cap candidates per host/class (e.g. top-N by score) so a
   host can't produce 24 low-signal LFI candidates. Make caps configurable via args with sane
   defaults. Tighten the parameter-name/value heuristics (`classify_candidate`, ssrf/ssti/sql
   signal functions) to reduce false candidates.
2. **Agent curation tool** `workspace.curate_candidate(workspace_id, target, surface_selector,
   add=[classes], remove=[classes], reason)`:
   - Adds/removes classes on a surface `test_candidate` (creating the entity from a known
     endpoint/parameter if it doesn't exist yet), with justification recorded.
   - Lets the agent create precise candidates from normal observations instead of adapters
     blanketing every parameter.
   - Transport schema + dispatch + README + Implementation-Map entry.

### Regression tests
- Below-threshold parameter does not auto-become a candidate.
- Cap limits candidates per host/class.
- `curate_candidate(add=["sqli"])` creates/updates a surface test_candidate with candidateFor.

---

## Global guardrails (all phases)
- No DB / new report engine / RBAC engine / broad rewrite; keep changes small and legible.
- Two-phase normalization: parsers stay context-free; workspace-aware work in ingest.
- Benign markers agent-runnable; dangerous payloads operator + `confirm=true`.
- Retire = mark (isReportable/retired), never delete; workspace/agent data stays rich.
- Suppression/redaction only at the report boundary.
- One commit per phase (or per coherent sub-step); `bin/test` green is the gate.
- Update `docs/Version-Log.md` (local) after each landed step.
