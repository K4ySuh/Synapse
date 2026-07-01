# Synapse Layer Playbooks & Tool Surface

Grounded in the repo's `docs/Architecture.md`, `docs/Operations.md`, `docs/Reporting-Model.md`,
the committed `AGENTS.md`, and the registered tool names in
`synapse_mcp/transport/stdio_server.py`. Read the relevant section before driving that layer.
All active actions follow the two-gate approval flow in SKILL.md. Active tool wrappers default to
background `jobs.*` execution.

## Contents
1. Workspace, scope & evidence
2. Credentials & authentication storage
3. Background jobs
4. Burp, dumps & cleanup
5. Crawling & discovery
6. Recon profiles (ffuf / nuclei / nmap)
7. JavaScript intelligence
8. Authentication layer
9. Access-control layer (BOLA/BFLA/BOPLA)
10. Vulnerability candidate triage
11. Infrastructure & OSINT (nmap / Shodan)
12. Documentation & reports (tool list)

---

## 1. Workspace, scope & evidence
- `project.start` — initialize a scoped project, evidence folders, fingerprints, workspace.
- `scope.set` — persist authorized hosts/patterns/CIDRs/notes. Default **exact hosts**; wildcard
  `patterns` (`*.example.com`, `exact:api.example.com`) and `cidrs` only when authorized.
- `scope.check_target` — before any scoped active action.
- `workspace.add_target`, `workspace.ingest_data` — normalized target knowledge enters through
  ingestion, not as disconnected notes. Other workspace tools: `create`, `summary`,
  `prepare_target_context`, `create_finding`, `update_finding`, `mark_finding_reviewed`,
  `link_evidence_to_finding`, `promote_observation_to_finding`, `export_finding_context`,
  `delete`.
- `workspace.prepare_target_context` — compact context before planning; prefer over raw evidence.
- `evidence.log_event` (also `evidence.tail`, `evidence.host_context`, `evidence.init_project`) —
  record operator-reviewed milestones, assumptions, commands, approvals, decisions.
- `fingerprint.read_host` — recover prior host context before repeating analysis.

Findings: never create confirmed findings from unreviewed candidates — `workspace.create_finding`
/ promotion only after operator review. Keep evidence traceable (workspace ID, host/URL,
method+path, Burp history ID, request/response file, tool+profile, job ID, output path, approval
ID, finding/observation ID).

## 2. Credentials & authentication storage
References, never raw secrets. Ask approval before storing; bind to exact authorized hosts.
- `credentials.set(confirm=true)` — static reusable material.
- `credentials.set_auth_profile(confirm=true)` — approved form/JSON login recipes (default POST;
  GET requires explicit `allowCredentialInUrl=true`).
- `credentials.authenticate(confirm=true)` — obtain/refresh cookie credential.
- `credentials.set_browser_auth_profile(confirm=true)`, `credentials.browser_authenticate(confirm=true)`,
  `credentials.browser_auth_check_setup` — browser-assisted flows; run via worker subprocess,
  require approval, store only redacted profile/session metadata.
- `credentials.list`, `credentials.get` — redacted metadata. `credentials.validate_session`,
  `credentials.delete(confirm=true)`.
- Pass `credentialId` / auth-profile IDs to adapters; never embed secrets. For complex/multi-step
  logins, prefer redacted Burp references or manual cookie capture over fragile automation.

## 3. Background jobs
Long-running active adapters run through `jobs.*` by default. When a tool returns a `jobId`,
report the polling instruction and poll `jobs.status(jobId=...)` for completion, finalization,
workspace updates, evidence, and report paths. `jobs.list(activeOnly=true)`, `jobs.cancel`. Treat
MCP timeouts as recoverable: check `jobs.list` and poll before assuming failure. **Never rerun an
active job just because the client timed out.**

## 4. Burp, dumps & cleanup
Burp MCP for live state; Synapse dump tools for repeatable offline analysis (prefer dumps for bulk
triage — no extra traffic, reprocessable).
- `dumps.list` — dump paths.
- `sitemap.from_dump` — passive site map (pass `workspaceId` to update target state).
- `fingerprint.from_dump` — host fingerprints from traffic.
- `fingerprint.analyze_workspace` — refresh fingerprinting after crawl/sitemap/nmap/Shodan/notes.
- Cleanup is **inspect-first**: `cache.inspect_scope_data`, `cache.inspect_generated_artifacts`,
  then `cache.clean_out_of_scope(confirm=true)` / `cache.clean_generated_artifacts(confirm=true)`
  only after approval.

## 5. Crawling & discovery
- `crawler.crawl(confirm=true)` — only after approval, in-scope, bounded. Implemented default
  mode: `maxPages=200`, `maxDepth=6`, `requestTimeout=15`, `delayMillis=0`,
  `includeInScopeHosts=true`, `analyzeScripts=true`, `followGetForms=true`, `submitPostForms=false`.
  Follows links, navigation attrs, meta refreshes, JS route literals, and GET forms; does **not**
  submit POST forms. Runs in background by default — poll the `jobId`. Treat
  `sitemap_finding_candidate` observations as prioritized leads, not confirmed findings.
- `crawler.extended` — POST-form submission; requires a previous crawl, a `credentialId`, and
  `confirm=true`. Each submitted POST is recorded as evidence + a workspace action; sensitive
  admin-like forms are skipped by default.

## 6. Recon profiles (ffuf / nuclei / nmap)
Profile-backed active scanners share three profile IDs: `low_noise`, `medium`,
`pentest_aggressive`. Default to `medium` when unspecified; `low_noise` for quieter limits;
`pentest_aggressive` only with explicit approval for that profile.
- Inspect with `ffuf.profiles` / `nuclei.profiles` / `nmap.profiles`.
- Show the exact command and rationale with `*.build_command` before execution.
- Execute `*.run_profile(confirm=true)` only after approval, only in-scope. Pass `workspaceId` to
  route normalized output.
- If the operator names one tool, run only that tool after approval — do not add companion recon
  (nmap/ffuf/nuclei/crawl/Shodan) unless separately asked. Don't expose arbitrary scan shell
  commands; add a named profile for repeatable patterns instead.

### Default crawl/recon follow-up
After authorized crawl/recon: `jobs.list(activeOnly=true)` -> run approved profile ->
`jobs.status(jobId=...)` -> review `fingerprint.analyze_workspace` -> refresh
`perimeter.build_summary(refresh=true)` / `perimeter.render_report(refresh=true)` -> only then
suggest deeper technology/version validation.

## 7. JavaScript intelligence
`js.*` models heavy JS apps **without executing application JavaScript**:
`js.discover_assets`, `js.fetch_assets`, `js.analyze_static`, `js.normalize_endpoints`,
`js.build_app_model`, `js.render_app_map`, `js.capabilities`. Extracts API bases, endpoints,
methods, GraphQL/WebSockets, storage keys, auth/CSRF header names, route literals, object
identifiers.
- `js.fetch_assets` is the **only** JS tool that sends traffic — in-scope + approval required
  (unless the HTTP backend is disabled). Static analysis and normalization stay passive.
- JS-derived endpoints are stored `source="js_intelligence"`, `derived=true`, `inferred=true`,
  `observed=false`; keep `sourceAsset`, confidence, inference metadata intact. Treat as inferred
  until validated against observed traffic or approved active tests.

## 8. Authentication layer
Identify login portals, protected resources, auth boundaries, session indicators, credential
profiles, authenticated-vs-anonymous behavior, redirects-to-login, token/cookie/header
expectations. **A redirect is not success** — redirect-to-login is usually a denial/unauthenticated
boundary. Store reusable auth state via credential/profile tools and reference by ID.

## 9. Access-control layer (BOLA/BFLA/BOPLA)
Tools: `access_control.identify_objects`, `record_context`, `build_test_matrix`, `plan_tests`,
`execute_matrix_test`, `capabilities`. Workflow:
1. `identify_objects` — object types, identifier names, shapes, candidate endpoints. **Don't store
   raw object IDs by default.**
2. `record_context` — actor contexts (anonymous, normal users, admin, service). Include role, auth
   state, credential reference, expected access, owned object types.
3. `build_test_matrix` / `plan_tests` — candidate tests.
4. Review the plan with the operator.
5. `execute_matrix_test(confirm=true)` — only after explicit approval.

Conservative conclusions: distinguish expected vs observed access; confirmed broken access vs
candidates; do not treat redirects as success; record replay context, approval, status, evidence;
don't silently turn authenticated tests into anonymous unless the operator chose that. Prefer at
least one known-allowed baseline and one expected-denied comparison context.

## 10. Vulnerability candidate triage
Passive-first, plan before execute, approval for active traffic, candidate-until-reviewed. Tool
families:
- **SQLi** — `sqli.analyze_dump` (passive), `sqli.build_sqlmap_command`. Synapse does **not** run
  sqlmap; preflight before the operator runs an accepted command; high-risk OS/file/registry
  options blocked at generation.
- **XSS** — `xss.analyze_dump` (passive), `xss.generate_test_code` (manual/console payloads only;
  don't auto-execute).
- **SSRF** — `ssrf.analyze_workspace`, `ssrf.generate_test_plan` (no traffic). Don't probe
  metadata/localhost/private nets without explicit approval.
- **Open redirect** — `open_redirect.analyze_workspace`, `open_redirect.generate_test_plan` (no
  traffic). Don't combine with credential capture/phishing/token collection.
- **Command injection** — `command_injection.analyze_workspace`, `generate_test_plan`,
  `prepare_replay`, `execute_test`. Execution is limited to **one approved benign marker request**
  against an in-scope HTTP target.
- **SSTI / LFI/RFI / SSI** — `ssti.*`, `lfi.*`, `ssi.*` with `passive_analyze` / `plan_tests` /
  `prepare_replay` / `execute_test` / `capabilities`.

Prefer request-file or workspace-native testing so method/headers/body/cookies/routing are
preserved. **Do not escalate from benign validation to destructive exploitation** without a new
explicit request and approval.

## 11. Infrastructure & OSINT (nmap / Shodan)
`adapters/infra/` share the same scope/workspace/evidence/job model.
- **nmap** — `nmap.profiles`, `nmap.build_command`, `nmap.run_profile(confirm=true)`.
- **Shodan** — `shodan.company_queries` first for auditable passive pivots;
  `shodan.search_filters` / `shodan.search_facets` for query planning; host/domain/search/resolve/
  reverse/internetdb/target_summary/search_count tools. API-backed calls require `confirm=true`
  (external service, may consume credits). Runtime key only: set/inspect/clear the session key at
  runtime; **never store Shodan API keys** in config, evidence, notes, or reports. Pass
  `workspaceId`/`ingest=true` to normalize results into workspace context before drawing
  conclusions.

## 12. Documentation & reports (tool list)
See `references/reporting.md` for the model. Tools: `documentation.build_report_context`,
`build_workspace_report_context`, `build_layer_report_context`, `render_workspace_report`
(consolidated two-view report), `render_layer_report`, `render_markdown`,
`render_assessment_summary`, `build_finding_context`, `build_finding_draft`, `build_evidence_pack`,
`summarize_coverage`, `list_layers`, `list_templates`, `export_json`. Perimeter layer:
`perimeter.analyze_workspace`, `perimeter.build_summary`, `perimeter.render_report`.
