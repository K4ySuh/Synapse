# Phase 7R6.1 operation transition map

This is a review map of the **174 built-in action IDs** in the frozen
[Action Registry inventory](../../MCPS/Synapse-MCP/synapse_mcp/app/actions/action_inventory.json),
joined by namespace to the six-pack
[capability ownership snapshot](capability-pack-ownership.json), then checked
against the implementation under `synapse_mcp/adapters/` and `synapse_mcp/core/`.
The live Action Registry and selected startup packs remain authoritative for
callable inputs, effects, availability, policy, and dispatch. This document is
methodology guidance, not a second action registry or an execution preference.
It adds no action or method tool.

Each operation has one **primary** category. `D` is deterministic parsing,
extraction, normalization, or projection of already supplied data. `H` is
heuristic interpretation, candidate scoring, or question-specific test
planning. `C` prepares or performs bounded command, HTTP, authentication, or
provider execution; command builders and manual replay constructors are here
although they send no traffic themselves. `L` is lifecycle, persistence,
metadata, discovery, job, credential, or report support. A primary category
does not erase secondary work inside an operation. For example, a heuristic
may parse saved input and persist candidate output, while an execution adapter
may parse and ingest its response. The action's actual effects and authority
requirements must be read from its live descriptor.

## Heuristic interpretation: optional question-specific helpers

These operations remain callable by explicit action selection. The method
column identifies the relevant web question, not an automatic call. Review
saved evidence first; use a helper only when its specific signal or plan would
answer an open question. Existing analyzers may ingest candidates by default,
so inspect the live `ingest` argument when present, select `false` for
exploration, and make a separate evidence-backed `contribution.v1` version 1.1
submission only when the conclusion is worth keeping. Do not bulk ingest
heuristic output. The eight optional packages live under
[`skills/codex/web-methods/`](../../skills/codex/web-methods/); the main web
method and CVE intelligence remain separate entry skills.

| Owned pack | Canonical action ID | Method package | Implementation |
| --- | --- | --- | --- |
| `infra` | `perimeter.analyze_workspace` | `synapse-web-configuration` | `core/perimeter.py` |
| `infra` | `perimeter.build_summary` | `synapse-web-configuration` | `core/perimeter.py` |
| `infra` | `perimeter.render_report` | `synapse-web-configuration` | `core/perimeter.py` |
| `web` | `sqli.analyze_workspace` | `synapse-web-server-input` | `adapters/web/sqlmap_adapter.py; sqlmap_analysis.py` |
| `web` | `sqli.analyze_dump` | `synapse-web-server-input` | `adapters/web/sqlmap_adapter.py; sqlmap_analysis.py` |
| `web` | `sqli.build_sqlmap_command` | `synapse-web-server-input` | `adapters/web/sqlmap_adapter.py; sqlmap_analysis.py` |
| `web` | `xss.analyze_workspace` | `synapse-web-browser-input` | `adapters/web/xss_adapter.py; xss_analysis.py` |
| `web` | `xss.analyze_dump` | `synapse-web-browser-input` | `adapters/web/xss_adapter.py; xss_analysis.py` |
| `web` | `xss.generate_test_code` | `synapse-web-browser-input` | `adapters/web/xss_adapter.py; xss_analysis.py` |
| `web` | `csrf.analyze_workspace` | `synapse-web-auth-session` | `adapters/web/csrf.py` |
| `web` | `csrf.generate_test_plan` | `synapse-web-auth-session` | `adapters/web/csrf.py` |
| `web` | `cors.analyze_workspace` | `synapse-web-configuration` | `adapters/web/cors.py` |
| `web` | `cors.generate_test_plan` | `synapse-web-configuration` | `adapters/web/cors.py` |
| `web` | `insecure_deser.analyze_workspace` | `synapse-web-structured-data` | `adapters/web/insecure_deser.py` |
| `web` | `xxe.analyze_workspace` | `synapse-web-fetch-file-xml` | `adapters/web/xxe.py` |
| `web` | `xxe.generate_test_plan` | `synapse-web-fetch-file-xml` | `adapters/web/xxe.py` |
| `web` | `graphql.analyze_workspace` | `synapse-web-structured-data` | `adapters/web/graphql.py` |
| `web` | `graphql.generate_test_plan` | `synapse-web-structured-data` | `adapters/web/graphql.py` |
| `web` | `tls_posture.analyze_workspace` | `synapse-web-configuration` | `adapters/web/tls_posture.py` |
| `web` | `jwt.analyze` | `synapse-web-auth-session` | `adapters/web/jwt_analysis.py` |
| `web` | `headers_cookies.analyze_workspace` | `synapse-web-configuration` | `adapters/web/headers_cookies.py` |
| `web` | `ssrf.analyze_workspace` | `synapse-web-fetch-file-xml` | `adapters/web/ssrf_adapter.py` |
| `web` | `ssrf.generate_test_plan` | `synapse-web-fetch-file-xml` | `adapters/web/ssrf_adapter.py` |
| `web` | `open_redirect.analyze_workspace` | `synapse-web-browser-input` | `adapters/web/open_redirect_adapter.py` |
| `web` | `open_redirect.generate_test_plan` | `synapse-web-browser-input` | `adapters/web/open_redirect_adapter.py` |
| `web` | `command_injection.analyze_workspace` | `synapse-web-server-input` | `adapters/web/command_injection_adapter.py` |
| `web` | `command_injection.generate_test_plan` | `synapse-web-server-input` | `adapters/web/command_injection_adapter.py` |
| `intelligence` | `cve.correlate` | `synapse-web-configuration` | `adapters/web/cve_intel.py` |
| `intelligence` | `cve.plan_tests` | `synapse-web-configuration` | `adapters/web/cve_intel.py` |
| `web` | `ssti.passive_analyze` | `synapse-web-server-input` | `adapters/web/ssti.py` |
| `web` | `ssti.plan_tests` | `synapse-web-server-input` | `adapters/web/ssti.py` |
| `web` | `lfi.passive_analyze` | `synapse-web-fetch-file-xml` | `adapters/web/lfi_rfi.py` |
| `web` | `lfi.plan_tests` | `synapse-web-fetch-file-xml` | `adapters/web/lfi_rfi.py` |
| `web` | `ssi.passive_analyze` | `synapse-web-server-input` | `adapters/web/ssi.py` |
| `web` | `ssi.plan_tests` | `synapse-web-server-input` | `adapters/web/ssi.py` |
| `web` | `access_control.identify_objects` | `synapse-web-access-control` | `adapters/web/access_control.py` |
| `web` | `access_control.build_test_matrix` | `synapse-web-access-control` | `adapters/web/access_control.py` |
| `web` | `access_control.plan_tests` | `synapse-web-access-control` | `adapters/web/access_control.py` |
| `web` | `js.analyze_static` | `synapse-web-browser-input` | `adapters/web/js_intel.py` |
| `infra` | `fingerprint.from_dump` | `synapse-web-configuration` | `core/fingerprint.py` |
| `infra` | `fingerprint.analyze_workspace` | `synapse-web-configuration` | `core/fingerprint.py` |

`js.analyze_static` primarily extracts routes, inputs, libraries, and signals
from saved JavaScript; its signal labels are heuristic. The browser-input
package is the closest signal interpretation boundary. For route inventory,
continue the main web method; choose another method only when the extracted
request or trust boundary raises its question. `fingerprint.from_dump` and
`fingerprint.analyze_workspace` infer technology identity from saved content;
`perimeter.analyze_workspace` classifies applications and candidate exposure.
The configuration package handles web deployment evidence. When the question
becomes versioned vulnerability applicability, hand the saved component and
uncertainty to `synapse-cve-intelligence`. `cve.correlate` combines this
interpretation with approved third-party provider execution; its version and
deployment claims belong in CVE intelligence. The configuration mapping marks
the related web surface and never replaces that CVE method or provider gate.
`perimeter.build_summary` and `perimeter.render_report` normally project
stored data, but `refresh=true` or a missing cache can call
`perimeter.analyze_workspace`; treat those invocations as heuristic runs.
`sqli.build_sqlmap_command` returns an exact command when given only command
options, but its workspace path scores all parameters and, by default, marks
selected candidates as under testing. Do not use that path as a default
extraction or harmless planning shortcut. `project.start` is lifecycle support;
its optional dump fingerprint branch invokes the mapped fingerprint heuristic.
`documentation.summarize_coverage` projects recorded adapter coverage and
may label unrun legacy analyzers as untested. Those labels are historical
coverage metadata, not instructions to run every analyzer. The current method
question and saved evidence determine which coverage gap matters.

The business-logic package has no dedicated legacy heuristic action. It uses
saved workflow and state evidence, selected deterministic helpers, and typed
method contributions. Several other packages also interpret saved data without
requiring the mapped helper.

## Other operations by primary category

Every suffix below is an individual canonical operation under the namespace in
its row. The pack column comes from capability ownership; for example,
`web` / `spec_import` / `import_spec` means `spec_import.import_spec`. This
compact notation lists every non-heuristic built-in ID once without copying
schemas, effects, or action descriptions.

| Category | Owned pack | Namespace | Operation suffixes |
| --- | --- | --- | --- |
| D | `reporting` | `documentation` | `build_report_context`, `build_layer_report_context`, `build_workspace_report_context`, `build_finding_context`, `build_evidence_pack`, `summarize_coverage` |
| D | `core` | `workspace` | `prepare_target_context`, `summary`, `export_finding_context` |
| D | `web` | `spec_import` | `import_spec` |
| D | `web` | `js` | `discover_assets`, `normalize_endpoints`, `build_app_model`, `render_app_map` |
| D | `web` | `sitemap` | `from_dump` |
| D | `intelligence` | `shodan` | `company_queries` |
| D | `core` | `evidence` | `host_context` |
| D | `infra` | `fingerprint` | `read_host` |
| C | `core` | `credentials` | `authenticate`, `browser_authenticate`, `validate_session` |
| C | `web` | `xss` | `execute_test` |
| C | `web` | `cors` | `execute_test` |
| C | `web` | `xxe` | `execute_test` |
| C | `web` | `graphql` | `execute_test` |
| C | `web` | `ssrf` | `execute_test` |
| C | `web` | `open_redirect` | `execute_test` |
| C | `web` | `command_injection` | `prepare_replay`, `execute_test` |
| C | `intelligence` | `cve` | `prepare_replay`, `execute_test` |
| C | `web` | `ssti` | `prepare_replay`, `execute_test` |
| C | `web` | `lfi` | `execute_test` |
| C | `web` | `ssi` | `prepare_replay`, `execute_test` |
| C | `web` | `access_control` | `execute_matrix_test` |
| C | `web` | `js` | `fetch_assets` |
| C | `web` | `crawler` | `crawl`, `extended` |
| C | `web` | `ffuf` | `build_command`, `run_profile` |
| C | `web` | `nuclei` | `build_command`, `run_profile` |
| C | `infra` | `nmap` | `build_command`, `run_profile` |
| C | `intelligence` | `shodan` | `host`, `internetdb`, `domain`, `resolve`, `reverse`, `search_count`, `search`, `search_facets`, `search_filters`, `target_summary` |
| C | `infra` | `fingerprint` | `probe_versions` |
| L | `core` | `jobs` | `list`, `status`, `cancel` |
| L | `core` | `adapters` | `list`, `capabilities` |
| L | `reporting` | `documentation` | `list_templates`, `list_layers`, `plan_scope_groups`, `prepare_validation_batch`, `render_workspace_report_batches`, `build_finding_draft`, `render_markdown`, `render_layer_report`, `render_workspace_report`, `render_assessment_summary`, `export_json` |
| L | `core` | `scope` | `set`, `check_target` |
| L | `core` | `project` | `start` |
| L | `core` | `workspace` | `create`, `add_target`, `ingest_data`, `delete`, `create_finding`, `update_finding`, `promote_observation_to_finding`, `link_evidence_to_finding`, `mark_finding_reviewed`, `set_entity_reportable`, `record_candidate_validation`, `curate_candidate` |
| L | `purple` | `social` | `approve_pretext_candidate` |
| L | `purple` | `purple_team` | `mark_detection_outcome` |
| L | `core` | `credentials` | `set`, `list`, `set_auth_profile`, `set_browser_auth_profile`, `browser_auth_check_setup`, `get`, `delete` |
| L | `core` | `dumps` | `list` |
| L | `core` | `cache` | `inspect_scope_data`, `clean_out_of_scope`, `inspect_generated_artifacts`, `clean_generated_artifacts` |
| L | `web` | `spec_import` | `capabilities` |
| L | `web` | `headers_cookies` | `capabilities` |
| L | `web` | `jwt` | `capabilities` |
| L | `web` | `csrf` | `capabilities` |
| L | `web` | `cors` | `capabilities` |
| L | `web` | `insecure_deser` | `capabilities` |
| L | `web` | `xxe` | `capabilities` |
| L | `web` | `graphql` | `capabilities` |
| L | `web` | `tls_posture` | `capabilities` |
| L | `intelligence` | `cve` | `capabilities`, `sources`, `set_source_endpoint`, `reset_source_endpoint`, `session_key.set`, `session_key.clear`, `session_key.status` |
| L | `web` | `ssti` | `capabilities` |
| L | `web` | `lfi` | `capabilities` |
| L | `web` | `ssi` | `capabilities` |
| L | `web` | `access_control` | `capabilities`, `record_context` |
| L | `web` | `js` | `capabilities` |
| L | `web` | `ffuf` | `profiles` |
| L | `web` | `nuclei` | `profiles` |
| L | `infra` | `nmap` | `profiles` |
| L | `intelligence` | `shodan` | `session_key.set`, `session_key.clear`, `session_key.status` |
| L | `core` | `evidence` | `log_event`, `tail`, `init_project` |

`workspace.ingest_data` is `L` because the public operation commits canonical
workspace and evidence state. Its source-specific parsers are deterministic
suboperations; `contribution.v1` version 1.1 is the method-result route.
`spec_import.import_spec`, `sitemap.from_dump`, `js.discover_assets`,
`js.normalize_endpoints`, and existing output parsers remain useful without a
heuristic candidate run. Report builders and `context.query` project saved
truth; compact facade operations are not separate Registry actions.

Execution integrations, including `cve.correlate`'s provider phase, still use
the existing Registry effect, scope, authority, dispatch, job, outcome, and
evidence path. Optional methodology selection cannot grant authority, alter
capability-pack ownership, or change whether an action is reachable. Preserve
legacy and modern action identities. Use live `capabilities.search` and
`actions.describe` before a concrete helper call; this map does not prescribe
arguments or a sequence of calls.

No current test or operator record demonstrates that modern discovery ranking
must change for this transition. Ranking changes are therefore deferred to the
bounded 7R7 client exercise. If that exercise supplies concrete evidence, use
only an additive preference with an explicit override; do not hide actions,
change pack selection, or rewrite frozen legacy descriptions and fixtures.
