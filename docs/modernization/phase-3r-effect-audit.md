# Phase 3R canonical effect audit

Date: 2026-08-24
Compared predecessor: `61797d1d530fec9ddce49ad3a37f3d6353f9cbb4`

## Source of truth

`effect_declarations.py` is the implementation-audited, descriptor-owned
authority source. `action_inventory.json` is its generated documentation view:
all 174 actions have explicit traffic, local-write domain, local-change,
local-destruction, remote-state-change, credential-use, secret-use, and replay-
safety values, plus an audit group and rationale. Labels, scope requirements,
input field names, and task mode are no longer used to infer authorization.

The observed-effect corpus instruments filesystem mutation, subprocess launch,
socket and HTTP routes, credential access, and job control. Observed behavior
must be a subset of the declaration. The corpus is deliberately fixed and
offline; it proves its exercised paths, while each declaration remains the
conservative implementation audit for all branches.

## Semantic changes from the removed inference

The following is the exhaustive per-dimension delta from the predecessor's
generated inference. An action listed under several headings changed in every
listed dimension.

- `traffic` (2): `cve.plan_tests`, `shodan.company_queries`.
- `remoteStateChange` (3): `js.fetch_assets`, `nmap.run_profile`,
  `fingerprint.probe_versions`.
- `credentialUse` (11): `cve.correlate`, `access_control.record_context`,
  `shodan.host`, `shodan.domain`, `shodan.resolve`, `shodan.reverse`,
  `shodan.search_count`, `shodan.search`, `shodan.search_facets`,
  `shodan.search_filters`, `shodan.target_summary`.
- `secretUse` (12): `jwt.analyze` and all 11 `credentialUse` actions above.
- `localDestruction` (4): `jobs.status`, `credentials.delete`,
  `cve.session_key.clear`, `shodan.session_key.clear`.
- `localChange` (19): `jobs.status`, `perimeter.analyze_workspace`,
  `perimeter.build_summary`, `documentation.build_layer_report_context`,
  `documentation.build_workspace_report_context`,
  `documentation.plan_scope_groups`, `documentation.prepare_validation_batch`,
  `workspace.export_finding_context`, `sqli.build_sqlmap_command`, `jwt.analyze`,
  `cve.plan_tests`, `js.discover_assets`, `js.build_app_model`,
  `sitemap.from_dump`, `ffuf.build_command`, `nuclei.build_command`,
  `nmap.build_command`, `shodan.company_queries`, `fingerprint.from_dump`.
- `replaySafety` (23): `jobs.status`, `perimeter.analyze_workspace`,
  `perimeter.build_summary`, `documentation.build_layer_report_context`,
  `documentation.build_workspace_report_context`,
  `documentation.plan_scope_groups`, `documentation.prepare_validation_batch`,
  `documentation.render_workspace_report_batches`,
  `workspace.export_finding_context`, `sqli.build_sqlmap_command`, `jwt.analyze`,
  `cve.session_key.clear`, `cve.plan_tests`, `js.discover_assets`,
  `js.build_app_model`, `js.render_app_map`, `sitemap.from_dump`,
  `ffuf.build_command`, `nuclei.build_command`, `nmap.build_command`,
  `shodan.session_key.clear`, `shodan.company_queries`,
  `fingerprint.from_dump`.
- `localWrites` (105): `jobs.status`, `perimeter.analyze_workspace`,
  `perimeter.build_summary`, `perimeter.render_report`,
  `documentation.build_layer_report_context`,
  `documentation.build_workspace_report_context`,
  `documentation.plan_scope_groups`, `documentation.prepare_validation_batch`,
  `documentation.render_workspace_report_batches`,
  `documentation.render_markdown`, `documentation.render_layer_report`,
  `documentation.render_workspace_report`,
  `documentation.render_assessment_summary`, `documentation.export_json`,
  `scope.set`, `project.start`, `workspace.create`, `workspace.add_target`,
  `workspace.ingest_data`, `workspace.delete`, `workspace.create_finding`,
  `workspace.update_finding`, `workspace.promote_observation_to_finding`,
  `workspace.link_evidence_to_finding`, `workspace.mark_finding_reviewed`,
  `social.approve_pretext_candidate`, `purple_team.mark_detection_outcome`,
  `workspace.set_entity_reportable`, `workspace.record_candidate_validation`,
  `workspace.curate_candidate`, `workspace.export_finding_context`,
  `cache.clean_out_of_scope`, `cache.clean_generated_artifacts`,
  `sqli.analyze_workspace`, `sqli.analyze_dump`, `sqli.build_sqlmap_command`,
  `xss.analyze_workspace`, `xss.analyze_dump`, `xss.execute_test`,
  `csrf.analyze_workspace`, `cors.analyze_workspace`, `cors.execute_test`,
  `insecure_deser.analyze_workspace`, `xxe.analyze_workspace`,
  `xxe.execute_test`, `graphql.analyze_workspace`, `graphql.execute_test`,
  `tls_posture.analyze_workspace`, `jwt.analyze`,
  `headers_cookies.analyze_workspace`, `spec_import.import_spec`,
  `ssrf.analyze_workspace`, `ssrf.execute_test`,
  `open_redirect.analyze_workspace`, `open_redirect.execute_test`,
  `command_injection.analyze_workspace`, `command_injection.execute_test`,
  `cve.session_key.set`, `cve.session_key.clear`, `cve.correlate`,
  `cve.plan_tests`, `cve.execute_test`, `ssti.passive_analyze`,
  `ssti.execute_test`, `lfi.passive_analyze`, `lfi.execute_test`,
  `ssi.passive_analyze`, `ssi.execute_test`,
  `access_control.identify_objects`, `access_control.record_context`,
  `access_control.build_test_matrix`, `access_control.execute_matrix_test`,
  `js.discover_assets`, `js.fetch_assets`, `js.analyze_static`,
  `js.normalize_endpoints`, `js.build_app_model`, `js.render_app_map`,
  `sitemap.from_dump`, `crawler.crawl`, `crawler.extended`, `ffuf.build_command`,
  `ffuf.run_profile`, `nuclei.build_command`, `nuclei.run_profile`,
  `nmap.build_command`, `nmap.run_profile`, `shodan.session_key.set`,
  `shodan.session_key.clear`, `shodan.host`, `shodan.internetdb`,
  `shodan.domain`, `shodan.resolve`, `shodan.reverse`, `shodan.search_count`,
  `shodan.search`, `shodan.search_facets`, `shodan.search_filters`,
  `shodan.target_summary`, `shodan.company_queries`, `evidence.log_event`,
  `evidence.init_project`, `fingerprint.from_dump`,
  `fingerprint.analyze_workspace`, `fingerprint.probe_versions`.

## Authority boundary corrections

Modern model input cannot authorize external output. Absolute output paths must
be beneath trusted Synapse artifact roots, and `allowExternalOutput=true` is
rejected before Registry dispatch. The field remains only in the frozen legacy
input contract.

Facade authority fields are reserved at their defined outer control-plane
positions. Nested application data named `profile`, `principal`, `grant`, or
`authorization` is passed through canonical action validation and cannot alter
the trusted `FacadeCallContext`, authority session, selected grant, request
state, or execution profile.
