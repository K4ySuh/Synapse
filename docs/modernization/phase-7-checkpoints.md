# Phase 7 Beta checkpoint ledger

The reviewed Beta base is `8134673a386ad00eed786d3d3ba841f00fcb28de`
on branch `Beta`. It is also the actual branch HEAD at the 7R0.1 baseline, so
there are no subsequent implementation commits to reassess. Phase 6 remains
complete; its [ledger](phase-6-checkpoints.md) and
[direct-client exercise](phase-6-client-exercise.md) are historical evidence,
not gates to rerun for each Phase 7 checkpoint.

| Task | Status | Checkpoints | Next step |
| --- | --- | --- | --- |
| 7R0 | Complete | 7R0.1 `bcddb09` | 7R1.1 |
| 7R1 | Complete | 7R1.1 `750e261`; 7R1.2 `a69db92`; 7R1.3 `526a644` | 7R2.1 |
| 7R2 | Complete | 7R2.1 `1207fa9` + `bdabeb2`; 7R2.2 `7dd5ef8` | 7R3.1 |
| 7R3 | Complete | 7R3.1 `5194342`; 7R3.2 `90b5618` | 7R4.1 |
| 7R4 | Complete | 7R4.1 `987a567`; 7R4.2 `a190e1b` | 7R5.1 |
| 7R5 | Complete | 7R5.1 `ca32158`; 7R5.2 `b2f1259` + `b9b026a` + `4629982`; 7R5.3 `d95c043` | 7R6.1 |
| 7R6 | Complete | 7R6.1 `7e0b6b4`; 7R6.2 `c67df23` | 7R7.1 |
| 7R7 | Complete | 7R7.1 `af16cbc`; 7R7.2 initial record `87f42a0` + completion `c86c263` | Beta testing |

## Latest checkpoint record

```yaml
task: 7R7
checkpoint: 7R7.2
status: complete
review_base: 8134673a386ad00eed786d3d3ba841f00fcb28de
implementation_commit: c86c263
branch: Beta
changed_files:
  - CHANGELOG.md
  - docs/Version-Log.md
  - docs/modernization/README.md
  - docs/modernization/phase-7-checkpoints.md
  - docs/modernization/phase-7-client-comparison.md
  - docs/modernization/phase-7-status.md
contract_changes:
  - No application, Registry, authority, storage, migration, protocol, generated schema, capability-pack, JSON-v1, legacy, or discovery-ranking contract changed.
  - The comparison record fixes six fictional cases, an initial 120-call or 350000 non-cached-token budget, a separate 36-call or 180000-token continuation, matched helper/method sessions, and one required restart; runtime logs and workspaces remain gitignored under DATA.
  - Both routes stated all six expected conclusions with correct case evidence and no unsupported impact claim. The selected method traversed all 220 C5 endpoints and made no material analysis-accuracy or coverage regression.
  - The retained helper persisted eight confirmed findings, five unnecessary for the fixed C3/C6 questions. The continuation persisted the four useful selected-method C1/C4/C5/C6 outputs at revisions 47, 54, 61, and 68 with exact evidence and method attribution.
  - A fresh live client/server process recovered the C6 conclusion, evidence, limitation, method ID, and digest in three read-only calls without recreating the contribution.
  - The explicit configuration helper remains a practical fallback during broader Beta testing because the selected route needed corrections. The method-first default for other families, all 174 actions, modern-direct, eleven-operation modern-compact, and frozen legacy fixtures remain unchanged.
checks:
  - command: seven bounded codex exec sessions over the fixed phase7-helper and phase7-method SQLite-v2 workspaces
    result: >-
      live but incomplete; Codex CLI 0.154.0, gpt-daybreak-blue-latest High,
      mcp 2.0.0, protocol 2025-06-18, Synapse 0.6.0b0 at c614ddb,
      modern-compact stdio, Python 3.14.7, one agent; 83 MCP calls, 984 seconds,
      2577869 input tokens including 2279172 cached, 30003 output tokens,
      16460 reasoning-output tokens, and 328700 budgeted non-cached input plus
      output; exact route scores and digests are in phase-7-client-comparison.md
  - command: four bounded codex exec continuation sessions over phase7-method, including one fresh client/server restart
    result: >-
      pass after two pre-dispatch corrections; 26 MCP calls, 853690 input tokens
      including 731743 cached, 12483 output tokens, 6846 reasoning-output
      tokens, and 134430 budgeted non-cached input plus output. One denied
      jobs.list preflight and one malformed contribution envelope made no state
      change. Four contract-exact writes returned distinct receipts and
      revisions 47/54/61/68; a fresh process recovered C6 in three read-only
      calls with no contribution.
  - command: >-
      PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests
      .venv/bin/python -m unittest
      test_workspace_ingestion.WorkspaceIngestionTests.test_curated_candidate_lifecycle_keeps_one_identity_across_stores_and_restart
      test_contributions.ContributionContractTests.test_retry_is_bound_to_normalized_target_without_cross_target_writes
      test_context_compiler.ContextCompilerTests.test_saved_entity_pages_are_complete_query_bound_and_revision_consistent
      test_context_compiler.ContextCompilerTests.test_knowledge_state_is_not_the_storage_lifecycle
      test_contributions.ContributionContractTests.test_observation_contribution_does_not_decode_unrelated_target_entities
      test_workspace_ingestion.WorkspaceIngestionTests.test_relation_sync_updates_only_changed_sources_and_resolves_forward_references
      test_contribution_method_recovery.ContributionMethodRecoveryTests.test_candidate_contrary_inconclusive_retry_and_process_restart
      test_contribution_method_recovery.ContributionMethodRecoveryTests.test_web_cve_web_method_refs_recover_after_process_restart -v
    result: >-
      partial selector failure; five intended tests passed and three stale
      class selectors raised unittest loader errors without executing
  - command: >-
      PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests
      .venv/bin/python -m unittest
      test_workspace_ingestion.CurateCandidateTests.test_curated_candidate_lifecycle_keeps_one_identity_across_stores_and_restart
      test_contributions.ContributionTests.test_retry_is_bound_to_normalized_target_without_cross_target_writes
      test_contributions.ContributionTests.test_observation_contribution_does_not_decode_unrelated_target_entities -v
    result: pass; the three corrected selectors passed in 0.230 seconds
  - command: sqlite3 -readonly comparison workspace inspection
    result: >-
      before the continuation, the helper workspace contained exactly eight
      confirmed findings with correct C1/C3/C5/C6 evidence and the method
      workspace contained 225 seeded endpoints with no contributions. Live MCP
      receipts and restart context now verify four method-attributed analyses.
  - command: PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_modernization_docs test_documentation -q
    result: pass; 44 modernization and primary documentation tests
  - command: git diff --check
    result: pass; final tracked documentation diff has no whitespace errors
skipped_checks: >-
  A distinct second consumer, report/bundle recovery, full core, full modern,
  distribution, skill validators, inventory generators, and active integration
  testing were not rerun. 7R7.1 already recorded the release suites and
  installed artifacts; retired completed-phase gates remain retired. No target
  traffic, browser authentication, credential use, scanner, third-party API,
  or unauthorized action ran.
known_issue: >-
  The selected route needed one authority correction and one contribution-
  envelope correction in the continuation, after the initial run's earlier
  authority, contract, idempotency, and expiry failures. The helper therefore
  remains a practical fallback for this configuration family during broader
  Beta testing. Historical pre-7R1.1 duplicate candidates still require
  operator review.
next_checkpoint: Beta testing
next_action: >-
  Follow the documented Beta order through fresh setup, supplied-data import,
  context traversal, method contribution, restart/second consumer,
  report/bundle recovery, and separately authorized real integration testing.
  Do not repeat completed helper cases, alter discovery ranking, restore
  retired gates, or start another modernization phase.
dirty_worktree: >-
  Before 7R7.2, only the pre-existing untracked review and source-plan documents
  remained: Synapse-Beta-Final-Review-2026-09-17.md and
  Synapse-Phase-7-Implementation-Tasks-2026-09-17.md. They remain untouched.
```
