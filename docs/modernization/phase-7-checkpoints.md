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
| 7R7 | In progress | 7R7.1 `af16cbc`; 7R7.2 comparison recorded, persistence/restart pending | 7R7.2 continuation |

## Latest checkpoint record

```yaml
task: 7R7
checkpoint: 7R7.2
status: pending
review_base: 8134673a386ad00eed786d3d3ba841f00fcb28de
implementation_commit: null
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
  - The comparison record fixes six fictional cases, a 120-call or 350000 non-cached-token budget, matched helper/method sessions, and one required restart; runtime logs and workspaces remain gitignored under DATA.
  - Both routes stated all six expected conclusions with correct case evidence and no unsupported impact claim. The selected method traversed all 220 C5 endpoints and made no material analysis-accuracy or coverage regression.
  - The retained helper persisted eight confirmed findings, five unnecessary for the fixed C3/C6 questions. The selected method persisted none: four useful C1/C4/C5/C6 outputs are omitted because authority/contract/idempotency failures consumed the bounded run.
  - The explicit configuration helper remains the operational fallback for this family. The method-first default for other families, all 174 actions, modern-direct, eleven-operation modern-compact, and frozen legacy fixtures remain unchanged.
  - No live selected-method restart result exists. Two deterministic fresh-process regressions still prove method ID/digest, evidence, uncertainty, and candidate identity recovery; they are not substituted for the missing client result.
checks:
  - command: seven bounded codex exec sessions over the fixed phase7-helper and phase7-method SQLite-v2 workspaces
    result: >-
      live but incomplete; Codex CLI 0.154.0, gpt-daybreak-blue-latest High,
      mcp 2.0.0, protocol 2025-06-18, Synapse 0.6.0b0 at c614ddb,
      modern-compact stdio, Python 3.14.7, one agent; 83 MCP calls, 984 seconds,
      2577869 input tokens including 2279172 cached, 30003 output tokens,
      16460 reasoning-output tokens, and 328700 budgeted non-cached input plus
      output; exact route scores and digests are in phase-7-client-comparison.md
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
      helper workspace contains exactly eight confirmed findings with correct
      C1/C3/C5/C6 evidence; method workspace contains 225 seeded endpoints,
      zero contribution receipts, zero findings, and zero method-attributed
      analyses
  - command: PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_modernization_docs test_documentation -q
    result: pass; 44 modernization and primary documentation tests
  - command: git diff --check
    result: pass; final tracked documentation diff has no whitespace errors
skipped_checks: >-
  The selected-method live C6 restart, second consumer, report/bundle recovery,
  full core, full modern, distribution, skill validators, inventory generators,
  and active integration testing were not run. 7R7.1 already recorded the
  release suites and installed artifacts; retired completed-phase gates remain
  retired. No target traffic, browser authentication, credential use, scanner,
  third-party API, or unauthorized action ran.
known_issue: >-
  The live comparison does not meet 7R7.2 persistence/restart acceptance. C1
  analysis was accurate but its contribution encountered a low risk ceiling,
  a forbidden legacy metadata field, then an idempotency fingerprint conflict.
  C4-C6 analyses were accurate, including complete C5 traversal, but the grant
  expired during an interrupted interval before their contribution. With only
  21300 budgeted tokens left, no fresh model session or C6 restart was started.
  The selected route used more calls and operator corrections than the helper;
  its five-finding noise reduction cannot be called a success until useful
  output persists and recovers. Historical pre-7R1.1 duplicate candidates
  still require operator review.
next_checkpoint: 7R7.2
next_action: >-
  Declare a new bounded continuation; preflight a low-risk grant whose lifetime
  covers the run; use contract-exact outer workspace.ingest_data arguments and
  fresh idempotency keys; persist only unfinished C1, C4, C5, and C6 selected-
  method analyses; then start one fresh client/server process and recover C6
  evidence, limitations, method ID, and digest. Do not repeat completed helper
  cases, alter discovery ranking, restore retired gates, or start another
  modernization phase. After this passes, follow the documented Beta testing
  order through setup, import, context, method contribution, restart/consumer,
  report/bundle recovery, and separately authorized real integration testing.
dirty_worktree: >-
  Before 7R7.2, only the pre-existing untracked review and source-plan documents
  remained: Synapse-Beta-Final-Review-2026-09-17.md and
  Synapse-Phase-7-Implementation-Tasks-2026-09-17.md. They remain untouched.
```
