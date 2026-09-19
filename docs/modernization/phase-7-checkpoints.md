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
| 7R3 | In progress | 7R3.1 `5194342`; 7R3.2 pending | 7R3.2 |
| 7R4 | Pending | 7R4.1–7R4.2 pending | After 7R0; work serially after 7R3 |
| 7R5 | Pending | 7R5.1–7R5.3 pending | After 7R3 and 7R4 |
| 7R6 | Pending | 7R6.1–7R6.2 pending | After 7R3–7R5 |
| 7R7 | Pending | 7R7.1–7R7.2 pending | After 7R1–7R6 |

## Latest checkpoint record

```yaml
task: 7R3
checkpoint: 7R3.1
status: complete
review_base: 8134673a386ad00eed786d3d3ba841f00fcb28de
implementation_commit: 5194342ebb44fe8491e4f9530e66f4c6bcabc071
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/README.md
  - MCPS/Synapse-MCP/synapse_mcp/app/actions/registry.py
  - MCPS/Synapse-MCP/synapse_mcp/app/context.py
  - MCPS/Synapse-MCP/synapse_mcp/core/adapters/results.py
  - MCPS/Synapse-MCP/synapse_mcp/core/entity_merge.py
  - MCPS/Synapse-MCP/synapse_mcp/core/workspace.py
  - MCPS/Synapse-MCP/synapse_mcp/state/runtime.py
  - MCPS/Synapse-MCP/tests/test_contributions.py
  - docs/Architecture.md
  - docs/Contribution-Contract.md
  - docs/Implementation-Map.md
  - docs/Operations.md
  - docs/modernization/phase-7-checkpoints.md
  - docs/modernization/phase-7-status.md
contract_changes:
  - The existing contribution.v1 source and workspace.ingest_data Registry action accept a strict schemaVersion 1.1 envelope with typed candidate/coverage-gap analyses. The 1.0 envelope class and rawDataSchema remain unchanged; actions.describe adds acceptedVersions and rawDataSchemas and the receipt schema permits 1.0 or 1.1.
  - A typed analysis carries stable HTTP(S) surface coordinates, candidate class where relevant, inferred/reported knowledge state, bounded confidence/reason, separate supporting and contrary evidence IDs, optional method ID plus sha256 content digest, optional model label, and an inconclusive marker. Unknown fields and observed/review/execution claims are rejected.
  - Candidate analyses normalize to the existing stable-ID test_candidate observation and coverage gaps to analysis_coverage_gap observations. Supporting/contrary references must be listed in the envelope and resolve at the same target in the existing receipt/evidence transaction. Context exposes conclusion, reason, candidate class, method/producer attribution, and evidence references.
  - Candidate validation, finding promotion/review, work-item coordination, and execution authority remain separate explicit paths. Registry action identity, JSON-v1 and frozen legacy behavior, compact operation count, canonical workspace/evidence/execution routes, report structure, and generated action output contracts remain unchanged. No migration or parallel provenance store was added.
checks:
  - command: PYTHONPATH=MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_contributions test_context_compiler test_saved_data_integration test_workspace_ingestion test_state_runtime -q
    result: pass; 73 focused contribution, context, saved-data, ingestion, and state tests, including v1.0 strict rejection, v1.1 Registry acceptance/receipt/retry, canonical candidate/gap mapping, context attribution, same-target evidence references, observed-claim rejection, and cross-target/invalid-reference refusal; one unclosed SQLite connection ResourceWarning was emitted without test failure
  - command: PYTHONPATH=MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_action_projection test_slice_projection_contracts test_action_inventory test_output_contracts test_action_contracts -q
    result: pass; 36 compact/direct projection, Registry inventory, generated output-contract, and action-contract tests
  - command: PYTHONPATH=MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_core_state test_state_migration test_documentation test_engagement_report_layer -q
    result: pass; 93 state, migration, documentation, and report-layer tests
  - command: bin/generate-action-output-contracts --check
    result: pass; 168 retained action output contracts are current and unchanged
  - command: git show --format= --check 5194342ebb44fe8491e4f9530e66f4c6bcabc071 && .venv/bin/python -m compileall -q MCPS/Synapse-MCP/synapse_mcp/core/adapters/results.py MCPS/Synapse-MCP/synapse_mcp/core/workspace.py MCPS/Synapse-MCP/synapse_mcp/core/entity_merge.py MCPS/Synapse-MCP/synapse_mcp/app/actions/registry.py MCPS/Synapse-MCP/synapse_mcp/app/context.py MCPS/Synapse-MCP/synapse_mcp/state/runtime.py MCPS/Synapse-MCP/tests/test_contributions.py
    result: pass; committed implementation diff has no whitespace errors and changed Python files compile
skipped_checks: >-
  Completed-phase acceptance and benchmark gates were not run; they are retired.
  The full modern suite was not run; focused Registry projection, output-contract,
  contribution, context, state, and report suites cover this checkpoint.
known_issue: >-
  Generic merge semantics can retain an earlier candidate analysisConclusion
  across a later same-surface submission; 7R3.2 must prove and harden
  cross-submission candidate updates, subject/evidence boundaries, and restart
  recovery without overwriting reviewed dispositions. Historical duplicate
  candidateId rows still require operator review; they are not auto-repaired.
next_checkpoint: 7R3.2
next_action: >-
  Complete the 7R3.2 canonical method-result recovery path: validate referenced
  subjects/evidence in the target boundary, preserve evidence and reviewed
  dispositions on candidate updates, and test proposed plus contrary/inconclusive
  analysis through retry, fresh-client restart, and report/context projection.
  Reuse the same Registry action and receipt transaction; add no parallel store.
dirty_worktree: >-
  Only the pre-existing untracked review and source-plan documents remain
  outside the committed checkpoint: Synapse-Beta-Final-Review-2026-09-17.md
  and Synapse-Phase-7-Implementation-Tasks-2026-09-17.md.
```
