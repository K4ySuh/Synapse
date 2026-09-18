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
| 7R1 | In progress | 7R1.1 `750e261`; 7R1.2 complete; 7R1.3 pending | 7R1.3 |
| 7R2 | Pending | 7R2.1–7R2.2 pending | After 7R0; work serially after 7R1 |
| 7R3 | Pending | 7R3.1–7R3.2 pending | After 7R1 and 7R2 |
| 7R4 | Pending | 7R4.1–7R4.2 pending | After 7R0; work serially after 7R3 |
| 7R5 | Pending | 7R5.1–7R5.3 pending | After 7R3 and 7R4 |
| 7R6 | Pending | 7R6.1–7R6.2 pending | After 7R3–7R5 |
| 7R7 | Pending | 7R7.1–7R7.2 pending | After 7R1–7R6 |

## Latest checkpoint record

```yaml
task: 7R1
checkpoint: 7R1.2
status: complete
review_base: 8134673a386ad00eed786d3d3ba841f00fcb28de
implementation_commit: null
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/synapse_mcp/state/runtime.py
  - MCPS/Synapse-MCP/tests/test_contributions.py
  - docs/Architecture.md
  - docs/Contribution-Contract.md
  - docs/modernization/phase-7-checkpoints.md
  - docs/modernization/phase-7-status.md
contract_changes:
  - A contribution retry now compares the current normalized action target with the target in the stored receipt inside the existing receipt transaction before accepting idempotent replay.
  - Same workspace, authenticated consumer, requestId, target, and envelope still return the stored receipt. A changed target or payload returns contribution_request_conflict without a canonical entity, evidence, receipt, artifact-metadata, or revision write.
  - Receipt uniqueness, the historical envelope fingerprint, contribution.v1 schemas, Registry identity, evidence linkage, execution path, compact/direct/legacy surfaces, JSON-v1 boundary, and frozen fixtures are unchanged.
checks:
  - command: PYTHONPATH=MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_contributions test_saved_data_integration -q
    result: pass; 10 Registry/repository contribution tests including normalized same-target retry, two-target conflict, consumer isolation, concurrency, bundle/backup recovery, strict rollback, and saved-data integration
  - command: PYTHONPATH=MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_action_inventory test_output_contracts test_action_contracts -q
    result: pass; 27 Registry inventory, generated output-contract, and action-contract tests
  - command: bin/generate-action-output-contracts --check
    result: pass; 168 retained action output contracts are current and unchanged
  - command: git diff --check && .venv/bin/python -m compileall -q MCPS/Synapse-MCP/synapse_mcp/state/runtime.py MCPS/Synapse-MCP/tests/test_contributions.py
    result: pass; the checkpoint diff has no whitespace errors and all changed Python modules compile
known_issue: >-
  Historical duplicate candidateId rows require operator review and are not
  repaired automatically. F5 history-dependent relation synchronization
  remains for 7R1.3; larger-context completeness and provenance remain pending
  in 7R2.
next_checkpoint: 7R1.3
next_action: >-
  Refactor ActivatedWorkspaceRepository._sync_relations and its ingestion
  callers to process changed relation sources plus destinations that can resolve
  prior forward references, using existing indexed identities; then run the
  100/2,000-endpoint decoded-row diagnostic without adding a graph subsystem.
dirty_worktree: >-
  Only the pre-existing untracked review and source-plan documents remain
  outside the committed checkpoint: Synapse-Beta-Final-Review-2026-09-17.md
  and Synapse-Phase-7-Implementation-Tasks-2026-09-17.md.
```
