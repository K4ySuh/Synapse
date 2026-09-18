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
| 7R1 | In progress | 7R1.1 complete; 7R1.2–7R1.3 pending | 7R1.2 |
| 7R2 | Pending | 7R2.1–7R2.2 pending | After 7R0; work serially after 7R1 |
| 7R3 | Pending | 7R3.1–7R3.2 pending | After 7R1 and 7R2 |
| 7R4 | Pending | 7R4.1–7R4.2 pending | After 7R0; work serially after 7R3 |
| 7R5 | Pending | 7R5.1–7R5.3 pending | After 7R3 and 7R4 |
| 7R6 | Pending | 7R6.1–7R6.2 pending | After 7R3–7R5 |
| 7R7 | Pending | 7R7.1–7R7.2 pending | After 7R1–7R6 |

## Latest checkpoint record

```yaml
task: 7R1
checkpoint: 7R1.1
status: complete
review_base: 8134673a386ad00eed786d3d3ba841f00fcb28de
implementation_commit: null
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/synapse_mcp/core/workspace.py
  - MCPS/Synapse-MCP/synapse_mcp/state/runtime.py
  - MCPS/Synapse-MCP/tests/test_workspace_ingestion.py
  - docs/Operations.md
  - docs/modernization/phase-7-checkpoints.md
  - docs/modernization/phase-7-status.md
contract_changes:
  - SQLite-v2 candidate curation now creates or updates one observation through a single repository transaction, materializes the canonical candidate key before the first write, and preserves the existing row ID and current payload.
  - Explicit curation can reconsider a refuted class by returning it to proposed state and clearing retirement; ordinary ingestion/rescan still cannot revive it. JSON-v1 retains the same lifecycle behavior.
  - Historical duplicate candidateId rows are detected and left unchanged for operator review; no evidence or review history is deleted or merged automatically.
  - No Action Registry identity, action schema, output contract, compact/direct/legacy surface, evidence path, execution path, contribution contract, or frozen fixture changed.
checks:
  - command: PYTHONPATH=MCPS/Synapse-MCP/tests .venv/bin/python -m unittest discover -s MCPS/Synapse-MCP/tests -p 'test_workspace_ingestion.py' -q
    result: pass; 41 ingestion, reportability, candidate consolidation, SQLite-v2/JSON-v1 lifecycle, restart, and historical-duplicate tests
  - command: PYTHONPATH=MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_action_inventory test_output_contracts test_action_contracts -q
    result: pass; 27 Registry inventory, generated output-contract, and action-contract tests
  - command: bin/generate-action-output-contracts --check
    result: pass; 168 retained action output contracts are current and unchanged
  - command: git diff --check && .venv/bin/python -m compileall -q MCPS/Synapse-MCP/synapse_mcp/core/workspace.py MCPS/Synapse-MCP/synapse_mcp/state/runtime.py MCPS/Synapse-MCP/tests/test_workspace_ingestion.py
    result: pass; the checkpoint diff has no whitespace errors and all changed Python modules compile
known_issue: >-
  Historical duplicate candidateId rows require operator review and are not
  repaired automatically. F4 target-bound contribution retries and F5
  history-dependent relation synchronization remain for 7R1.2 and 7R1.3;
  larger-context correctness remains pending in 7R2.
next_checkpoint: 7R1.2
next_action: >-
  In ActivatedWorkspaceRepository.ingest_collections, compare the current
  normalized target with the stored contribution receipt target inside the
  existing receipt transaction before returning an idempotent retry; add the
  same-target control and two-target conflict regression without changing the
  workspace/consumer/requestId uniqueness contract.
dirty_worktree: >-
  Only the pre-existing untracked review and source-plan documents remain
  outside the committed checkpoint: Synapse-Beta-Final-Review-2026-09-17.md
  and Synapse-Phase-7-Implementation-Tasks-2026-09-17.md.
```
