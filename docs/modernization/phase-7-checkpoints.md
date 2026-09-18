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
| 7R2 | Pending | 7R2.1–7R2.2 pending | 7R2.1 |
| 7R3 | Pending | 7R3.1–7R3.2 pending | After 7R1 and 7R2 |
| 7R4 | Pending | 7R4.1–7R4.2 pending | After 7R0; work serially after 7R3 |
| 7R5 | Pending | 7R5.1–7R5.3 pending | After 7R3 and 7R4 |
| 7R6 | Pending | 7R6.1–7R6.2 pending | After 7R3–7R5 |
| 7R7 | Pending | 7R7.1–7R7.2 pending | After 7R1–7R6 |

## Latest checkpoint record

```yaml
task: 7R1
checkpoint: 7R1.3
status: complete
review_base: 8134673a386ad00eed786d3d3ba841f00fcb28de
implementation_commit: 526a644eea1074d552c284ea927c54d70d6174fe
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/synapse_mcp/state/runtime.py
  - MCPS/Synapse-MCP/tests/test_contributions.py
  - MCPS/Synapse-MCP/tests/test_workspace_ingestion.py
  - MCPS/Synapse-MCP/tests/diagnose_relation_sync.py
  - docs/modernization/phase-7-checkpoints.md
  - docs/modernization/phase-7-status.md
contract_changes:
  - Collection upserts, transactional single-item mutations, and contribution ingestion now pass their touched canonical entity IDs into relation synchronization instead of causing a full-target entity decode.
  - Relation synchronization processes changed sources and older sources whose forward references match newly touched destination aliases. Indexed entity IDs and per-type natural keys resolve normal references; the historical payload-alias scan runs only for still-unresolved references.
  - Changed relation sets delete or replace only the affected source's rows, newly available destinations resolve prior forward references, and unrelated entity/relation revisions and creation metadata remain unchanged.
  - The Registry, workspace, evidence, revision, execution, compact/direct/legacy, JSON-v1, and frozen-fixture contracts are unchanged. No migration, lookup index, graph layer, action, or output contract was added.
checks:
  - command: PYTHONPATH=MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_contributions test_workspace_ingestion test_state_runtime -q
    result: pass; 59 focused Registry contribution, workspace-ingestion, relation-correctness, transaction, and state-runtime tests; the existing non-failing SQLite ResourceWarning was emitted
  - command: PYTHONPATH=MCPS/Synapse-MCP/tests .venv/bin/python MCPS/Synapse-MCP/tests/diagnose_relation_sync.py
    result: pass; Python 3.14.7, SQLite 3.53.4 sqlite3 binding on MSI-Tower; 100 saved endpoints measured 8.70 ms median and 3 decoded rows per contribution, while 2,000 measured 9.13 ms and 3 decoded rows; both sizes performed BEGIN 1, COMMIT 1, INSERT 10, PRAGMA 28, SELECT 35, and UPDATE 2 per contribution
  - command: PYTHONPATH=MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_state_migration test_saved_data_integration test_action_inventory test_output_contracts test_action_contracts -q
    result: pass; 45 migration, saved-data integration, Registry inventory, generated output-contract, and action-contract tests
  - command: bin/generate-action-output-contracts --check
    result: pass; 168 retained action output contracts are current and unchanged
  - command: git diff --check && .venv/bin/python -m compileall -q MCPS/Synapse-MCP/synapse_mcp/state/runtime.py MCPS/Synapse-MCP/tests/test_contributions.py MCPS/Synapse-MCP/tests/test_workspace_ingestion.py MCPS/Synapse-MCP/tests/diagnose_relation_sync.py
    result: pass; the checkpoint diff has no whitespace errors and all changed Python modules compile
known_issue: >-
  Historical duplicate candidateId rows require operator review and are not
  repaired automatically. Forward-reference discovery and historical alias
  compatibility still use target-scoped SQLite JSON filtering when indexed
  identities cannot answer the lookup; the diagnostic establishes constant
  Python decoding and statement counts for the exercised sizes, not constant
  internal SQLite row work or a machine-independent latency guarantee.
  Larger-context completeness and provenance remain pending in 7R2.
next_checkpoint: 7R2.1
next_action: >-
  Extend the existing context.query contract with an optional opaque cursor
  bound to workspace, normalized query/filter identity, section, deterministic
  position, and revision; add a saved-data regression with more than 200
  same-target entities and a contradiction beyond the old cutoff, without a
  new MCP operation or graph/search subsystem.
dirty_worktree: >-
  Only the pre-existing untracked review and source-plan documents remain
  outside the committed checkpoint: Synapse-Beta-Final-Review-2026-09-17.md
  and Synapse-Phase-7-Implementation-Tasks-2026-09-17.md.
```
