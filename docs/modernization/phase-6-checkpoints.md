# Phase 6 Beta checkpoint ledger

The reviewed Beta base is `5a33b238020ff987ecf38dd3afcacca81d13de1a`
on branch `Beta`. It was the exact HEAD at the 2026-09-13 rebaseline, so no
newer implementation commits needed reassessment. The 6R0.1 roadmap/status
commit below is subsequent documentation work. Keep historical results attached
to their original commits; do not treat them as fresh checks or restore retired
phase acceptance and benchmark runners.

| Task | Status | Checkpoints | Next step |
| --- | --- | --- | --- |
| 6R0 | Complete | 6R0.1 complete at `370597f`; 6R0.2 complete at reviewed `f503e87`/`5a33b23` | 6R1.1 |
| 6R1 | In progress | 6R1.1 complete at `6845e9f`; 6R1.2, 6R1.3 pending | Merge touched rows against transactional current state |
| 6R2 | Pending | 6R2.1, 6R2.2, 6R2.3 pending | Stop rewriting unchanged lifecycle history |
| 6R3 | Pending | 6R3.1, 6R3.2, 6R3.3 pending | Define the contribution envelope |
| 6R4 | Pending | 6R4.1, 6R4.2, 6R4.3 pending | Unify the packaged operating entry point |
| 6R5 | Pending | 6R5.1, 6R5.2, 6R5.3 pending | Add bounded recovery lookup |
| 6R6 | Pending | 6R6.1, 6R6.2 pending | Extract one saved-data integration seam |
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R1
checkpoint: 6R1.1
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: 6845e9f172fbf71ca4075a5ed72ca3518f0a058d
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/synapse_mcp/core/workspace.py
  - MCPS/Synapse-MCP/synapse_mcp/state/runtime.py
  - MCPS/Synapse-MCP/tests/test_workspace_ingestion.py
contract_changes:
  - SQLite-v2 ingestion submits only contributed entities; existing rows are resolved in the repository transaction.
  - Relation synchronization preserves unchanged relation rows.
checks:
  - command: PYTHONPATH=tests python -m unittest test_workspace_ingestion test_state_runtime -q
    result: pass; 46 tests
  - command: git diff --cached --check
    result: pass; no whitespace errors
remaining_issue: Same-entity list unions and reviewed finding fields still need merge against the current transactional row.
next_checkpoint: 6R1.2
next_action: >-
  Move the existing field merge policy into a shared core helper and call it from
  state/runtime.py::_upsert_collection_rows for ingestion after reading the current
  row inside the transaction. Verify two same-entity submissions and a reviewed
  finding with local fixtures, including rollback on an injected failure.
dirty_worktree: >-
  Tracked checkpoint work committed; pre-existing untracked
  Synapse-Reconvert-Phase.md left untouched.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
