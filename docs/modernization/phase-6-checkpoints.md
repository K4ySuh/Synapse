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
| 6R1 | In progress | 6R1.1 complete at `6845e9f`; 6R1.2 complete at `3b50c98`; 6R1.3 pending | Record historical repair limits |
| 6R2 | Pending | 6R2.1, 6R2.2, 6R2.3 pending | Stop rewriting unchanged lifecycle history |
| 6R3 | Pending | 6R3.1, 6R3.2, 6R3.3 pending | Define the contribution envelope |
| 6R4 | Pending | 6R4.1, 6R4.2, 6R4.3 pending | Unify the packaged operating entry point |
| 6R5 | Pending | 6R5.1, 6R5.2, 6R5.3 pending | Add bounded recovery lookup |
| 6R6 | Pending | 6R6.1, 6R6.2 pending | Extract one saved-data integration seam |
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R1
checkpoint: 6R1.2
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: 3b50c98bcd6aeaf45700cf9febf8eb3d5ba90330
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/synapse_mcp/core/entity_merge.py
  - MCPS/Synapse-MCP/synapse_mcp/core/workspace.py
  - MCPS/Synapse-MCP/synapse_mcp/state/runtime.py
  - MCPS/Synapse-MCP/tests/test_state_runtime.py
  - MCPS/Synapse-MCP/tests/test_workspace_ingestion.py
contract_changes:
  - SQLite-v2 ingestion merges submitted fields with the current row inside its write transaction.
  - JSON-v1 retains the same shared field merge policy; non-ingest repository updates keep their previous replacement behavior.
checks:
  - command: PYTHONPATH=tests python -m unittest test_workspace_ingestion test_state_runtime -q
    result: pass; 47 tests
  - command: git diff --cached --check
    result: pass; no whitespace errors
remaining_issue: Existing SQLite-v2 workspaces may contain historical over-linking; no automatic repair has been established.
next_checkpoint: 6R1.3
next_action: >-
  Document the affected SQLite-v2 path and historical over-linking limit. Check
  whether evidence payloads and stored entity rows can reliably distinguish
  erroneous links from legitimate repeated submissions; provide only a bounded
  read-only diagnostic if that provenance is sufficient. Record compatibility
  and the focused checks without deleting historical links.
dirty_worktree: >-
  Tracked checkpoint work committed; pre-existing untracked
  Synapse-Reconvert-Phase.md left untouched.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
