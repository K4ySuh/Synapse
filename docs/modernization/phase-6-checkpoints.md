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
| 6R1 | Complete | 6R1.1 `6845e9f`; 6R1.2 `3b50c98`; 6R1.3 `e9b8233` | 6R2.1 |
| 6R2 | In progress | 6R2.1 `4c6e6a0`; 6R2.2, 6R2.3 pending | Replace mutation snapshots with relevant-record reads |
| 6R3 | Pending | 6R3.1, 6R3.2, 6R3.3 pending | Define the contribution envelope |
| 6R4 | Pending | 6R4.1, 6R4.2, 6R4.3 pending | Unify the packaged operating entry point |
| 6R5 | Pending | 6R5.1, 6R5.2, 6R5.3 pending | Add bounded recovery lookup |
| 6R6 | Pending | 6R6.1, 6R6.2 pending | Extract one saved-data integration seam |
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R2
checkpoint: 6R2.1
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: 4c6e6a0
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/synapse_mcp/policy/repository.py
  - MCPS/Synapse-MCP/synapse_mcp/state/runtime.py
  - MCPS/Synapse-MCP/tests/test_execution_lifecycle.py
contract_changes:
  - SQLite-v2 authority commits write only changed grant, request, step-up, budget, dispatch, run, observation, validation, and decision records.
  - JSON-v1, modern/legacy wire schemas, and storage schema unchanged.
checks:
  - command: PYTHONPATH=tests /home/kaysuh/Projects/Synapse/.venv/bin/python -m unittest test_authority_repository test_authority_integration test_state_runtime test_execution_lifecycle -q
    result: pass; 64 tests, including unchanged run A after run B
  - command: git diff --check
    result: pass; no whitespace errors
remaining_issue: Full authority_state snapshot is still read on each mutation and historical lifecycle records are still deserialized/validated in the save path.
next_checkpoint: 6R2.2
next_action: >-
  Add scoped authority transaction reads in state/runtime.py and select them
  from policy/repository.py. Load the current grant and budget, matching
  idempotency/request/step-up rows, and only the referenced dispatch/run with
  its observations/validations. Preserve full snapshot for inspection/export.
dirty_worktree: >-
  Tracked implementation committed; checkpoint record pending commit;
  pre-existing untracked
  Synapse-Reconvert-Phase.md left untouched.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
