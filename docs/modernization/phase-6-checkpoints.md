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
| 6R2 | In progress | 6R2.1 `4c6e6a0`; 6R2.2 `5272de4`; 6R2.3 pending | Measure and close persistent-path checks |
| 6R3 | Pending | 6R3.1, 6R3.2, 6R3.3 pending | Define the contribution envelope |
| 6R4 | Pending | 6R4.1, 6R4.2, 6R4.3 pending | Unify the packaged operating entry point |
| 6R5 | Pending | 6R5.1, 6R5.2, 6R5.3 pending | Add bounded recovery lookup |
| 6R6 | Pending | 6R6.1, 6R6.2 pending | Extract one saved-data integration seam |
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R2
checkpoint: 6R2.2
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: 5272de4
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/synapse_mcp/policy/repository.py
  - MCPS/Synapse-MCP/synapse_mcp/state/runtime.py
  - MCPS/Synapse-MCP/synapse_mcp/state/migrations/0007_authority_lookup_indexes.sql
  - MCPS/Synapse-MCP/synapse_mcp/state/migrations/__init__.py
  - MCPS/Synapse-MCP/tests/test_execution_lifecycle.py
  - MCPS/Synapse-MCP/tests/test_state_store.py
  - MCPS/Synapse-MCP/tests/test_action_contracts.py
  - MCPS/Synapse-MCP/tests/test_work_contracts.py
  - MCPS/Synapse-MCP/tests/test_work_items.py
  - bin/validate-distribution
  - docs/Architecture.md
  - docs/Implementation-Map.md
  - docs/Operations.md
contract_changes:
  - SQLite-v2 migration 0007 adds indexed idempotency, continuation, and expiry lookup paths without changing stored row shape.
  - Authority mutations load relevant records only; full snapshots remain explicit inspection/export behavior.
  - Supplied observer callbacks run before the write lock and stale sealed run bindings are rejected.
  - JSON-v1 and modern/legacy wire schemas unchanged.
checks:
  - command: PYTHONPATH=tests ../../.venv/bin/python -m unittest test_authority_model test_authority_repository test_authority_integration test_execution_lifecycle test_execution_truth test_synchronous_execution test_state_store test_state_runtime test_state_migration test_work_items test_work_contracts test_work_reliability -q
    result: pass; 186 tests
  - command: PYTHONPATH=tests ../../.venv/bin/python -m unittest test_action_contracts test_modernization_docs -q
    result: pass; 20 tests after correcting two pre-existing stale test expectations and the checkpoint path
  - command: SYNAPSE_BUILD_PYTHON=.venv/bin/python SYNAPSE_BUILD_PYTHONPATH=/usr/lib/python3.14/site-packages SYNAPSE_RUNTIME_PYTHON=.venv/bin/python .venv/bin/python bin/validate-distribution
    result: pass; wheel and sdist built/installed, migration 0007 present
  - command: git diff --cached --check
    result: pass; no whitespace errors
remaining_issue: Full core rerun and persistent-path diagnostic are due at 6R2.3; initial 795-test core run found two stale assertions, now corrected.
next_checkpoint: 6R2.3
next_action: >-
  Run tests/diagnose_authority_history.py in one interpreter for 8 and 256
  retained passive/mock runs, record SQL counts and median latency; rerun the
  full core suite after stale-test corrections, update the status/changelog,
  and close 6R2 without restoring retired performance gates.
dirty_worktree: >-
  Tracked implementation committed; checkpoint record pending commit;
  tests/diagnose_authority_history.py is unfinished 6R2.3 work; pre-existing
  untracked Synapse-Reconvert-Phase.md left untouched.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
