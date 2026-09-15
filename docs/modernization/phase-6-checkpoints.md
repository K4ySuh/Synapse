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
| 6R2 | Complete | 6R2.1 `4c6e6a0`; 6R2.2 `5272de4`; 6R2.3 `d18dbd7` | 6R3.1 |
| 6R3 | Complete | 6R3.1–6R3.3 `c01242e` | 6R4.1 |
| 6R4 | Complete | 6R4.1–6R4.3 `2d81f14` | 6R5.1 |
| 6R5 | Complete | 6R5.1–6R5.3 `eb72496` | 6R6.1 |
| 6R6 | Pending | 6R6.1, 6R6.2 pending | Extract one saved-data integration seam |
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R5
checkpoint: 6R5.3
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: eb72496
branch: Beta
changed_files:
  - CHANGELOG.md
  - MCPS/Synapse-MCP/synapse_mcp/app/actions/registry.py
  - MCPS/Synapse-MCP/synapse_mcp/app/context.py
  - MCPS/Synapse-MCP/synapse_mcp/core/synchronous_observer.py
  - MCPS/Synapse-MCP/synapse_mcp/policy/integration.py
  - MCPS/Synapse-MCP/synapse_mcp/state/contracts.py
  - MCPS/Synapse-MCP/synapse_mcp/state/json_v1.py
  - MCPS/Synapse-MCP/synapse_mcp/state/migrations/0009_context_recovery_indexes.sql
  - MCPS/Synapse-MCP/synapse_mcp/state/migrations/__init__.py
  - MCPS/Synapse-MCP/synapse_mcp/state/runtime.py
  - MCPS/Synapse-MCP/synapse_mcp/state/work_items.py
  - MCPS/Synapse-MCP/tests/test_context_compiler.py
  - MCPS/Synapse-MCP/tests/test_synchronous_execution.py
  - MCPS/Synapse-MCP/tests/test_work_contracts.py
  - MCPS/Synapse-MCP/tests/test_work_items.py
  - bin/validate-distribution
  - docs/modernization/phase-6-status.md
contract_changes:
  - ContextRepositorySnapshot accepts target, entity-type, revision, work-item, claimant, selected-grant, and opaque authority-session selectors and exposes bounded recovery/page metadata.
  - Modern context omissions add repository_page with an explicit continuation; no compact tool count, modern-direct input, frozen legacy fixture, or JSON-v1 behavior change.
  - Ordered SQLite-v2 migration 0009 adds idx_execution_runs_authority_recovery over the opaque authority-session expression; existing v2 workspaces upgrade in place.
checks:
  - command: bin/test --core -q
    result: pass; 808 tests after correcting two stale hard-coded migration-count assertions found by the first post-migration run
  - command: bin/test-modern -q
    result: pass; 17 isolated modern-adapter tests including exact wire fixtures
  - command: cd MCPS/Synapse-MCP && PYTHONPATH=tests ../../.venv/bin/python -m unittest test_context_compiler test_synchronous_execution test_execution_lifecycle test_work_items -q
    result: pass; 70 focused context, observation, lifecycle, and work-item tests
  - command: cd MCPS/Synapse-MCP && PYTHONPATH=tests ../../.venv/bin/python -m unittest test_state_migration test_execution_lifecycle -q
    result: pass; 43 focused migration and lifecycle tests
  - command: SYNAPSE_BUILD_PYTHON="$PWD/.venv/bin/python" SYNAPSE_BUILD_PYTHONPATH=/usr/lib/python3.14/site-packages SYNAPSE_RUNTIME_PYTHON="$PWD/.venv/bin/python" .venv/bin/python bin/validate-distribution
    result: pass; wheel and sdist installed outside checkout; migration 0009, standard 174-action and core-only 42-action startup verified
  - command: git diff --cached --check
    result: pass; no whitespace errors
remaining_issue: >-
  Repository-page omission counts are conservative lower bounds so queries do
  not scan an omitted tail merely to count it. Provider/browser/process-internal
  observation remains outside the owned synchronous coverage, as documented.
next_checkpoint: 6R6.1
next_action: >-
  Select one saved-data import path with a stable parser and extract its passive
  interpretation/help seam while preserving canonical ingestion and legacy forwarding.
dirty_worktree: >-
  Tracked 6R5 implementation committed at eb72496; only pre-existing untracked
  Synapse-Reconvert-Phase.md remains untouched after the checkpoint record commit.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
