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
| 6R4 | Pending | 6R4.1, 6R4.2, 6R4.3 pending | Unify the packaged operating entry point |
| 6R5 | Pending | 6R5.1, 6R5.2, 6R5.3 pending | Add bounded recovery lookup |
| 6R6 | Pending | 6R6.1, 6R6.2 pending | Extract one saved-data integration seam |
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R3
checkpoint: 6R3.3
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: c01242e
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/synapse_mcp/core/adapters/results.py
  - MCPS/Synapse-MCP/synapse_mcp/core/workspace.py
  - MCPS/Synapse-MCP/synapse_mcp/app/actions/catalog.py
  - MCPS/Synapse-MCP/synapse_mcp/app/actions/descriptor.py
  - MCPS/Synapse-MCP/synapse_mcp/app/actions/legacy_bridge.py
  - MCPS/Synapse-MCP/synapse_mcp/app/actions/registry.py
  - MCPS/Synapse-MCP/synapse_mcp/app/facade/services.py
  - MCPS/Synapse-MCP/synapse_mcp/state/runtime.py
  - MCPS/Synapse-MCP/synapse_mcp/state/bundles.py
  - MCPS/Synapse-MCP/synapse_mcp/state/migration.py
  - MCPS/Synapse-MCP/synapse_mcp/state/migrations/__init__.py
  - MCPS/Synapse-MCP/synapse_mcp/state/migrations/0008_contribution_receipts.sql
  - MCPS/Synapse-MCP/tests/test_contributions.py
  - MCPS/Synapse-MCP/tests/test_execution_lifecycle.py
  - MCPS/Synapse-MCP/tests/test_state_store.py
  - MCPS/Synapse-MCP/tests/test_work_contracts.py
  - MCPS/Synapse-MCP/tests/test_work_items.py
  - MCPS/Synapse-MCP/tests/fixtures/phase3d/payload-manifest.json
  - MCPS/Synapse-MCP/tests/fixtures/phase3d/sdk-modern-direct-2024-11-05-tools.json
  - MCPS/Synapse-MCP/tests/fixtures/phase3d/sdk-modern-direct-2026-07-28-tools.json
  - bin/validate-distribution
  - README.md
  - MCPS/Synapse-MCP/README.md
  - docs/Architecture.md
  - docs/Contribution-Contract.md
  - docs/Implementation-Map.md
  - docs/Operations.md
  - docs/README.md
  - docs/modernization/phase-6-status.md
  - CHANGELOG.md
contract_changes:
  - Modern workspace.ingest_data accepts source=contribution.v1 with a strict 1.0 JSON envelope in rawData.
  - Registry-generated input and receipt schemas are published in x-synapse-contribution extensions; modern-direct SDK wire fixtures intentionally changed, compact operation count stays eleven.
  - SQLite-v2 migration 0008 adds consumer-scoped durable request receipts and bundle/backup preservation; JSON-v1 refuses strict mode without migration and activation.
  - Legacy tool input, parser modes, and reviewed-finding promotion are unchanged.
checks:
  - command: PYTHONPATH=tests ../../.venv/bin/python -m unittest test_contributions -q
    result: pass; 7 focused local tests covering two consumers, retry/conflict, concurrency, evidence/artifact links, rollback, facade binding, JSON-v1 refusal, bundle and backup recovery
  - command: bin/test --core -q
    result: pass; 802 tests
  - command: bin/test-modern -q
    result: pass; 16 isolated modern-adapter tests including exact direct wire fixtures
  - command: SYNAPSE_BUILD_PYTHON="$PWD/.venv/bin/python" SYNAPSE_BUILD_PYTHONPATH=/usr/lib/python3.14/site-packages SYNAPSE_RUNTIME_PYTHON="$PWD/.venv/bin/python" .venv/bin/python bin/validate-distribution
    result: pass; wheel and sdist installed; migration 0008 included; standard 174 and core-only 42 action startup
  - command: PYTHONPATH=tests ../../.venv/bin/python -m unittest test_modernization_docs -q
    result: pass; 5 documentation tests
  - command: git diff --cached --check
    result: pass; no whitespace errors
remaining_issue: >-
  Version 1.0 intentionally supports endpoints and observations only. The
  two-consumer exercise used isolated local contexts and fictional data; it
  is not a live external-client or Daybreak compatibility claim.
next_checkpoint: 6R4.1
next_action: >-
  Add one package-level canonical guidance accessor and register the operating
  prompt/resource on modern MCP, preserving the legacy retrieval shape.
dirty_worktree: >-
  Tracked 6R3 implementation and checkpoint record committed; only pre-existing untracked
  Synapse-Reconvert-Phase.md remains untouched.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
