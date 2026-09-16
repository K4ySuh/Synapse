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
| 6R6 | Complete | 6R6.1–6R6.2 `a7cf5a9` | 6R7.1 |
| 6R7 | Complete | 6R7.1–6R7.3 `48dee7f` | Beta operator handoff complete |

## Latest checkpoint record

```yaml
task: 6R7
checkpoint: 6R7.3
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: 48dee7f
branch: Beta
changed_files:
  - CHANGELOG.md
  - README.md
  - docs/Operations.md
  - docs/modernization/README.md
  - docs/modernization/phase-6-client-exercise.md
contract_changes:
  - No application, Registry, state, authority, protocol, generated inventory, output-contract, contribution, or legacy compatibility contract changed in 6R7.
  - The operator documentation now records the tested client boundary and restart-safe quick start/handoff.
checks:
  - command: bin/test --core -q
    result: pass; 810 current tests, including fresh SQLite-v2, migration/storage, inventory/output contracts, ingestion/retry, independent consumers, context/background recovery, and reports
  - command: bin/test-modern -q
    result: pass; 17 tests across compact/direct, stdio/HTTP, restart, hosted resources, and frozen fixtures
  - command: bin/validate-codex-skills --check
    result: pass; 3 default skills and 2 shared references
  - command: bin/validate-codex-skills --check --profile multi-agent-compat
    result: pass; 8 compatibility skills and 2 shared references
  - command: SYNAPSE_BUILD_PYTHON=.venv/bin/python SYNAPSE_BUILD_PYTHONPATH=/usr/lib/python3.14/site-packages SYNAPSE_RUNTIME_PYTHON=.venv/bin/python .venv/bin/python bin/validate-distribution
    result: pass; wheel and sdist installed outside checkout; standard 174-action and core-only 42-action startup verified
  - command: bounded single-agent Codex direct-client exercise
    result: pass; Codex CLI 0.154.0, provisioned gpt-daybreak-blue-latest at High, mcp 2.0.0, protocol 2025-06-18, modern-compact stdio, Synapse 0.6.0b0, and Python 3.14.7
  - command: cd MCPS/Synapse-MCP && PYTHONPATH=tests ../../.venv/bin/python -m unittest test_modernization_docs test_distribution -q
    result: pass; 14 focused documentation and distribution-contract tests
remaining_issue: >-
  The pass is limited to the recorded client/model/build. Provider, browser,
  background-worker, and child-process-internal observation; generalized
  taint/invalidation; counterfactual evaluation; and migration of every
  saved-data adapter remain outside this Beta boundary.
next_checkpoint: null
next_action: >-
  Use the Beta operator quick start and server-held authority workflow for an
  authorized engagement; open a new scoped roadmap task for deferred work.
dirty_worktree: >-
  Tracked 6R7 handoff committed at 48dee7f; only pre-existing untracked
  Synapse-Reconvert-Phase.md remains untouched after the checkpoint record commit.
```

The direct-client pass applies only to the recorded Codex host, provisioned
model, protocol, SDK, and package versions. Full observer/provider coverage,
generalized taint/invalidation, counterfactual evaluation, and untested client
support remain deferred.
