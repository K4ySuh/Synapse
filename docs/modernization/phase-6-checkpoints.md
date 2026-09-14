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
| 6R3 | Pending | 6R3.1, 6R3.2, 6R3.3 pending | Define the contribution envelope |
| 6R4 | Pending | 6R4.1, 6R4.2, 6R4.3 pending | Unify the packaged operating entry point |
| 6R5 | Pending | 6R5.1, 6R5.2, 6R5.3 pending | Add bounded recovery lookup |
| 6R6 | Pending | 6R6.1, 6R6.2 pending | Extract one saved-data integration seam |
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R2
checkpoint: 6R2.3
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: d18dbd7
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/tests/diagnose_authority_history.py
  - CHANGELOG.md
  - docs/modernization/phase-6-status.md
contract_changes:
  - No further runtime or schema change in this measurement checkpoint.
  - Across 6R2, SQLite-v2 added lookup-index migration 0007; JSON-v1, modern/legacy wire schemas, and stored row shapes remain compatible.
checks:
  - command: PYTHONPATH=tests ../../.venv/bin/python tests/diagnose_authority_history.py
    result: >-
      pass; Python 3.14.7, SQLite 3.53.4 via sqlite3 on MSI-Tower; five
      passive/mock authority-lifecycle operations per history size. With 8
      retained runs median was 15.22 ms; with 256 it was 15.40 ms. Both used
      91 SELECT, 38 INSERT, 6 UPDATE, 3 DELETE, 35 PRAGMA, 4 BEGIN, and 4 COMMIT
      statements per operation. This is local diagnostic evidence, not a timing
      threshold or full MCP client measurement.
  - command: bin/test --core -q
    result: pass; 795 tests after correcting stale action-contract and documentation assertions
  - command: bin/test-modern -q
    result: pass; 16 isolated modern-adapter tests
  - command: SYNAPSE_BUILD_PYTHON=.venv/bin/python SYNAPSE_BUILD_PYTHONPATH=/usr/lib/python3.14/site-packages SYNAPSE_RUNTIME_PYTHON=.venv/bin/python .venv/bin/python bin/validate-distribution
    result: pass at 6R2.2; wheel/sdist installed, standard 174 and core 42 action startup, migration 0007 present
  - command: PYTHONPATH=tests ../../.venv/bin/python -m unittest test_modernization_docs -q
    result: pass; 5 documentation tests after status update
  - command: git diff --cached --check
    result: pass; no whitespace errors
remaining_issue: >-
  The diagnostic covers a passive/mock local path on one host and is not a
  live-client compatibility claim. Full-history reads remain by design for
  explicit snapshot/export and inspection operations.
next_checkpoint: 6R3.1
next_action: >-
  Define the strict versioned contribution envelope on the existing ingestion
  path in core/workspace.py and app/actions, with a published schema and a
  receipt containing canonical IDs, diagnostics, and committed revision.
dirty_worktree: >-
  Tracked 6R2 implementation committed; this checkpoint record pending commit;
  pre-existing untracked Synapse-Reconvert-Phase.md left untouched.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
