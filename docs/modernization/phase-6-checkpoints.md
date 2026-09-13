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
| 6R2 | Pending | 6R2.1, 6R2.2, 6R2.3 pending | Stop rewriting unchanged lifecycle history |
| 6R3 | Pending | 6R3.1, 6R3.2, 6R3.3 pending | Define the contribution envelope |
| 6R4 | Pending | 6R4.1, 6R4.2, 6R4.3 pending | Unify the packaged operating entry point |
| 6R5 | Pending | 6R5.1, 6R5.2, 6R5.3 pending | Add bounded recovery lookup |
| 6R6 | Pending | 6R6.1, 6R6.2 pending | Extract one saved-data integration seam |
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R1
checkpoint: 6R1.3
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: e9b823354f135af92fb8cca8e27bd82057d9c179
branch: Beta
changed_files:
  - CHANGELOG.md
  - docs/Implementation-Map.md
  - docs/Operations.md
  - docs/modernization/phase-6-status.md
contract_changes:
  - Documentation only; historical SQLite-v2 over-linking remains untouched.
  - JSON-v1, modern/legacy wire schemas, storage schema, and fixtures unchanged across 6R1.
checks:
  - command: PYTHONPATH=tests python -m unittest test_workspace_ingestion test_state_runtime -q
    result: pass; 47 tests at 6R1.2, including JSON-v1 and SQLite-v2 paths; not rerun for documentation-only 6R1.3
  - command: git diff --cached --check
    result: pass; no whitespace errors
  - command: local Markdown reference review
    result: pass; Operations link and Workspace Context anchor resolve
remaining_issue: >-
  Older SQLite-v2 workspaces may contain over-linked evidence. Stored revision
  metadata cannot reliably distinguish those links from legitimate repeated
  submissions, and retained raw artifacts may be incomplete; no automatic
  diagnostic or repair was added. Operator review is required where material.
next_checkpoint: 6R2.1
next_action: >-
  Trace policy/repository.py and state/runtime.py authority transactions for
  grant, dispatch, run, budget, decision, observation, and validation writes.
  Stop updating unchanged run/dispatch rows and add a focused run-A/run-B
  regression before moving to the history-read reduction in 6R2.2.
dirty_worktree: >-
  Tracked checkpoint work committed; pre-existing untracked
  Synapse-Reconvert-Phase.md left untouched.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
