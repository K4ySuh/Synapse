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
| 6R1 | Pending | 6R1.1, 6R1.2, 6R1.3 pending | Limit evidence links to contributed records |
| 6R2 | Pending | 6R2.1, 6R2.2, 6R2.3 pending | Stop rewriting unchanged lifecycle history |
| 6R3 | Pending | 6R3.1, 6R3.2, 6R3.3 pending | Define the contribution envelope |
| 6R4 | Pending | 6R4.1, 6R4.2, 6R4.3 pending | Unify the packaged operating entry point |
| 6R5 | Pending | 6R5.1, 6R5.2, 6R5.3 pending | Add bounded recovery lookup |
| 6R6 | Pending | 6R6.1, 6R6.2 pending | Extract one saved-data integration seam |
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R0
checkpoint: 6R0.1
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: 370597f4b04c1b502e5d52ce211ae0ccabdc6167
branch: Beta
changed_files:
  - docs/modernization/README.md
  - docs/modernization/phase-6-status.md
  - docs/modernization/phase-6-checkpoints.md
contract_changes:
  - Documentation only; no runtime, wire, storage, or compatibility contract change.
checks:
  - command: git diff --check
    result: pass; no whitespace errors in the roadmap/status diff
  - command: git diff -- docs/modernization/README.md docs/modernization/phase-6-status.md
    result: reviewed; roadmap, old-to-new mapping, coverage limits, and deferred work agree
  - command: git merge-base --is-ancestor 5a33b238020ff987ecf38dd3afcacca81d13de1a HEAD
    result: pass; reviewed Beta was the exact HEAD before the documentation commit
  - command: runtime suite
    result: skipped; documentation-only checkpoint
historical_verification:
  checkpoint: 6R0.2
  commit: f503e87
  reviewed_head: 5a33b23
  result: test_execution_lifecycle.py passed 22/22 at reviewed HEAD; not rerun for 6R0
remaining_issue: Evidence ownership and transactional merge integrity remain for 6R1.
next_checkpoint: 6R1.1
next_action: >-
  Inspect core/workspace.py::_ingest_data_v2 and state/runtime.py::ingest_collections;
  carry only touched endpoint records into the repository write and link evidence
  only to those records. Add a two-endpoint ingestion regression for payload and
  relational links, then run the focused state/ingestion tests.
dirty_worktree: >-
  Tracked checkpoint work committed; pre-existing untracked
  Synapse-Reconvert-Phase.md left untouched.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
