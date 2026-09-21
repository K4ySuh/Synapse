# Phase 7 Beta checkpoint ledger

The reviewed Beta base is `8134673a386ad00eed786d3d3ba841f00fcb28de`
on branch `Beta`. It is also the actual branch HEAD at the 7R0.1 baseline, so
there are no subsequent implementation commits to reassess. Phase 6 remains
complete; its [ledger](phase-6-checkpoints.md) and
[direct-client exercise](phase-6-client-exercise.md) are historical evidence,
not gates to rerun for each Phase 7 checkpoint.

| Task | Status | Checkpoints | Next step |
| --- | --- | --- | --- |
| 7R0 | Complete | 7R0.1 `bcddb09` | 7R1.1 |
| 7R1 | Complete | 7R1.1 `750e261`; 7R1.2 `a69db92`; 7R1.3 `526a644` | 7R2.1 |
| 7R2 | Complete | 7R2.1 `1207fa9` + `bdabeb2`; 7R2.2 `7dd5ef8` | 7R3.1 |
| 7R3 | Complete | 7R3.1 `5194342`; 7R3.2 `90b5618` | 7R4.1 |
| 7R4 | Complete | 7R4.1 `987a567`; 7R4.2 `a190e1b` | 7R5.1 |
| 7R5 | Complete | 7R5.1 `ca32158`; 7R5.2 `b2f1259` + `b9b026a` + `4629982`; 7R5.3 `d95c043` | 7R6.1 |
| 7R6 | Complete | 7R6.1 `7e0b6b4`; 7R6.2 `c67df23` | 7R7.1 |
| 7R7 | In progress | 7R7.1 `af16cbc`; 7R7.2 pending | 7R7.2 |

## Latest checkpoint record

```yaml
task: 7R7
checkpoint: 7R7.1
status: complete
review_base: 8134673a386ad00eed786d3d3ba841f00fcb28de
implementation_commit: af16cbc4c974160002a84f9b918aed31c7f4c761
branch: Beta
changed_files:
  - CHANGELOG.md
  - MCPS/Synapse-MCP/modern_tests/test_modern_adapter.py
  - MCPS/Synapse-MCP/tests/fixtures/phase3d/modern-compact-tools.json
  - MCPS/Synapse-MCP/tests/fixtures/phase3d/modern-direct-tools.json
  - MCPS/Synapse-MCP/tests/fixtures/phase3d/payload-manifest.json
  - MCPS/Synapse-MCP/tests/fixtures/phase3d/sdk-modern-compact-2024-11-05-tools.json
  - MCPS/Synapse-MCP/tests/fixtures/phase3d/sdk-modern-compact-2026-07-28-tools.json
  - MCPS/Synapse-MCP/tests/fixtures/phase3d/sdk-modern-direct-2024-11-05-tools.json
  - MCPS/Synapse-MCP/tests/fixtures/phase3d/sdk-modern-direct-2026-07-28-tools.json
  - MCPS/Synapse-MCP/tests/test_contribution_method_recovery.py
  - MCPS/Synapse-MCP/tests/test_contributions.py
  - MCPS/Synapse-MCP/tests/test_tool_wrappers.py
  - bin/validate-distribution
  - docs/Implementation-Map.md
  - docs/Operations.md
  - docs/modernization/phase-7-status.md
contract_changes:
  - Operations and Implementation Map now put the standard eleven-operation modern-compact route first, label frozen legacy as rollback compatibility, list migrations through 0009, and document minimum workflow-specific optional dependencies without requiring browsers or scanner binaries for saved-data work.
  - Distribution validation retrieves all 3 default, 8 optional web-method, and 8 compatibility skills from each installed artifact and recursively resolves their local Markdown references outside the checkout. One wheel and one sdist are still built and installed exactly once per gate run.
  - Existing current-state bundle/export/import and online-backup checks now prove that a contribution v1.1 receipt, method ID/digest, model label, knowledge state, contrary evidence, and analysis coverage-gap conclusion survive recovery. No migration or rollback engine was added.
  - Modern-direct HTTP startup readiness now uses a five-second monotonic deadline, detects early process exit, and includes captured server output in the failure. It does not sleep indefinitely or retry a whole suite.
  - The integrated modern run exposed stale generated modern fixtures for two prior intentional contracts: 7R2.1 context cursor/continuation and 7R3.1 contribution v1.1. Only modern compact/direct application and official-SDK fixtures and their manifest measurements were regenerated. Frozen legacy fixtures are byte-unchanged; modern-direct retains all 174 action IDs/order and modern-compact remains eleven operations.
  - Fresh-process recovery tests now override SYNAPSE_DUMP_DIR with their isolated SYNAPSE_DATA_DIR, and the package-prompt assertion follows the current equivalent lease wording. Runtime application, Registry, authority, workspace, evidence, execution, discovery ranking, JSON-v1, and migration behavior are unchanged.
checks:
  - command: PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_workspace_ingestion test_contributions test_saved_data_integration test_context_compiler test_facade_services test_state_runtime test_work_items test_contribution_method_recovery test_action_projection test_slice_projection_contracts test_action_inventory test_output_contracts test_action_contracts test_core_state test_state_migration test_documentation test_engagement_report_layer -q
    result: pass; 250 current 7R1-7R3 candidate, contribution, relation, context, attribution, recovery, projection, state, migration, and report regressions; two non-failing unclosed-SQLite ResourceWarnings
  - command: bin/generate-action-inventory --check && PATH="$PWD/.venv/bin:$PATH" bin/generate-action-output-contracts --check && PATH="$PWD/.venv/bin:$PATH" bin/generate-capability-pack-ownership --check
    result: pass; 174 canonical actions, 168 retained output contracts, and 174 actions owned once across six packs
  - command: bin/validate-codex-skills --check && bin/validate-codex-skills --check --profile web-methods && bin/validate-codex-skills --check --profile multi-agent-compat
    result: pass; 3 default, 8 optional web-method, and 8 compatibility skills validated with their repository references
  - command: SYNAPSE_BUILD_PYTHON="$PWD/.venv/bin/python" SYNAPSE_BUILD_PYTHONPATH="$HOME/Projects/COAE/miniconda3/lib/python3.14/site-packages" .venv/bin/python bin/validate-distribution
    result: pass; one 0.6.0b0 wheel and one sdist built and installed once outside the checkout; each install retrieved all 19 selected operating/method/compatibility skills and resolved references; installed standard wheel/sdist runtimes constructed with 174 actions and installed core-only with 42
  - command: timeout --signal=ABRT --kill-after=5s 30s env PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -X faulthandler -m unittest MCPS.Synapse-MCP.modern_tests.test_modern_adapter.ModernPersistenceAndResourceTests.test_operating_prompt_and_default_guidance_are_discoverable_read_only -v
    result: pass; the previously stalling Python 3.14 official-SDK synchronous prompt/guidance resource-read test completed in 0.121 seconds, so no timeout or traceback fired
  - command: bin/test --core -q
    result: fail; the one integrated core run executed 830 tests with 3 failures: two fresh-process tests inherited the repository SYNAPSE_DUMP_DIR after replacing SYNAPSE_DATA_DIR, and one package-prompt test asserted superseded equivalent lease wording; non-failing SQLite ResourceWarnings and Python 3.14 fork deprecation warning were emitted
  - command: PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_contribution_method_recovery.ContributionMethodRecoveryTests.test_candidate_contrary_inconclusive_retry_and_process_restart test_contribution_method_recovery.ContributionMethodRecoveryTests.test_web_cve_web_method_refs_recover_after_process_restart test_tool_wrappers.ToolWrapperTests.test_main_prompt_uses_package_guidance_outside_repository_cwd -v
    result: pass; the three isolated failed core cases passed together after the scoped test-environment/assertion corrections; the full core suite was not retried
  - command: bin/test-modern -q
    result: fail; the one integrated modern run executed 17 tests with one negotiation-matrix error caused by stale generated modern fixtures; the other 16 tests completed, including direct stdio/HTTP and bounded readiness
  - command: PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest MCPS.Synapse-MCP.modern_tests.test_modern_adapter.ModernDiscoveryTests.test_both_surfaces_are_deterministic_on_modern_and_legacy_negotiation -q
    result: pass; the isolated negotiation regression passed all 10 compact/direct and current/older protocol combinations after the intentional modern-only fixture refresh; the full modern suite was not retried
  - command: PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_distribution test_modernization_docs test_tool_wrappers -q
    result: pass; 46 final distribution, documentation, and wrapper tests
  - command: git diff --cached --check
    result: pass; final implementation and checkpoint-record diffs have no whitespace errors
skipped_checks: >-
  The full core and modern suites were each run exactly once and were not
  retried wholesale after their scoped failures; only the named failed cases
  were rerun. The custom adapter template suite was not part of the requested
  core/modern release check. Completed-phase acceptance and benchmark gates
  remain retired. No live model/client comparison, discovery-ranking exercise,
  active target traffic, browser authentication, scanner binary, or third-party
  API check was run. 7R7.2 was not started.
known_issue: >-
  No known 7R7.1 package, skill/reference, current-state recovery, setup,
  direct-HTTP readiness, negotiation, action identity/order, legacy, or JSON-v1
  issue remains. The Python 3.14 official-SDK synchronous resource-read stall
  recorded at 7R5.3 did not reproduce in the bounded attempt, but one pass does
  not establish universal resolution of the earlier environment-sensitive
  behavior. The complete suites were deliberately not retried after the
  isolated corrections, so their recorded integrated outcomes remain 827/830
  and 16/17 with the failed cases passing separately. Historical pre-7R1.1
  duplicate candidates still require operator review. The bounded client
  comparison remains pending.
next_checkpoint: 7R7.2
next_action: >-
  Run 7R7.2 exactly as the bounded six-case saved-data client comparison in the
  Phase 7 plan: compare the previous helper route with the selected-method route
  on the same available model/runtime/budget, include the required restart,
  record actual versions/digests/coverage/attribution/calls/usage/corrections,
  and stop without active target traffic, discovery-ranking changes, another
  modernization phase, or broader client claims.
dirty_worktree: >-
  Only the pre-existing untracked review and source-plan documents remain:
  Synapse-Beta-Final-Review-2026-09-17.md and
  Synapse-Phase-7-Implementation-Tasks-2026-09-17.md.
```
