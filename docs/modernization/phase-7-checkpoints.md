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
| 7R7 | Pending | 7R7.1–7R7.2 pending | 7R7.1 |

## Latest checkpoint record

```yaml
task: 7R6
checkpoint: 7R6.2
status: complete
review_base: 8134673a386ad00eed786d3d3ba841f00fcb28de
implementation_commit: c67df237d775c6b471fda946a4a2849b94931a09
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/tests/test_contribution_method_recovery.py
  - MCPS/Synapse-MCP/tests/test_modernization_docs.py
  - MCPS/Synapse-MCP/tests/test_saved_data_integration.py
  - MCPS/Synapse-MCP/tests/test_single_agent_default.py
  - docs/Adapter-Development.md
  - docs/Operations.md
  - docs/modernization/phase-7-operation-transition-map.md
  - docs/modernization/phase-7-status.md
contract_changes:
  - Operations and adapter guidance now make the saved-evidence/current-question skill route the documented default. Retained heuristic helpers remain explicitly selectable for concrete questions; no analyzer was removed, no web capability was disabled, and no default bulk analyzer or automatic candidate-ingestion workflow was added.
  - An explicit graphql.analyze_workspace regression crosses ActionExecutionService and the canonical Registry, then verifies its ingested evidence and candidate in the activated SQLite-v2 workspace repository.
  - A method-package removal regression proves that a previously accepted contribution and its historical method ID/digest remain readable through compact context when the optional package is absent.
  - Method packages remain client guidance, separate from six-pack startup selection and server-held authority. New integration guidance assigns deterministic contracts, parsers, extraction, normalization, and bounded executors to integrations while replaceable methodology owns interpretation.
  - Runtime contracts are unchanged: all 174 Registry IDs retain exact frozen legacy schemas/order, modern-direct projects the same ordered IDs, and modern-compact remains eleven operations. Analyzer modules, the web pack, action availability, workspace/evidence/execution paths, and contribution schemas are unchanged.
  - No concrete usage evidence requires a discovery-ranking change. Any additive preference and explicit override remain deferred to the bounded 7R7 client exercise.
checks:
  - command: bin/generate-action-inventory --check && PATH="$PWD/.venv/bin:$PATH" bin/generate-capability-pack-ownership --check
    result: pass; canonical inventory 174 actions and ownership 174 actions across six packs unchanged
  - command: PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_action_inventory test_action_projection test_capability_packs test_capability_discovery test_contributions test_contribution_method_recovery test_saved_data_integration test_single_agent_default test_distribution test_modernization_docs -q
    result: pass; 72 focused inventory, frozen compatibility, projection, ownership, discovery, contribution, saved-data, skill-surface, distribution, and documentation tests; one unclosed-SQLite ResourceWarning after success
  - command: PATH="$PWD/.venv/bin:$PATH" PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_authority_integration.AuthorityRegistryIntegrationTests.test_observe_workspace_read_and_explicit_observation_write test_authority_integration.AuthorityRegistryIntegrationTests.test_authority_is_not_exposed_as_model_executable_actions -v
    result: pass; two focused checks confirm observe-mode analyzer execution remains grant-bound and authority is not model-executable
  - command: bin/validate-codex-skills --check && bin/validate-codex-skills --check --profile web-methods && bin/validate-codex-skills --check --profile multi-agent-compat
    result: pass; three default, eight optional web, and eight compatibility skills validated
  - command: python "$HOME/.codex/skills/.system/skill-creator/scripts/quick_validate.py" skills/codex/default/operate-synapse && python "$HOME/.codex/skills/.system/skill-creator/scripts/quick_validate.py" skills/codex/default/synapse-web-pentesting
    result: pass; both default entry skill packages passed frontmatter and structure validation
  - command: git diff --cached --check
    result: pass; final implementation diff had no whitespace errors
skipped_checks: >-
  Full core and modern suites and a new wheel/sdist install were not run because
  7R6.2 changes documentation and focused regressions without changing runtime
  or packaged skill assets; 7R7.1 owns the integrated installed release check.
  The official-SDK synchronous resource-read smoke was not rerun: its Python
  3.14 stall was recorded at 7R5.3 and this slice does not change that path.
  Completed-phase acceptance and benchmark gates remain retired. No live model
  or discovery-ranking exercise was run.
known_issue: >-
  No known 7R6.2 compatibility, helper-path, saved-data, skill, or documentation
  issue remains. The official SDK synchronous resource-read stall observed with
  Python 3.14 at 7R5.3 was not retested, so it is not claimed resolved; direct
  repository resource, catalog, digest, and distribution tests pass. Installed
  runtime validation and the small client comparison remain for 7R7.
next_checkpoint: 7R7.1
next_action: >-
  Validate installed behavior and fix the remaining setup polish: run the
  focused 7R1-7R3 regressions; validate default, optional-method, and
  compatibility assets outside the checkout; run the current core and modern
  suites once; bound direct-HTTP startup readiness with surfaced errors; put
  modern-compact first in setup documentation; and verify current-state bundle
  recovery with contribution receipts and analysis metadata. Preserve existing
  test organization, frozen fixtures, legacy/modern-direct/JSON-v1 behavior,
  and existing migration/rollback boundaries.
dirty_worktree: >-
  Only the pre-existing untracked review and source-plan documents remain:
  Synapse-Beta-Final-Review-2026-09-17.md and
  Synapse-Phase-7-Implementation-Tasks-2026-09-17.md.
```
