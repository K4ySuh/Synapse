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
| 7R4 | In progress | 7R4.1 `987a567`; 7R4.2 pending | 7R4.2 |
| 7R5 | Pending | 7R5.1–7R5.3 pending | After 7R3 and 7R4 |
| 7R6 | Pending | 7R6.1–7R6.2 pending | After 7R3–7R5 |
| 7R7 | Pending | 7R7.1–7R7.2 pending | After 7R1–7R6 |

## Latest checkpoint record

```yaml
task: 7R4
checkpoint: 7R4.1
status: complete
review_base: 8134673a386ad00eed786d3d3ba841f00fcb28de
implementation_commit: 987a567ea5d122d781675ba966a91ae27c8d7dc0
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/README.md
  - MCPS/Synapse-MCP/modern_tests/test_modern_adapter.py
  - MCPS/Synapse-MCP/synapse_mcp/guidance.py
  - MCPS/Synapse-MCP/synapse_mcp/transport/modern/server.py
  - MCPS/Synapse-MCP/tests/test_distribution.py
  - bin/validate-codex-skills
  - bin/validate-distribution
  - docs/Operations.md
  - pyproject.toml
  - skills/README.md
  - skills/codex/web-methods/synapse-web-auth-session/SKILL.md
  - skills/codex/web-methods/synapse-web-auth-session/references/selection.md
  - skills/codex/web-methods/synapse-web-access-control/SKILL.md
  - skills/codex/web-methods/synapse-web-access-control/references/selection.md
contract_changes:
  - A single static package manifest identifies three existing entry skills and two optional web methods with stable IDs, kind, selection descriptions, source profile/path, and parent methodology. The original entry skill URIs remain intact.
  - The modern MCP catalog contains package and document metadata without bodies. Document versions, SHA-256 digests, and byte sizes derive from packaged bytes; package and catalog versions derive from their content. A modern server holds one startup snapshot for both advertised metadata and resource reads, so edits require restart.
  - Hosted SKILL.md and reference resources use the same files shipped by wheel and sdist. Only packaged SKILL.md and reference Markdown paths are registered; unknown paths fail. No action, operation, dispatch, state mutation, dynamic loader, or native optional installation was added.
checks:
  - command: PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_codex_skills test_distribution -q
    result: pass; 19 focused skill and distribution service tests
  - command: PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest MCPS/Synapse-MCP/modern_tests/test_modern_adapter.py -k operating_prompt_and_default_guidance_are_discoverable_read_only -q
    result: pass; one modern MCP resource test verifies all 12 document digests and sizes, resource metadata, unchanged eleven-tool count, and read-only behavior
  - command: bin/validate-codex-skills --check
    result: pass; three default skills and both hosted method packages/references validated
  - command: bin/validate-codex-skills --check --profile multi-agent-compat
    result: pass; eight retained compatibility skills validated
  - command: SYNAPSE_BUILD_PYTHON="$PWD/.venv/bin/python" SYNAPSE_BUILD_PYTHONPATH="$HOME/Projects/COAE/miniconda3/lib/python3.14/site-packages" bin/validate-distribution
    result: pass; wheel and sdist built and installed outside checkout, packaged guidance/digests verified, modern standard 174-action and core-only 42-action runtime startup passed for both archives. Initial unconfigured run lacked local setuptools/wheel; existing local Python 3.14 packages supplied the offline build prerequisites.
  - command: git diff --cached --check && .venv/bin/python -m compileall -q MCPS/Synapse-MCP/synapse_mcp/guidance.py MCPS/Synapse-MCP/synapse_mcp/transport/modern/server.py MCPS/Synapse-MCP/tests/test_distribution.py
    result: pass; staged implementation diff had no whitespace errors and changed Python files compiled
  - command: PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_modernization_docs -q
    result: fail; 4 of 5 tests passed, and the hostname hygiene test rejected a pre-existing Codex documentation link in the committed phase-7-plan.md. The same link is present in HEAD before this ledger update.
skipped_checks: >-
  Full core and modern suites were not run because the changed boundary is
  hosted guidance, packaging, and resource registration. Completed-phase
  acceptance and benchmark gates remain retired.
known_issue: >-
  The two hosted method packages currently provide selection and handoff
  guidance; their detailed methodology is scheduled for 7R5. Native Codex
  installation/selection is scheduled for 7R4.2. No external model client was
  exercised at this checkpoint. The modernization documentation hostname test
  has an unrelated pre-existing rejection of the phase plan's Codex docs link.
next_checkpoint: 7R4.2
next_action: >-
  Extend synapse_mcp/integrations/codex.py with an explicit optional web-methods
  skill profile and per-method agents/openai.yaml metadata. Use the guidance
  manifest for inventory, validate local and hosted bytes/references, and keep
  the default profile at exactly three skills without enabling multi-agent mode.
dirty_worktree: >-
  Only the pre-existing untracked review and source-plan documents remain:
  Synapse-Beta-Final-Review-2026-09-17.md and
  Synapse-Phase-7-Implementation-Tasks-2026-09-17.md.
```
