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
| 7R6 | Pending | 7R6.1–7R6.2 pending | After 7R3–7R5 |
| 7R7 | Pending | 7R7.1–7R7.2 pending | After 7R1–7R6 |

## Latest checkpoint record

```yaml
task: 7R5
checkpoint: 7R5.3
status: complete
review_base: 8134673a386ad00eed786d3d3ba841f00fcb28de
implementation_commit: d95c043574f89fb18e836199e63209cbe3062171
branch: Beta
changed_files:
  - MCPS/Synapse-MCP/tests/test_contribution_method_recovery.py
  - MCPS/Synapse-MCP/tests/test_single_agent_default.py
  - skills/README.md
  - skills/codex/default/operate-synapse/references/single-agent-workflow.md
  - skills/codex/default/synapse-cve-intelligence/SKILL.md
  - skills/codex/default/synapse-web-pentesting/SKILL.md
  - skills/codex/default/synapse-web-pentesting/references/selection-and-resumption.md
contract_changes:
  - The default Web and CVE skills now document one short selection and resumption workflow, explicit Web/CVE transitions, and clear missing-package and digest-mismatch remedies.
  - Accepted analysis reuses contribution v1.1's typed methodRef for the selected package ID and current catalog digest. Historical digests remain immutable provenance; a digest change alone neither invalidates nor duplicates a stored result.
  - A fresh-process regression proves canonical saved-data recovery across Web to CVE to Web. The returning Web contribution updates its existing candidate, a second consumer recovers both method attributions, and direct same-operator work creates no work item.
  - No action, schema, Registry, authority, execution, workspace, agent-topology, or 7R6 heuristic contract changed.
checks:
  - command: bin/validate-codex-skills --check && bin/validate-codex-skills --check --profile web-methods && bin/validate-codex-skills --check --profile multi-agent-compat
    result: pass; three default skills, all eight optional web methods, and eight compatibility skills validated with local and hosted references resolved
  - command: for skill in skills/codex/default/operate-synapse skills/codex/default/synapse-web-pentesting skills/codex/default/synapse-cve-intelligence; do python /home/kaysuh/.codex/skills/.system/skill-creator/scripts/quick_validate.py "$skill"; done
    result: pass; all three changed default skills passed frontmatter and structure validation
  - command: PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_contributions test_contribution_method_recovery test_saved_data_integration test_context_compiler -q
    result: pass; 25 contribution, restart recovery, saved-data, and context tests; Python emitted one unclosed-SQLite ResourceWarning after the passing run
  - command: PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest test_single_agent_default test_distribution -q
    result: pass; 20 default-skill, hosted-guidance, package-content, and distribution tests
  - command: SYNAPSE_BUILD_PYTHON="$PWD/.venv/bin/python" SYNAPSE_BUILD_PYTHONPATH="$HOME/Projects/COAE/miniconda3/lib/python3.14/site-packages" .venv/bin/python <inline verifier using validate-distribution archive, install, and installed-guidance helpers>
    result: pass; fresh wheel and sdist built and installed outside the checkout, every installed guidance document and digest resolved, all installed skill profiles validated, and the new 4,276-byte reference was present in both artifacts
  - command: timeout 60s env PYTHONPATH=MCPS/Synapse-MCP:MCPS/Synapse-MCP/tests .venv/bin/python -m unittest MCPS/Synapse-MCP/modern_tests/test_modern_adapter.py -k operating_prompt_and_default_guidance_are_discoverable_read_only -q
    result: unavailable; exit 124 with no test output; a bounded diagnostic reproduced the stall on the unchanged synapse://prompt/main resource in the official SDK anyio.to_thread synchronous-resource path
  - command: git diff --cached --check && .venv/bin/python -m py_compile MCPS/Synapse-MCP/tests/test_contribution_method_recovery.py MCPS/Synapse-MCP/tests/test_single_agent_default.py
    result: pass; final implementation diff had no whitespace errors and both changed Python tests compiled
skipped_checks: >-
  Full core and modern suites were not run; 7R5.3 changes methodology and a
  focused saved-data regression. The full distribution command reached its
  installed modern runtime smoke but was stopped after the same SDK synchronous
  resource-read stall; wheel/sdist build, install, content, digest, and skill
  validation passed separately. Completed-phase acceptance and benchmark gates
  remain retired. No live model comparison was run.
known_issue: >-
  No known 7R5.3 content, contribution, context, or packaged-asset issue remains.
  The current Python 3.14 official SDK direct client stalls when dispatching a
  synchronous resource read through anyio.to_thread, including unchanged
  resources; the hosted catalog is covered by direct distribution tests, and
  the runtime smoke should be retried after that environment issue is repaired.
  The small client comparison remains reserved for 7R7.
next_checkpoint: 7R6.1
next_action: >-
  Inventory existing adapter operations from Action Registry descriptors and
  ownership, classify each as deterministic parsing/extraction, heuristic
  interpretation, command/provider execution, or lifecycle/persistence
  support, then map every heuristic interpretation operation to the relevant
  one of the eight method skills without changing action IDs, Registry
  authority, execution paths, or default helper behavior yet.
dirty_worktree: >-
  Only the pre-existing untracked review and source-plan documents remain:
  Synapse-Beta-Final-Review-2026-09-17.md and
  Synapse-Phase-7-Implementation-Tasks-2026-09-17.md.
```
