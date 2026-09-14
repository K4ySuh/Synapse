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
| 6R5 | Pending | 6R5.1, 6R5.2, 6R5.3 pending | Add bounded recovery lookup |
| 6R6 | Pending | 6R6.1, 6R6.2 pending | Extract one saved-data integration seam |
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R4
checkpoint: 6R4.3
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: 2d81f14
branch: Beta
changed_files:
  - AGENTS.md
  - CHANGELOG.md
  - MCPS/Synapse-MCP/README.md
  - MCPS/Synapse-MCP/modern_tests/test_modern_adapter.py
  - MCPS/Synapse-MCP/synapse_mcp/guidance.py
  - MCPS/Synapse-MCP/synapse_mcp/integrations/codex.py
  - MCPS/Synapse-MCP/synapse_mcp/operational_prompt.md
  - MCPS/Synapse-MCP/synapse_mcp/transport/modern/server.py
  - MCPS/Synapse-MCP/synapse_mcp/transport/stdio_server.py
  - MCPS/Synapse-MCP/tests/test_distribution.py
  - bin/validate-distribution
  - config/codex/standard.toml
  - docs/Operations.md
  - docs/modernization/phase-6-status.md
  - skills/README.md
contract_changes:
  - Modern MCP prompts/list and resources/list expose synapse-main and synapse://prompt/main from the shared package-level prompt reader; legacy retrieval shape and configured-path override remain intact.
  - Modern resources/list exposes a static read-only guidance catalog plus three default skill files and four references with stable URIs, package version, SHA-256 digests, descriptions, and 64 KiB read limit.
  - Hosted default guidance and local Codex installation resolve the same asset tree; resource discovery does not activate a skill. Compact remains eleven tools; no Registry, state, authority, migration, or frozen fixture change.
checks:
  - command: bin/test --core -q
    result: pass; 803 tests after correcting a legacy patched-path regression found by the first run
  - command: bin/test-modern -q
    result: pass; 17 isolated modern-adapter tests including prompt/resource reads and exact wire fixtures
  - command: bin/validate-codex-skills --check
    result: pass; three default skills and their local references
  - command: bin/validate-codex-skills --check --profile multi-agent-compat
    result: pass; eight compatibility skills and their local references
  - command: SYNAPSE_BUILD_PYTHON="$PWD/.venv/bin/python" SYNAPSE_BUILD_PYTHONPATH=/usr/lib/python3.14/site-packages SYNAPSE_RUNTIME_PYTHON="$PWD/.venv/bin/python" .venv/bin/python bin/validate-distribution
    result: pass; wheel and sdist installed outside checkout; prompt, guidance, contribution schema, standard 174-action/eleven-tool and core-only 42-action startup verified
  - command: PYTHONPATH=tests ../../.venv/bin/python -m unittest test_modernization_docs test_distribution test_single_agent_default -q
    result: pass; 21 focused documentation, distribution, and profile tests
  - command: git diff --cached --check
    result: pass; no whitespace errors
remaining_issue: >-
  No external Codex/Daybreak client build was exercised for this task; exact
  direct-client compatibility remains the bounded 6R7.2 exercise. MCP resource
  discovery alone cannot install or activate a Codex skill.
next_checkpoint: 6R5.1
next_action: >-
  Add a bounded run/job/recent-evidence recovery lookup using existing lifecycle
  metadata, then verify restart reconstruction in the focused state/service tests.
dirty_worktree: >-
  Tracked 6R4 implementation committed at 2d81f14; only pre-existing untracked
  Synapse-Reconvert-Phase.md remains untouched after the checkpoint record commit.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
