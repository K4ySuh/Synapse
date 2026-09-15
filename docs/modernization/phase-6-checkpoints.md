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
| 6R7 | Pending | 6R7.1, 6R7.2, 6R7.3 pending | Run current integrated service checks |

## Latest checkpoint record

```yaml
task: 6R6
checkpoint: 6R6.2
status: complete
review_base: 5a33b238020ff987ecf38dd3afcacca81d13de1a
implementation_commit: a7cf5a9
branch: Beta
changed_files:
  - CHANGELOG.md
  - MCPS/Synapse-MCP/modern_tests/test_modern_adapter.py
  - MCPS/Synapse-MCP/synapse_mcp/adapters/web/spec_import.py
  - MCPS/Synapse-MCP/synapse_mcp/core/saved_spec_import.py
  - MCPS/Synapse-MCP/synapse_mcp/guidance.py
  - MCPS/Synapse-MCP/tests/fixtures/integrations/saved-openapi.json
  - MCPS/Synapse-MCP/tests/test_distribution.py
  - MCPS/Synapse-MCP/tests/test_saved_data_integration.py
  - README.md
  - bin/validate-distribution
  - docs/Architecture.md
  - docs/Implementation-Map.md
  - docs/Integration-Convention.md
  - docs/Operations.md
  - docs/README.md
  - docs/modernization/README.md
  - skills/codex/default/synapse-web-pentesting/SKILL.md
  - skills/codex/default/synapse-web-pentesting/references/saved-data-integrations.md
contract_changes:
  - spec_import.import_spec and its same-named legacy alias retain their existing input/output shape, effects, serializer, and canonical entities through a forwarding adapter wrapper.
  - OpenAPI, Swagger, and Postman detection, parsing, redaction, normalization, evidence creation, and adapter_result ingestion now live in the protocol-independent core.saved_spec_import seam.
  - The hosted default guidance catalog adds saved-data-integrations.md; modern-compact remains eleven operations and no Registry, contribution, legacy fixture, JSON-v1, or state schema changes were made.
checks:
  - command: cd MCPS/Synapse-MCP && PYTHONPATH=tests ../../.venv/bin/python -m unittest test_saved_data_integration test_web_discovery_adapters.SpecImportAdapterTests test_architecture_boundaries test_distribution -q
    result: pass; 17 focused pilot, retained import, architecture, and distribution tests
  - command: bin/validate-codex-skills --check && bin/validate-codex-skills --check --profile multi-agent-compat
    result: pass; 3 default skills and 8 multi-agent compatibility skills validated with all local references
  - command: bin/test --core -q
    result: pass; 810 tests. The first run found stale output-contract derivation at the forwarding wrapper; wrapped-function introspection restored the existing 168-action generated contract without changing it.
  - command: bin/test-modern -q
    result: pass; 17 isolated modern-adapter tests including eight hosted guidance documents and exact wire fixtures
  - command: SYNAPSE_BUILD_PYTHON="$PWD/.venv/bin/python" SYNAPSE_BUILD_PYTHONPATH=/usr/lib/python3.14/site-packages SYNAPSE_RUNTIME_PYTHON="$PWD/.venv/bin/python" .venv/bin/python bin/validate-distribution
    result: pass; wheel and sdist installed outside checkout; eight hosted guidance documents, standard 174-action and core-only 42-action startup verified
  - command: git diff --cached --check
    result: pass; no whitespace errors
remaining_issue: >-
  The pilot covers one saved specification importer. Other saved formats,
  passive analyzers, consumer-interpreted facts, and guarded active/provider
  adapters are classified for future migration but are not rewritten by 6R6.
next_checkpoint: 6R7.1
next_action: >-
  Run the current integrated service checks once, record exact versions and
  results, then continue to the bounded direct-client exercise in 6R7.2.
dirty_worktree: >-
  Tracked 6R6 implementation committed at a7cf5a9; only pre-existing untracked
  Synapse-Reconvert-Phase.md remains untouched after the checkpoint record commit.
```

The Daybreak preference applies to the future operator-selected model. Codex
host, protocol, SDK, and package compatibility are separate questions for the
recorded direct-client exercise in 6R7.2; this ledger makes no live-client pass
claim. Full observer/provider coverage and counterfactual evaluation remain
deferred.
