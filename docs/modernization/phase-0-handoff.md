# Phase 0 Handoff

## Identity

- Phase: 0 — freeze and baseline
- Branch: `modernization/phase-0-baseline`
- Baseline commit: `099ba1aec4873b3ac08ffbecd82a45c06753880f`
- Head commit: `4bcba55` (post-handoff hygiene/backfill)
- Commit range: `099ba1a..4bcba55` (9 commits)
- Implementer/model: OpenAI Codex
- Date: 2026-07-29

## Objective

Freeze the observable legacy MCP surface, representative result behavior, and
deterministic workflows before modernization changes production architecture.
Record reproducible measurements and architecture decisions so later phases can
prove compatibility against evidence rather than assumption.

## Delivered

- Five byte-exact Tier-1 protocol fixtures; `errors.json` contains seven frozen
  cases, including the deterministic `-32003` tool-timeout envelope.
- Fourteen normalized-exact Tier-2 result fixtures covering passive, active,
  destructive-local, credential, third-party, and background-job operations.
- A seven-workflow deterministic benchmark corpus covering context budgets,
  disabled traffic, background execution, timeout recovery, and reporting.
- Six ADRs covering the application boundary, action registry, authority,
  compatibility profiles, storage, and context revisions.
- A reproducible baseline for the tool surface, test progression, context
  budget behavior, error taxonomy, and fixture counts.
- A four-version Python CI matrix with full-suite, contract, and clean-tree
  checks.
- Hardened fixture and documentation guards plus this phase handoff.

## Explicitly not changed

- No production code under `synapse_mcp/` changed.
- No public tool name, schema, protocol version, authority behavior, storage
  format, dependency range, or runtime default changed.
- Across the phase-output range, exactly one file that existed at the baseline
  was modified: `docs/README.md`, by one added pointer line. One post-handoff
  hygiene commit follows `72b7205` on this branch; it touches `.gitignore` and
  this document only, and changes no production code.
- No tag, release, migration, or production deployment was performed. The Phase
  0 head now exists on `origin/Beta`; no successful remote Python-matrix run is
  cited by this handoff.

## Architecture decisions

| Decision | ADR | Status |
| --- | --- | --- |
| Generic agents remain the cognitive plane; Synapse is the operational plane | ADR-0001 | Accepted |
| Introduce a typed application core and one Action Registry | ADR-0002 | Accepted |
| Replace caller-asserted confirmation with durable Authority Grants | ADR-0003 | Proposed |
| Preserve legacy and modern MCP compatibility profiles | ADR-0004 | Proposed |
| Move toward SQLite plus content-addressed artifacts | ADR-0005 | Proposed |
| Add context revisions and enforced budget behavior | ADR-0006 | Proposed |

## Public compatibility

| Surface | Before | After | Equivalence | Evidence |
| --- | --- | --- | --- | --- |
| Initialization and protocol | `2025-03-26` | `2025-03-26` | exact | `initialize.json`; baseline metric guard |
| Tool discovery | 174 ordered tools; 99,337 compact schema bytes | unchanged | exact | `tools_list.json`; hard count and byte assertions |
| Resource and prompt discovery | legacy lists | unchanged | exact | `resources_list.json`; `prompts_list.json` |
| Deterministic JSON-RPC errors | legacy envelopes | seven frozen cases | exact | `errors.json`, including `-32003` |
| Generic `-32000` failure | environment-bearing message | same code and non-empty message | semantic | shape assertion; intentionally not frozen |
| Representative tool results | legacy payloads | unchanged modulo five declared normalizer rules | semantic | fourteen Tier-2 fixtures and live-type assertions |
| Active safety gates | approval `-32001`; scope denial `-32002` | unchanged | exact | named gate assertions and byte-exact fixtures |
| Background submission and status | generated job handle and terminal result | unchanged | semantic | normalized-exact submission/status fixtures |
| `jobs.status(includeResult=True)` | environment-bearing `run` block | same pinned shape | semantic | shape assertion; interpreter path intentionally unfrozen |

## Safety and authority evidence

- Scope: the out-of-scope crawler fixture freezes `-32002`, while allowed
  fixture hosts are checked against an explicit allowlist.
- Authority: the unconfirmed crawler fixture freezes `-32001` and the
  `confirm=true` approval message; the named gate test pins both codes.
- Credentials: the planted canary is absent from every fixture, while the
  legacy masked result remains frozen for later remediation.
- Dispatch/retry: workflow 06 proves a simulated timeout recovers the original
  background job without increasing the job count.
- Evidence linkage: identifiers and result structure are preserved in live
  responses; normalization affects committed fixture copies only and retains
  stable first-seen identifier relationships.

## Data and migration

- Store/schema version: unchanged.
- Migration: none; Phase 0 adds only tests, fixtures, documentation, and CI
  configuration.
- Rollback: revert the Phase 0 commits; no runtime data transformation is
  required.
- ID/provenance preservation: production identifiers and storage are unchanged;
  contract tests assert live identifier types before fixture normalization.

## Verification

| Command/test | Result |
| --- | --- |
| `bin/test` | PASS — 414 core tests and 2 template tests |
| `bin/test --core -k contracts` | PASS — 30 tests; five consecutive stable runs |
| Contract regeneration | PASS — two consecutive regenerations had the same whole-tree checksum |
| Contract fixture inventory | PASS — 5 Tier-1 plus 14 Tier-2 files; 19 total |
| Workflow benchmark corpus | PASS — all 7 deterministic workflows |
| Fixture leakage and host guards | PASS — no residual path, planted canary, generated ID, or forbidden host |
| Modernization documentation guard | PASS — no absolute path, planted canary, or non-fixture host |
| Production-range diff | PASS — no file under `synapse_mcp/` changed |

## Measurements

| Metric | Baseline | Current | Delta |
| --- | ---: | ---: | ---: |
| Tool count | 174 | 174 | 0 |
| Schema bytes | 99,337 compact; 168,671 pretty | 99,337 compact; 168,671 pretty | 0 |
| Approval interruptions | Authority coverage baseline: 47 tools expose `confirm` | No agent interruption run; baseline retained | not claimed |
| Context bytes/tokens | 4,024–4,026 characters; about 1,006 estimated tokens | No production change; baseline retained | not re-measured |

## Known limitations

- The Phase 0 head is present on `origin/Beta`, closing the earlier unpushed
  condition (M-2). The operator confirmed on 2026-07-30 that the four-version
  matrix (3.10–3.13) ran green on this head, which is the basis for treating the
  `requires-python = ">=3.10"` floor as exercised rather than asserted. The
  evidence of record is Javier Roldán Ortiz's local full-matrix attestation dated
  2026-07-30. No remote CI run URL exists or is expected because remote CI is
  deliberately deferred for this project.
- `jobs.status(includeResult=True)` is shape-asserted rather than frozen because
  its `run` block embeds the environment-specific interpreter path.
- The generic `-32000` response is shape-asserted rather than frozen because
  its reachable prompt-file failure embeds an environment-specific path.

## Risks for the next phase

- Phase 2 must map its reason codes onto the observable `-32001` approval and
  `-32002` scope taxonomy, or explicitly supersede that contract.
- The legacy credential mask retains the first and last four characters of
  longer values; Phase 5 must address this under the recorded report-boundary
  decision.
- `maxTokens` measured at 0% budget adherence. Phase 4 must enforce it and
  report truncation or omissions.
- A tracked Phase 0 integrity prerequisite must land before Phase 2 persists
  authority state.

## Worktree status

After the handoff commit, tracked files are clean. The `Modernization/`
planning and review pack remains the expected local source material and is not
part of the committed phase output; it is now gitignored so that its private
findings cannot be committed by an accidental broad `git add`.

## Recommended gate

PASS

The local compatibility, determinism, documentation, and benchmark evidence is
green, and Phase 0 changed no production behavior. The gate is promoted on that
record, Javier Roldán Ortiz's Python 3.10–3.13 full-matrix attestation, and his
checkpoint sign-off on 2026-08-06. Remote CI evidence is explicitly out of scope
by operator decision.
