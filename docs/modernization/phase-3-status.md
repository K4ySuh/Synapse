# Phase 3 running status

Updated: 2026-08-19
Current session: Phase 3A — canonical action surface
Baseline: `6f46dae128520e06056dce50632e750023aedc80` on `Beta`
State: Session 3A complete; Session 3B not started

## Preflight

- Worktree began clean; local and remote `Beta` matched the reviewed baseline.
- `git merge-base --is-ancestor 6f46dae HEAD` returned success.
- The root `AGENTS.md`, Phase 3 execution pack, Phase 3A brief, Phase 2 status
  and handoff, modernization index, ADR-0004, existing migration pattern,
  registry/policy/projection implementations, and relevant tests were read.
- The requested `action-migration-guide.md` did not exist at entry. Phase 3A
  added it and marked the older `action-migration-pattern.md` as historical,
  replacing the one-action-per-commit rule with bounded pack batches.

## Baseline stability evidence

- `bin/test`: 565 core tests passed in 40.827 seconds; 2 template tests passed.
  Workflow calls remained `1,5,1,2,3,6,1`.
- Fresh retained Python 3.13 modern environment with official `mcp==2.0.0`,
  `SYNAPSE_PYTHON=<MODERN_ENV>/bin/python bin/test-modern`:
  6 tests passed in 2.819 seconds.
- CVE provider pause regression: 25/25 isolated process runs passed.
- No-network workflow benchmark regression: 25/25 isolated process runs
  passed.

The reviewed CVE failure was a genuine test-harness timing race: a real
wall-clock assertion observed only the *remaining* persisted provider pause
after response handling, so scheduler/IO time could reduce a nominal 30 ms
pause below the asserted 20 ms. Phase 3A now uses an injected deterministic
provider clock and asserts the exact coordinated sleep.

The reviewed workflow failure occurred at the background-job boundary while
the benchmark changed process-global state paths. The harness now waits for
watchdog/process-handle cleanup and for the intentionally timed-out tool thread
before releasing the isolated root. No retry or relaxed assertion was added.

## Migration ledger

| Reviewed use case | Actions | State |
|---|---:|---|
| control_plane | 5 | complete |
| reporting | 20 | complete |
| engagement_state | 24 | complete |
| credentials_auth | 10 | complete |
| local_artifacts | 5 | complete |
| web_assessment | 62 | complete |
| app_discovery | 10 | complete |
| scanner_execution | 9 | complete |
| infrastructure_osint | 18 | complete |
| cve_intelligence | 11 | complete |

All 174 actions now enter `ActionRegistry.execute()` first. Six native pack
executors remain in place; 168 descriptors use the protocol-free retained-
implementation bridge, with the old dispatch body independently callable as a
per-action rollback adapter. The generated manifest fixes canonical IDs,
legacy aliases, models, classifications, availability, implementation targets,
serializer ownership, migration state, and parity-test location.

The 40 pack counts are: access_control 6, adapters 2, cache 4,
command_injection 4, cors 4, crawler 2, credentials 10, csrf 3, cve 11,
documentation 17, dumps 1, evidence 4, ffuf 3, fingerprint 4, graphql 4,
headers_cookies 2, insecure_deser 2, jobs 3, js 7, jwt 2, lfi 4, nmap 3,
nuclei 3, open_redirect 3, perimeter 3, project 1, purple_team 1, scope 2,
shodan 14, sitemap 1, social 1, spec_import 2, sqli 3, ssi 5, ssrf 3, ssti 5,
tls_posture 2, workspace 15, xss 4, and xxe 4.

## Frozen equivalence

- Live legacy discovery deep-equals the approved fixture: 174 names in the
  exact order with exact descriptions and JSON Schemas.
- The compact tools array remains exactly 99,337 UTF-8 bytes.
- All 174 aliases dispatch through the Registry by default. Removing one ID
  from `LEGACY_DISPATCH_ACTIONS` preserves descriptor-owned discovery and
  validation while falling back to the retained implementation branch.
- Six field-specific native output models remain; each of the other 168 actions
  has a distinct typed JSON-object result model with the common
  status/background/job/result/error core and JSON-checked additional fields.
- Missing ffuf, Nuclei, or nmap executables and missing Shodan provider
  configuration are asserted as typed unavailability.

## Final verification

- Baseline regressions after the deterministic fixes: CVE provider pause 25/25
  isolated runs; no-network workflow corpus 25/25 isolated runs.
- Inventory/descriptor gate: 7 tests passed; registry negative gate: 21 tests
  passed; action contract gate: 15 tests passed.
- Legacy projection/result/contract gates: 3 projection, 6 slice, 21 result,
  and 13 byte-contract tests passed.
- Authority/exactly-once/ledger/continuation gates: 15 integration, 18
  repository, 17 execution-truth, 12 job-lifecycle, and 5 credential-
  confinement tests passed.
- `bin/test`: 576 core tests passed in 43.065 seconds; 2 template tests passed.
  Workflow calls remained `1,5,1,2,3,6,1`.
- `SYNAPSE_PYTHON=<MODERN_ENV>/bin/python bin/test-modern`: 6 official-SDK
  tests passed in 3.342 seconds.
- `python -m compileall -q MCPS/Synapse-MCP/synapse_mcp
  MCPS/Synapse-MCP/tests`, `bin/generate-action-inventory --check`, and
  `git diff --check` passed.

## Deferred by the session boundary

- The retained implementation adapter remains the explicit rollback target;
  physical branch retirement requires a separate decision.
- The official-SDK spike remains exactly three actions. Compact/direct facade,
  modern transport expansion, and interoperability/default decisions belong to
  Sessions 3B–3D.
- ADR-0004 remains Proposed until those later sessions implement and verify the
  complete compatibility decision.

PHASE_3A_PASS
