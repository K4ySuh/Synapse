# Phase 3 execution plan

Status: complete; `modern-compact` is the Codex default
Started: 2026-08-19
Baseline: `6f46dae128520e06056dce50632e750023aedc80` on `Beta`

This plan implements the operator-provided Phase 3 execution pack as four
strictly sequential sessions. Sessions 3A through 3D are complete. The
operator-approved 2026-08-24 acceptance contract closes against stable Codex
without an experimental protocol flag. Codex is the sole project acceptance
client unless the operator explicitly changes this plan.

## Session sequence

| Session | Scope | Exit gate |
|---|---|---|
| 3A | Canonical descriptors, implementations, inventory, and frozen legacy parity for all 174 actions | `PHASE_3A_PASS` |
| 3B | Protocol-independent compact and direct services | `PHASE_3B_PASS` |
| 3C | Official-SDK modern MCP adapter, identity, and durable request-state security | `PHASE_3C_PASS` |
| 3D | Fixed-corpus interoperability, default decision, conformance, and formal closure | `PHASE_3_PASS` |

## Session 3D outcome

- The exact payload gate passes: legacy remains 174 tools / 99,337 bytes,
  the compact application projection is 11 / 22,863 bytes, and the direct
  application projection is 174 / 1,513,976 bytes. Separate official-SDK wire
  fixtures are hash checked for every supported revision.
- The sole acceptance client is stable Codex, which may use Synapse's
  application-level approval handle when its negotiated revision cannot carry
  protocol request state.
- `bin/run-phase3d-codex` explicitly leaves the under-development
  `mcp_2026_07_28` feature disabled and runs the fictional no-network fixture
  three times through real `codex exec` sessions.
- All three repetitions passed passive inspection, one approval interruption,
  exact trusted step-up, MCP process restart, opaque-handle resume, trace
  continuity, and exactly one successful dispatch. Each of the nine stages
  made exactly one expected MCP tool call with no duplicate calls.
- Inspector and automated suites retain discovery, Streamable HTTP, protocol,
  resource, job, denial, cross-binding, and frozen-legacy coverage.
- The adversarial corrective gate adds exact transport/safety cases and an
  objective-driven seven-workflow corpus. Codex passed both 3/3 with no
  experimental feature, no unauthorized/duplicate dispatch, zero schema
  retries for deterministic calls, and zero external traffic.

`modern-compact` stdio is adopted as the Codex default. `legacy` remains a
frozen rollback/bootstrap profile; `modern-direct` remains explicit and
diagnostic. ADR-0004 is Accepted, with no legacy removal date.

## Phase 3A gates

1. Reproduce and stabilize the reviewed baseline without retries, skipped
   tests, or relaxed thresholds.
2. Check in a deterministic inventory derived from the frozen legacy contract,
   reviewed Appendix A classifications, and canonical descriptors.
3. Strengthen descriptor validation for aliases, models, effects, authority,
   availability, implementation identity, and deterministic projection.
4. Migrate the remaining 168 actions in coherent capability batches while
   preserving the legacy adapter as the rollback path.
5. Prove exact 174-name/order/schema parity and the 99,337-byte compact payload.
6. Amend ADR-0004 and the migration/architecture/testing guidance only after
   executable behavior passes.
7. Run focused inventory, parity, policy, authority, job, ledger, full core,
   modern SDK, compile, and diff gates. Record `PHASE_3A_PASS` or an exact
   blocker in `phase-3-status.md`.

## Fixed decisions

- MCP wire revision, Synapse surface mode, and authenticated authority are
  independent.
- The canonical registry is protocol-independent and is the only execution
  entry for migrated actions.
- The frozen legacy launcher remains independently usable and unchanged at its
  public contract.
- Unknown availability, effect, intent, or output facts fail closed; Phase 3A
  does not invent successful capability.
- Phase 3B application code contains no MCP SDK or transport imports. No Phase
  3C adapter implementation is permitted before the 3B gate passes.

## Phase 3B gates

1. Expose exactly eleven compact application operations in deterministic order.
2. Provide bounded catalog search and exact schema/effect/policy description
   over all 174 canonical actions.
3. Revalidate dynamic action input/output and route passive, active, direct,
   review, report, and task work only through `ActionRegistry.execute()`.
4. Reject model-supplied authority identity and fail the passive gate before
   dispatch on traffic, credential/secret, remote-mutation, or destructive
   maximum effects.
5. Resume supervised approval through opaque bound handles exactly once.
6. Replace local paths with opaque principal/session/workspace/version-bound
   resources that reauthorize every read.
7. Prove direct/compact descriptor equivalence, deterministic serialization
   below 24,834 bytes, all existing suites, compile, inventory, and diff gates.

## Phase 3C gates

1. Publish one startup-selected compact or direct surface through pinned
   official SDK 2.0.0 over stdio and authenticated Streamable HTTP.
2. Bind stdio/HTTP principals to server-held workspace and authority context;
   reject client metadata, model arguments, and untrusted headers as identity.
3. Persist bound operation/resource records and rotate principal/audience-bound
   request-state keys across restart and workers.
4. Map success, approval/input-required, operational error, protocol error, and
   opaque resource links deliberately with complete schemas and annotations.
5. Fail remote startup closed without explicit authentication, Host/Origin,
   persistent keyring, remote enablement, and TLS/proxy trust policy.
6. Verify both transports, both surfaces, every SDK-supported revision,
   exactly-once resume, Inspector availability, all core/modern suites,
   compile, inventory, and diff gates.
