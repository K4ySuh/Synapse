# Phase 3 execution plan

Status: active; Phase 3C complete
Started: 2026-08-19
Baseline: `6f46dae128520e06056dce50632e750023aedc80` on `Beta`

This plan implements the operator-provided Phase 3 execution pack as four
strictly sequential sessions. Sessions 3A, 3B, and 3C are complete.
Interoperability/default work remains isolated to Session 3D.

## Session sequence

| Session | Scope | Exit gate |
|---|---|---|
| 3A | Canonical descriptors, implementations, inventory, and frozen legacy parity for all 174 actions | `PHASE_3A_PASS` |
| 3B | Protocol-independent compact and direct services | `PHASE_3B_PASS` |
| 3C | Official-SDK modern MCP adapter, identity, and durable request-state security | `PHASE_3C_PASS` |
| 3D | Fixed-corpus interoperability, default decision, conformance, and formal closure | Separate Codex session after 3C passes |

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
