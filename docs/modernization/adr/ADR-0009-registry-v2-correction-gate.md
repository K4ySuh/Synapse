# ADR-0009: Registry v2 correction gate

- Status: Accepted
- Date: 2026-08-09
- Owners: Synapse operator and implementation lead
- Applies from: correction gate before Phase 2
- Supersedes: singular action-effect authority and input-type dispatch in the Phase 1 slice

## Context

The Phase 1 slice preserved legacy contracts but selected actions by input-model
type, carried a singular side-effect label, did not validate declared output
models, and duplicated operational adapter metadata. Atomic replacement also
left credential read-modify-write cycles exposed to lost updates. Those defects
made the proposed Authority Engine unsafe to implement directly.

## Decision

Route execution by explicit canonical `action_id`; validate the corresponding
input model and canonical typed output at one Registry boundary; represent
maximum and request-effective effects across independent dimensions; evaluate
runtime availability before policy; and derive migrated adapter operational
metadata from action descriptors. Credential mutations hold one lock across the
entire state transition. Phase 2 consumes these contracts and does not consume
the legacy singular effect projection.

The official MCP Python SDK 2.0.0 and normative revision `2026-07-28` are proven
only in a reversible three-action spike. The stable legacy profile is unchanged.

## Invariants

- A registered executor is invoked only inside `ActionRegistry.execute(action_id, request)`.
- Shared input models are legal and never influence routing.
- Every successful migrated action carries its declared validated output model.
- Maximum effects cannot be exceeded by an effective resolver; uncertainty uses the maximum and records why.
- Availability precedes policy and dispatch.
- Adapter discovery is informational and cannot authorize execution.
- Modern calls never treat `confirm=true` as authority.
- Credential mutations cannot read state before acquiring their store lock.

## Alternatives considered

### Keep singular side-effect classes

- Benefits: small grant comparisons.
- Costs: hides simultaneous traffic, evidence, workspace, job, artifact, and credential effects.
- Reason rejected/deferred: grants would authorize an incomplete effect picture.

### Publish the modern spike as the default server

- Benefits: immediate modern protocol surface.
- Costs: only three actions and no durable authority model have been proven.
- Reason rejected/deferred: the spike is a technology gate, not Phase 2 or Phase 3 completion.

### Use atomic replacement without transaction locking

- Benefits: fewer lock-held operations.
- Costs: concurrent valid updates can overwrite each other.
- Reason rejected/deferred: crash atomicity does not prevent lost updates.

## Consequences

- Positive: Authority Grants can evaluate the actual action and effective
  effects, and modern output schemas describe enforced models.
- Negative: legacy compatibility keeps an explicit raw payload beside the
  canonical application result until the stable profile is retired.
- Operational: migrated adapter metadata needs an application-layer provider;
  unmigrated adapters remain on a named transitional bridge.
- Security: unresolved effects fail conservatively and active modern dispatch
  remains `input_required` without server-held authority.

## Migration and rollback

Migrate remaining actions individually using the v2 descriptor pattern; do not
bulk-copy the schema converter. Rollback disables `SYNAPSE_ENABLE_MODERN_SPIKE`
and keeps the stable `synapse-mcp` launcher. The legacy dispatch switch can
return an individual migrated call to its preserved branch without changing its
descriptor-owned legacy input schema.

## Verification

- Registry routing/shared-model/mismatch/bypass and invalid-output tests.
- Maximum/effective effect tests for all six actions and ordering tests for availability.
- Adapter divergence tests against descriptor-derived fields.
- Deterministic contended-lock tests for credential upsert, delete, and profiles.
- Official-SDK in-memory, stdio, and loopback Streamable HTTP tests.
- Two clean local HTTP vertical runs with vulnerable and safe controls.
- Frozen legacy contract suite, full suite, templates, and seven workflow benchmarks.
