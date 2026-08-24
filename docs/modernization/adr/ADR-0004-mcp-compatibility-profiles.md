# ADR-0004: Legacy and modern MCP compatibility profiles

- Status: Accepted
- Date: 2026-08-24
- Owners: Synapse architectural lead
- Applies from: Phase 3 after acceptance
- Supersedes: None

## Context

The current stdio server implements MCP framing, validation, discovery, and
dispatch directly and advertises protocol revision `2025-03-26`. Its ordered
174-tool surface has no output schemas, annotations, or titles. The official
Python MCP SDK is not a core dependency. Phase 0 fixtures now preserve
initialization, tools, resources, prompts, errors, and representative results,
while P0-3 provides a behavioral corpus for volatile workflows.

Rechecked on 2026-08-23, the normative MCP revision remains `2026-07-28` and
the official Python SDK stable release remains 2.0.0. Phase 3C pins
`mcp==2.0.0` in the isolated `modern` optional extra. Sources: the
[official specification](https://modelcontextprotocol.io/specification/2026-07-28),
[official SDK release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0),
and [PyPI project metadata](https://pypi.org/project/mcp/2.0.0/).

Replacing the transport in place would combine protocol adoption with a public
compatibility break. Keeping only the hand-written transport would prevent
modern protocol capabilities and official SDK conformance from being evaluated.

## Decision

Adopt the official Python MCP SDK for a new adapter while preserving the
current stdio launcher and `2025-03-26` behavior as the frozen legacy
compatibility path. The legacy surface is not removed in the first migration
and no removal date is set.

Treat three choices as orthogonal:

1. **MCP wire revision** is negotiated between client and server. It determines
   protocol framing and capabilities only.
2. **Synapse surface** is selected by trusted operator configuration as
   `legacy`, `modern-compact`, or `modern-direct`. It determines which action
   projection is published, independent of the negotiated wire revision.
3. **Principal and authority** come from authenticated, server-held execution
   context and Authority Grants. They are never inferred from the wire
   revision, surface selection, client/server display metadata, or model input.

A newer client may deliberately use the legacy surface, and a modern surface
does not imply more authority. A surface selection never changes scope or
creates a principal.

The first implementation was a feature-flagged feasibility spike with exactly
three Registry v2 actions. Phase 3C replaces it with the production
`synapse-mcp-modern` adapter. The former spike entry point and extra remain
deprecated forwarding/installation aliases, not an independent surface.

Phase 3B implements the transport-independent side of this decision. The
`modern-compact` application projection exposes exactly eleven ordered
operations and serializes to 21,648 bytes of deterministic metadata under the
Phase 3 measurement. `modern-direct` generates one operation for each of the
174 canonical descriptors. Both call the same Registry seam; neither imports
the MCP SDK or chooses a default modern surface.

Phase 3C implements the adapter side with official SDK 2.0.0 over stdio and
authenticated Streamable HTTP. It publishes one trusted startup-selected
surface, persists opaque operation/resource bindings, resolves principals to
server-held workspace/authority sessions, and uses a rotating keyring whose
first key seals while every configured key may unseal. Sealed request state is
bound to the principal and stable audience. Loopback remains the HTTP default;
remote startup requires explicit enablement, authentication, allowed hosts and
origins, a persistent keyring, and direct-TLS or trusted-proxy policy. This did
not preselect the Phase 3D default decision.

The original 2026-08-23 Phase 3D attempt did not meet its two-client rule:
Claude Code could not authenticate and stable Codex negotiated an older wire
revision. On 2026-08-24 the operator removed Claude as a required client and
approved a Codex-only closure amendment. The amendment treats protocol-native
`input_required` and Synapse's typed application-level approval handle as
equivalent safe carriers, provided restart, binding, replay, and exactly-once
tests pass. It forbids under-development Codex protocol flags.

Codex CLI `0.149.0` then passed three independent modern-compact stdio runs.
Each run performed one passive read, one supervised interruption with no
dispatch, one exact trusted step-up, a fresh MCP process, one opaque-handle
resume, trace continuity, and exactly one successful dispatch. Inspector and
automated suites retain both-transport, protocol, conformance-classification,
security, workflow, and legacy-contract coverage. `modern-compact` stdio is
therefore the Codex default. `legacy` remains the frozen rollback/bootstrap
path and `modern-direct` remains explicit diagnostic compatibility.

The 2026-08-24 adversarial corrective retained that Codex-only Phase 3 release
gate.
It reclassified the exact-tool choreography as a transport/safety smoke and
added an objective-driven seven-workflow gate with no supplied tool names,
canonical action IDs, exact arguments, or call counts. Codex passed both 3/3
with zero schema retries for deterministic cases, zero duplicate side effects
or dispatches, and zero external target traffic. Independent agent clients are
outside the Phase 3 named-client acceptance gate, so no universal cross-agent
claim follows. Provider-neutral application and protocol contracts remain a
project invariant, and cross-agent objective benchmarks remain a later product
acceptance track. Generic Inspector/conformance evidence remains a separate
verdict and does not depend on a named model client.

## Invariants

- Tier-1 and Tier-2 contract fixtures remain green; every delta is classified exact, semantically equivalent, or intentionally changed with a recorded decision.
- SDK versions are pinned exactly and isolated from the default stable
  installation, whether stable or prerelease.
- The modern profile omits `confirm` from its schema and never treats a supplied
  value as authority.
- No security decision is based on self-reported client or server display metadata.
- Protocol negotiation cannot select a Synapse surface or authority profile.
- Surface selection cannot authenticate a principal, widen scope, or grant
  execution authority.
- Principal/session/grant selection is server-held and is not part of action
  input or display metadata.
- Dynamic action arguments are revalidated by the selected descriptor. Passive
  invocation rejects canonical maximum effects that include traffic,
  credential/secret use, remote mutation, or local destruction before dispatch.
- Local artifacts use opaque principal/session/workspace/version-bound
  references and are reauthorized on every read; model-facing results do not
  expose raw filesystem paths.
- HTTP client identity is authenticated only through the digest-backed bearer
  resolver; `clientInfo`, forwarded display values, and tool arguments cannot
  create a principal or authority context.
- Request-state keys, authority bindings, and bearer-token digests are private
  operator files. Remote HTTP fails closed without persistent rotation and an
  explicit transport trust policy.
- Modern adoption is additive and must retain a passing stable-Codex live gate,
  deterministic payloads, server-side workflow/security suites, and the frozen
  legacy rollback contract.

## Alternatives considered

### Replace the legacy server in place

- Benefits: One transport implementation and immediate SDK adoption.
- Costs: Protocol, schema, serialization, and dispatch changes become
  inseparable, with no stable compatibility path.
- Reason rejected/deferred: The Phase 0 contracts exist specifically to prevent
  an unclassified replacement.

### Keep the hand-written MCP transport indefinitely

- Benefits: No new dependency and exact current behavior.
- Costs: Ongoing protocol maintenance and no clean route to newer negotiated
  capabilities.
- Reason rejected/deferred: It preserves the baseline but cannot deliver the
  modern adapter objective.

### Let SDK types define the application core

- Benefits: Minimizes mapping between application and protocol objects.
- Costs: Reverses the dependency direction and makes MCP the core model.
- Reason rejected/deferred: ADR-0002 requires protocol-independent application
  services.

## Consequences

- Positive: Modern SDK behavior can be tested additively against a stable legacy
  reference.
- Negative: Two explicit profiles coexist during migration and require
  compatibility classification; the modern surface has compact and direct
  projections, so three explicit surfaces coexist during evaluation.
- Operational: launchers negotiate the wire protocol and separately consume a
  trusted operator-selected Synapse surface. Authenticated execution context is
  supplied through its own server boundary.
- Security: Display metadata remains informational; policy uses server-held
  scope and authority. Compact operation and resource handles contain no grant
  secret or authority session and cannot be replayed across bindings.
- Compatibility: No legacy removal date is implied. Additional clients are
  compatibility targets, not adoption blockers, unless the operator explicitly
  adds them to a future acceptance contract.

## Migration and rollback

Build the modern adapter over the typed application services from ADR-0002.
Keep the existing launcher and legacy surface unchanged while adding protocol
negotiation plus compact and direct projections. Store surface selection only
in trusted operator configuration; keep authenticated principal/authority
context separate. Pin the official SDK exactly in an isolated optional
environment. Classify every contract delta. Rollback selects the legacy surface
and launcher without changing wire negotiation, grants, or operational state.
The current rollback is to stop `synapse-mcp-modern` and use the unchanged
`synapse-mcp` launcher. No grant, workspace, or legacy contract change is
required.

The legacy launcher, canonical Registry, and retained implementation bridge do
not depend on `app/facade/` or `transport/modern/`. The 2026-08-23 blocked run
and the 2026-08-24 Codex closure amendment are both recorded in the Phase 3
handoff and machine-readable evidence. Rollback remains a configuration choice,
not a data migration.

## Verification

- Run every Tier-1 and Tier-2 contract under the legacy profile.
- Compare modern responses as exact, semantically equivalent, or intentionally
  changed with a recorded decision.
- Run the stable-Codex live read/approval/restart/resume gate three times
  against the fictional disabled-traffic fixture.
- Test protocol negotiation and refusal of unsupported revisions.
- Cross-product test wire revision, selected surface, and authority profile so
  no dimension silently selects either of the others.
- Inspect dependency metadata to confirm prerelease SDK isolation and exact
  pinning.
- Run the official SDK client against both stdio and loopback Streamable HTTP,
  and assert that active no-authority calls return `input_required` without
  reaching Registry dispatch.
- Assert exactly eleven compact operations, 174 direct operations, deterministic
  schema serialization below 24,834 bytes, complete catalog filters, passive
  pre-dispatch denial, server-held authority input rejection, exactly-once
  resume, and cross-principal/workspace/version resource denial.
- Test key rotation/restart, expiry, tamper, retired-key, wrong-principal, and
  wrong-audience denials; authenticated HTTP Host/Origin/protocol/body-header
  consistency; and unsafe remote startup combinations.
