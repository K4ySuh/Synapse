# ADR-0004: Legacy and modern MCP compatibility profiles

- Status: Proposed
- Date: 2026-07-28
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

On 2026-08-09 the normative MCP revision was `2026-07-28` and the official
Python SDK stable release was 2.0.0. The correction gate pins `mcp==2.0.0` in
the `modern-spike` optional extra. Sources: the
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

The first implementation is a feature-flagged feasibility spike with exactly
three Registry v2 actions. It proves stdio, loopback Streamable HTTP,
negotiation, typed input/output schemas, structured content, annotations, and
`input_required` without active dispatch. It is not the default adapter.

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
- Modern adoption is additive until both target clients pass the fixed benchmark corpus.

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
  scope and authority.
- Compatibility: No legacy removal date is implied, and target clients must
  pass the same workflow corpus before modern adoption.

## Migration and rollback

Build the modern adapter over the typed application services from ADR-0002.
Keep the existing launcher and legacy surface unchanged while adding protocol
negotiation plus compact and direct projections. Store surface selection only
in trusted operator configuration; keep authenticated principal/authority
context separate. Pin the official SDK exactly in an isolated optional
environment. Classify every contract delta. Rollback selects the legacy surface
and launcher without changing wire negotiation, grants, or operational state.
The current rollback is to unset `SYNAPSE_ENABLE_MODERN_SPIKE` and use the
unchanged `synapse-mcp` launcher.

## Verification

- Run every Tier-1 and Tier-2 contract under the legacy profile.
- Compare modern responses as exact, semantically equivalent, or intentionally
  changed with a recorded decision.
- Run the seven-workflow corpus through both target clients against identical
  scope, authority, and workspace data.
- Test protocol negotiation and refusal of unsupported revisions.
- Cross-product test wire revision, selected surface, and authority profile so
  no dimension silently selects either of the others.
- Inspect dependency metadata to confirm prerelease SDK isolation and exact
  pinning.
- Run the official SDK client against both stdio and loopback Streamable HTTP,
  and assert that active no-authority calls return `input_required` without
  reaching Registry dispatch.
