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

Replacing the transport in place would combine protocol adoption with a public
compatibility break. Keeping only the hand-written transport would prevent
modern protocol capabilities and official SDK conformance from being evaluated.

## Decision

Adopt the official Python MCP SDK for a new adapter while preserving the current stdio launcher and `2025-03-26` behaviour behind an explicitly selected `legacy` profile. Negotiate the protocol version and target a newer revision only when the client advertises it. The legacy surface is not removed in the first migration and no removal date is set.

## Invariants

- Tier-1 and Tier-2 contract fixtures remain green; every delta is classified exact, semantically equivalent, or intentionally changed with a recorded decision.
- Prerelease SDKs are pinned exactly and isolated from the default stable installation.
- No security decision is based on self-reported client or server display metadata.
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
  compatibility classification.
- Operational: Launchers and client configuration must select or negotiate a
  profile unambiguously.
- Security: Display metadata remains informational; policy uses server-held
  scope and authority.
- Compatibility: No legacy removal date is implied, and target clients must
  pass the same workflow corpus before modern adoption.

## Migration and rollback

Build the modern adapter over the typed application services from ADR-0002.
Keep the existing launcher and legacy profile unchanged while adding protocol
negotiation and modern projections. Pin any prerelease SDK exactly in an
isolated optional environment. Classify every contract delta. Rollback disables
the modern profile and returns clients to the legacy launcher without migrating
operational state.

## Verification

- Run every Tier-1 and Tier-2 contract under the legacy profile.
- Compare modern responses as exact, semantically equivalent, or intentionally
  changed with a recorded decision.
- Run the seven-workflow corpus through both target clients against identical
  scope, authority, and workspace data.
- Test protocol negotiation and refusal of unsupported revisions.
- Inspect dependency metadata to confirm prerelease SDK isolation and exact
  pinning.
