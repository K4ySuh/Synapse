# ADR-0001: Generic agents as cognitive plane, Synapse as operational plane

- Status: Accepted
- Date: 2026-07-28
- Owners: Synapse architectural lead
- Applies from: Phase 0 architecture baseline
- Supersedes: None

## Context

Synapse currently exposes a local MCP control plane to an external agent. The
repository prompt assigns the agent investigation strategy while the server
implements scope checks, approval gates, bounded adapters, credentials by
reference, workspace state, evidence, background jobs, context preparation, and
reports. The transport dispatches a simple tool call directly to the requested
operation; neither the package dependencies nor the application core contain a
model provider or an embedded planning loop.

The modernization needs a stable ownership boundary before application
services, authority, protocol adapters, storage, and context compilation are
changed. Without it, later phases could duplicate agent reasoning in the server,
couple core behavior to one provider, or turn every direct operation into
mandatory orchestration.

## Decision

Generic coding/security agents own reasoning, prioritization, hypothesis formation, and investigation strategy. Synapse owns scope, authority, bounded execution, durable engagement state, evidence, provenance, task recovery, context compilation, and reporting. Synapse will not contain an LLM planner, investigation engine, or mandatory agent loop.

## Invariants

- No provider-specific model code in the application core.
- A simple action remains a single direct call; no mandatory multi-stage ceremony.
- Any Synapse-produced recommendation is advisory and never self-executes.
- Beru is out of scope for this program.

## Alternatives considered

### Embed a planner and investigation loop in Synapse

- Benefits: One product could select tools, order investigations, and execute
  complete playbooks without relying on an external reasoning client.
- Costs: Duplicates the cognitive plane, couples operational safety to planning
  quality, and turns simple actions into orchestration.
- Reason rejected/deferred: It contradicts the product boundary and would make
  provider-neutral application services harder to preserve.

### Put provider-specific behavior in the application core

- Benefits: Provider features and prompt conventions could be optimized close
  to execution.
- Costs: Provider changes would affect safety-critical code and make cross-agent
  evaluation incomparable.
- Reason rejected/deferred: Optional integrations belong at distribution edges,
  not in the operational plane.

### Expose only low-level storage and scanner primitives

- Benefits: Keeps the server small and leaves all composition to clients.
- Costs: Loses consistent scope, authority, evidence, recovery, and provenance
  semantics across clients.
- Reason rejected/deferred: Synapse's value is a controlled operational
  substrate, not disconnected primitives.

## Consequences

- Positive: Reasoning clients can evolve independently while sharing the same
  safety and operational truth.
- Negative: Synapse cannot compensate for weak investigation strategy by adding
  an internal planner.
- Operational: Recommendations and context remain available to agents but never
  dispatch actions by themselves.
- Security: Scope, authority, execution, evidence, and recovery stay
  server-enforced rather than prompt-enforced.
- Compatibility: Existing direct MCP tool calls remain valid; this decision
  changes no wire behavior.

## Migration and rollback

Each later phase must preserve a direct application-service path independent of
MCP and model providers. Provider-specific packaging may call protocol adapters
but cannot move inward. If a migration introduces mandatory planning or
provider coupling, rollback is to retain the legacy direct adapter and remove
the coupling before the phase gate; no stored-data migration is required for
this decision.

## Verification

- Keep dependency and architecture tests free of provider SDK imports in the
  application core.
- Preserve the P0-3 one-call simple workflows.
- Review recommendations to confirm they carry no self-executing behavior.
- Run the fixed cross-agent corpus in later gates using the same application
  actions and safety state.
