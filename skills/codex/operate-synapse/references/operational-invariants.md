# Synapse Operational Invariants

Apply these invariants to every assessment role.

## Canonical truth

- Recover compact workspace context before planning new work. Workspace
  entities, evidence, findings, tasks, authority records, work items, and
  revisions outrank chat memory.
- Use `tasks.control` to inspect jobs, operation handles, and work items. After
  a timeout or lease loss, inspect linked active or unknown execution before
  considering another action.
- Use `capabilities.search` and `actions.describe` for live behavior. Do not
  maintain a copied action catalog or JSON schema in a skill.

## Scope and authority

- Scope permits consideration and planning; it does not grant execution
  authority.
- A work-item claim, role, worker label, skill instruction, or `confirm=true`
  is coordination metadata, not authority.
- Every action still crosses canonical effects, scope, Authority Engine, and
  dispatch policy. On `approval_required`, stop that action and surface the
  uncovered requirement or supervised step-up; do not rewrite it as anonymous,
  passive, or supposedly equivalent execution.
- A covering server-held grant avoids redundant pauses only for work it
  actually covers. Never widen target scope from a grant.

## Passive, active, and recovery behavior

- Prefer local/passive analysis. Explain target, effects, expected impact, and
  risk before active traffic or state change.
- Never repeat an active or outcome-unknown action merely because a client,
  agent, heartbeat, or chat session disappeared. Poll or reconcile the linked
  job, dispatch, or operation handle.
- Use credential references and auth profiles; never place reusable secrets in
  work items, evidence notes, commands, or summaries.

## Evidence and conclusions

- Persist concrete facts, candidates, gaps, decisions, evidence, and useful
  references. Do not store chain of thought or transcript summaries.
- Scanner and heuristic analyzer output remains a candidate until validated and
  reviewed. A finding is lifecycle-managed truth; deterministic passive facts
  may remain pending operator review.
- Distinguish confirmed work, candidates, findings, contradictions, blockers,
  and unresolved gaps in every convergence summary.
- Internal `high_level` reporting is concise, not redacted or client-safe.
