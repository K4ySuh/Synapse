---
name: operate-synapse
description: Route and operate authorized Synapse assessment work. Use for engagement recovery, simple direct operations, or selecting bounded coordinator, bootstrap, perimeter, web, access-control, CVE, and reporting playbooks. Do not use for Synapse repository development.
metadata:
  short-description: Route authorized Synapse operations
  synapse-role: router
  synapse-pack: core
---

# Operate Synapse

Use Synapse workspace state—not chat history—as operational truth. Read
[operational invariants](references/operational-invariants.md) before acting.
Use [the specialist workflow](references/specialist-workflow.md) when taking or
delegating a claimed work item.

## Route the request

Recover the trusted workspace, current revision, active jobs/operation handles,
work items, scope, and authority state first. Then choose the smallest useful
mode:

- Handle a simple context read, inspection, or single bounded operation
  directly. Do not require a coordinator merely because work items exist.
- Use `$synapse-engagement-bootstrap` when authorized assets need a workspace,
  scope initialization, or initial passive context.
- Use `$synapse-coordinate-engagement` when two or more objectives are
  independent enough to benefit from specialist work and later convergence.
- Use `$synapse-perimeter-triage` for infrastructure, perimeter, fingerprint,
  or passive OSINT objectives.
- Use `$synapse-web-assessment` for web surface, JavaScript, authentication, or
  vulnerability-candidate assessment.
- Use `$synapse-access-control` for actor/object/property authorization models
  and expected-allow versus expected-deny comparisons.
- Use `$synapse-cve-validation` for version-aware CVE correlation and bounded
  verification planning.
- Use `$synapse-reporting` after required dependencies are complete or when the
  operator asks for a current internal report with explicit gaps.

If the request concerns Synapse code, tests, architecture, or documentation,
route to `$synapse-developing` instead.

## Discover live behavior

Use `capabilities.search` to find currently selected, available actions by
intent, capability pack, target, task suitability, effects, and risk. Use
`actions.describe` before execution when exact inputs, effects, authority, or
availability matter. Never substitute a copied action catalog or remembered
schema for the live Registry.

For direct work, query bounded context, perform the smallest safe operation,
persist useful facts/evidence/gaps, and return a concise status. For decomposed
work, create bounded work items before delegation and converge from workspace
entities and references rather than agent transcript aggregation.
