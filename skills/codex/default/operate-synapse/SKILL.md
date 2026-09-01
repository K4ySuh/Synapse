---
name: operate-synapse
description: Operate an authorized Synapse engagement as one Codex agent. Use to recover workspace truth, perform direct work, maintain durable progress, and load Web Pentesting or CVE Intelligence methodology when needed. Do not use for Synapse repository development.
metadata:
  short-description: Operate Synapse as one durable agent
  synapse-role: operator
  synapse-pack: core
---

# Operate Synapse

Use Synapse workspace state—not conversation memory—as operational truth. Read
[operational invariants](references/operational-invariants.md) before acting and
follow the [single-agent workflow](references/single-agent-workflow.md) through
recovery, execution, skill transitions, restarts, and convergence.

## Recover and choose the methodology

Recover the trusted workspace, current revision, active or outcome-unknown
execution, durable work, scope, and authority state first. Continue useful
existing work before creating new coordination records. Then choose the
smallest useful mode:

- Handle inspection, bounded context, local analysis, one action, job polling,
  and current-state reporting directly. Do not create a work item merely to
  narrate a short linear task.
- Load `$synapse-web-pentesting` for bootstrap, perimeter and application
  mapping, JavaScript, authentication, access-control, vulnerability
  hypotheses, bounded active validation, or web-assessment convergence.
- Load `$synapse-cve-intelligence` for product/version/CPE normalization,
  CVE/NVD/KEV/vendor and public-PoC research, applicability analysis, or
  bounded validation recommendations.
- Use both skills sequentially when observed web or perimeter components need
  vulnerability intelligence. Keep the same workspace revision, references,
  active execution, open gaps, and authority boundary when changing methods.

If the request concerns Synapse code, tests, architecture, or documentation,
route to `$synapse-developing` instead.

## Discover live behavior

Use `capabilities.search` to find currently selected, available actions by
intent, capability pack, target, task suitability, effects, and risk. Use
`actions.describe` before execution when exact inputs, effects, authority, or
availability matter. Never substitute a copied action catalog or remembered
schema for the live Registry.

For direct work, query bounded context, perform the smallest safe operation,
persist useful facts, evidence, negative results, and gaps, then converge from
workspace truth. Create or claim durable work only for restart recovery,
dependencies, long-running responsibility, or coordination with an independent
consumer or human. A work-item claim never grants authority.

Do not spawn sub-agents during the default operating profile. The preserved
Phase 5 coordinator/specialist methodology is available only through the
explicit `multi-agent-compat` integration profile selected by the operator.
