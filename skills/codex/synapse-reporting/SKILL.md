---
name: synapse-reporting
description: Converge completed Synapse workspace truth into coherent internal operator or high-level reports. Use after required work-item dependencies resolve, or to report current coverage with explicit blockers and gaps.
metadata:
  short-description: Render coherent internal Synapse reports
  synapse-role: reporting
  synapse-pack: reporting
---

# Report from Workspace Truth

Read the shared [operational invariants](../operate-synapse/references/operational-invariants.md)
and follow the [specialist workflow](../operate-synapse/references/specialist-workflow.md)
when reporting is a claimed work item.

## Check readiness

Inspect reporting dependencies and linked execution before rendering. Wait for
required specialist work to complete. If a dependency is blocked or failed,
surface that state and decide whether an explicitly partial report satisfies
the completion contract; never silently treat missing coverage as complete.

## Build the narrative

Use workspace entities, reviewed findings, candidates, evidence, actions,
contradictions, coverage, blockers, and unresolved gaps. Do not merge agent chat
transcripts or use report output as the source of truth. Keep candidates
visually and textually separate from confirmed findings.

Use live capability search/description for the selected reporting layer and
format. `operator` is the detailed internal view. `high_level` is a concise
internal view, not a redaction boundary, sanitized export, or client-safe
deliverable. Keep generated reports self-contained and offline-safe.

## Complete

Link generated artifacts and selected evidence references, state the included
and omitted coverage, and record remaining gaps and next recommendations. A
reporting item completes only when its dependency and output contract are met;
otherwise block or hand off with the concrete missing input.
