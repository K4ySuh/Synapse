---
name: synapse-engagement-bootstrap
description: Initialize or recover an authorized Synapse engagement, its exact scope, workspace, passive inputs, and first bounded context. Use before assessment roles when durable engagement state is absent or unclear.
metadata:
  short-description: Bootstrap authorized Synapse state
  synapse-role: bootstrap
  synapse-pack: core
---

# Bootstrap a Synapse Engagement

Read the shared [operational invariants](../operate-synapse/references/operational-invariants.md).
When bootstrap is a claimed work item, also follow the
[specialist workflow](../operate-synapse/references/specialist-workflow.md).

## Recover before creating

Identify the operator-authorized assets and look for an existing workspace,
revision, active jobs, work items, dumps, and evidence. Do not initialize a new
workspace merely because chat context is missing. If several assets are
present, preserve whether the operator described them as related, unrelated,
or separate engagements.

## Establish durable context

When no workspace exists, initialize only the exact authorized hosts, patterns,
or CIDRs supplied by the operator. Keep scope and execution authority separate.
Ingest operator notes or passive artifacts into workspace truth, then obtain a
bounded context snapshot and identify concrete coverage gaps.

Prefer passive local inputs for the first assessment picture. If authentication
will matter, capture the flow requirements and request approved credential or
auth-profile handling later; do not embed secrets in bootstrap notes.

## Finish or route

For a simple request, return the workspace ID, scope status, revision, available
passive context, active/unknown work, and next safe action without creating a
coordination tree. For broader independent objectives, hand the recovered state
to `$synapse-coordinate-engagement` with explicit targets and gaps.
