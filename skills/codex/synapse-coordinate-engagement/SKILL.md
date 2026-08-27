---
name: synapse-coordinate-engagement
description: Coordinate an authorized Synapse engagement when independent perimeter, web, access-control, intelligence, or reporting objectives benefit from specialist work items and deliberate convergence. Avoid for a single short linear operation.
metadata:
  short-description: Coordinate bounded Synapse specialists
  synapse-role: coordinator
  synapse-pack: core
---

# Coordinate a Synapse Engagement

Read the shared [operational invariants](../operate-synapse/references/operational-invariants.md)
and [specialist workflow](../operate-synapse/references/specialist-workflow.md).

## Decide whether to decompose

Use specialist work items only when at least two objectives can proceed
independently or a dependency boundary makes ownership clearer. Execute a
simple read or short linear action chain directly. Coordination overhead is not
evidence of progress.

Never assign two specialists to send the same active traffic unless the
operator explicitly requests independent validation and canonical authority
covers each action.

## Define bounded work

Recover existing jobs, operation handles, work items, workspace revision,
scope, and authority before creating anything. For each new child item record:

- one objective and expected output;
- allowed targets and context boundary;
- role and relevant capability-pack hint;
- parent, dependencies, and exclusive/non-exclusive relationship;
- completion evidence and contract;
- stop or block conditions;
- handoff destination, next work, and known gaps.

Create reporting work with explicit dependencies when it must wait for
specialists. Do not place credentials, raw secrets, chat logs, or reasoning
traces in work items.

## Coordinate and recover

Have each specialist claim its item before work. On an exclusive claim
collision, direct the loser to useful compatible unclaimed work instead of
fighting the winner. Monitor durable progress and heartbeat state; recover
expired claims only after inspecting linked active or unknown execution.

If a specialist encounters missing scope, authority, authentication, evidence,
or operator input, preserve the concrete blocker. Do not instruct it to weaken
the test or change identity.

## Converge

Build final status from workspace facts, candidates, findings, evidence,
contradictions, completed/blocked items, and unresolved gaps. Do not aggregate
agent transcripts. Report what completed, what remains uncertain, which linked
execution needs reconciliation, and the next safe operator decision.
