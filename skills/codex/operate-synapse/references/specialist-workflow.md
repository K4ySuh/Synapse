# Specialist Work-Item Workflow

Use this workflow when a specialist receives or selects a Synapse work item.

## Recover and claim

1. Inspect the item with `tasks.control`. Claim it atomically if unclaimed, or
   validate the existing claim before acting.
2. If an exclusive claim loses a race, do not retry blindly. List compatible
   available work and select a useful remaining item; otherwise report the
   contention to the coordinator.
3. Query `context.query` with the workspace, work item, matching claim when
   available, and a bounded budget. Continue from the item's last-seen
   workspace revision rather than rebuilding the engagement.
4. Inspect linked active or unknown jobs, dispatches, and operation handles.
   Poll or reconcile them; never infer that lease expiry makes replay safe.

## Plan from live capabilities

Search the selected Registry by role, intent, pack, target type, and effects.
Describe only the candidate actions needed for the objective. Keep local/passive
analysis separate from authority-gated active validation, and preserve the
target/context and completion boundaries recorded on the item.

## Maintain durable progress

- Heartbeat while useful work is ongoing.
- Update concise progress, last-seen workspace revision, evidence/artifact and
  domain references, next work, and unresolved gaps. Persist operational truth,
  not reasoning traces.
- If execution returns an active job or supervised operation handle, link and
  poll it instead of starting a duplicate.

## Finish deliberately

- Complete only when the completion contract is met; include a concise result,
  references, remaining uncertainty, and next recommendation.
- Hand off when another role owns the remaining objective; state completed and
  outstanding work plus the destination role.
- Block with a concrete reason when scope, authority, authentication, evidence,
  dependency, or operator input is missing. Missing authority is a blocker, not
  permission to choose a different identity or weaker test.
