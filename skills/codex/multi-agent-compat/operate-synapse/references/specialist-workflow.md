# Specialist Work-Item Workflow

Use this workflow only in the explicitly selected `multi-agent-compat` profile
when a specialist receives or selects a Synapse work item.

## Recover and claim

1. Inspect the item with `tasks.control`. Claim it atomically if unclaimed, or
   validate the existing claim before acting.
2. If an exclusive claim loses a race, select useful compatible available work
   instead of retrying blindly; otherwise report the contention.
3. Query `context.query` with a bounded budget and continue from the item's
   last-seen revision rather than rebuilding the engagement.
4. Inspect linked active or unknown jobs, dispatches, and operations. Poll or
   reconcile them; lease expiry never makes replay safe.

## Plan from live capabilities

Search the selected Registry by role, intent, pack, target type, and effects.
Describe only actions needed for the objective. Keep local/passive analysis
separate from authority-gated active validation.

## Maintain durable progress

- Heartbeat while useful work is ongoing.
- Update concise progress, last-seen revision, canonical references, next work,
  and unresolved gaps. Persist operational truth, not reasoning traces.
- Link and poll active execution instead of starting a duplicate.

## Finish deliberately

- Complete only when the contract is met; include a concise result, references,
  remaining uncertainty, and next recommendation.
- Hand off when another role owns remaining work.
- Block with a concrete reason when scope, authority, authentication, evidence,
  dependency, or operator input is missing.
