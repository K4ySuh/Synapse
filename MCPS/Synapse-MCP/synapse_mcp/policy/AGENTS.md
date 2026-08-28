# Authority and Policy Instructions

- Treat authorization scope and execution authority as independent inputs.
  `ScopeDenied` cannot be repaired by selecting or broadening a grant.
- `legacy` retains exact `confirm=true` gates and approval metadata. Modern
  profiles evaluate only trusted server-held principal, session, grant, and
  step-up state; caller arguments cannot assert them.
- Coordination labels, agent-run IDs, roles, work-item claims, and handoffs are
  attribution metadata only. They must never affect scope, credentials, effects,
  risk, budgets, or authorization decisions.
- Build and seal one exact `ExecutionPlan` before policy evaluation. Preserve
  target, redirect, provider-route, method, credential, output, effect,
  replay-safety, risk, and budget dimensions.
- Reserve dispatch authority atomically immediately before execution. Ambiguous
  or outcome-unknown work requires reconciliation and must not be replayed.
- Keep operator grant management in trusted local services/CLI surfaces. Do not
  add model-executable self-granting actions or return stored secret values.
- Add negative tests for cross-principal/workspace/session binding, stale
  request state, budget contention, coordination-identity escalation, and
  supervised resume exactly-once behavior.
