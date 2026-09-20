---
name: synapse-web-auth-session
description: Select when the current web question concerns authentication or session behavior, including login transitions, cookies, tokens, logout, recovery, or CSRF evidence.
metadata:
  short-description: Analyze authentication and session evidence
  synapse-role: method
  synapse-pack: web
---

# Authentication and session method

Use this package for one bounded question about how authenticated state starts,
persists, changes, recovers, or ends. Read the on-demand
[method procedure](references/selection.md) and the main web skill's common
method contract. Hosted, the contract is at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`;
for native skills, open
`synapse-web-pentesting/references/method-contract.md` under the installed skill
root. The family procedure reuses the shared identity comparison foundations.

Recover the current workspace revision and referenced evidence before analysis.
Use live action descriptions for any execution or contribution contract. Keep
reported or inferred conclusions separate from directly observed behavior;
scope and server-held authority continue to govern active work.
