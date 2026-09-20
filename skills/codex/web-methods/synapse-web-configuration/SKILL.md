---
name: synapse-web-configuration
description: Select when the current web question concerns security headers, CORS, cookie attributes, TLS, or deployment configuration evidence.
metadata:
  short-description: Analyze web security configuration evidence
  synapse-role: method
  synapse-pack: web
---

# Configuration method

Use this package for one bounded question about headers, cross-origin policy,
cookie attributes, TLS, or another deployed web security setting. Read the
family-specific [procedure](references/selection.md) and the main web skill's
common method contract. Hosted, the contract is at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`;
for native skills, open
`synapse-web-pentesting/references/method-contract.md` under the installed skill
root.

Recover the current workspace revision and referenced evidence first. Relate a
setting to the actual route, origin, actor, data, client, and trust boundary;
keep hardening gaps separate from demonstrated security effects. Use live
action descriptions for any deterministic helper, execution, or canonical
contribution.
