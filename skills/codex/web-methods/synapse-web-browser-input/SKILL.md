---
name: synapse-web-browser-input
description: Select when the current web question concerns browser input reaching executable markup or script contexts, client navigation, or redirect decisions.
metadata:
  short-description: Analyze browser input and redirect evidence
  synapse-role: method
  synapse-pack: web
---

# Browser input method

Use this package for one bounded question about browser interpretation or a
redirect decision. Read the family-specific
[procedure](references/selection.md) and the main web skill's common method
contract. Hosted, the contract is at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`;
for native skills, open
`synapse-web-pentesting/references/method-contract.md` under the installed skill
root.

Recover the current workspace revision and referenced evidence first. Keep the
browser source, transformation, sink, execution or navigation context, and
security policy distinct. Use live action descriptions for any deterministic
helper, execution, or canonical contribution.
