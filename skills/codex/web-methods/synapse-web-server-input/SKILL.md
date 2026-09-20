---
name: synapse-web-server-input
description: Select when the current web question concerns SQL, command, template, or SSI interpretation of server-side input.
metadata:
  short-description: Analyze server-side input handling evidence
  synapse-role: method
  synapse-pack: web
---

# Server input method

Use this package for one bounded question about server-side query, command,
template, or SSI interpretation. Read the family-specific
[procedure](references/selection.md) and the main web skill's common method
contract. Hosted, the contract is at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`;
for native skills, open
`synapse-web-pentesting/references/method-contract.md` under the installed skill
root.

Recover the current workspace revision and referenced evidence first. Keep the
input, transformations, interpreter boundary, observable result, and benign
alternatives distinct. Use live action descriptions for any deterministic
helper, execution, or canonical contribution.
