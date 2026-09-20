---
name: synapse-web-business-logic
description: Select when the current web question concerns workflow state, sequencing, replay, concurrency, quantities, or application-specific business invariants.
metadata:
  short-description: Analyze workflow and business-rule evidence
  synapse-role: method
  synapse-pack: web
---

# Business logic method

Use this package for one bounded question about workflow state, ordering,
replay, concurrency, quantities, or another application-specific invariant.
Read the family-specific [procedure](references/selection.md) and the main web
skill's common method contract. Hosted, the contract is at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`;
for native skills, open
`synapse-web-pentesting/references/method-contract.md` under the installed skill
root.

Recover the current workspace revision and referenced evidence first. Model the
expected state machine and effect before interpreting a response difference.
Use live action descriptions for any deterministic helper, execution, or
canonical contribution.
