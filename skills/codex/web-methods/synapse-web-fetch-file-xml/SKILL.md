---
name: synapse-web-fetch-file-xml
description: Select when the current web question concerns server-side URL fetching, file or path handling, archive processing, or XML parser boundaries.
metadata:
  short-description: Analyze fetch, file, path, and XML evidence
  synapse-role: method
  synapse-pack: web
---

# Fetch, file, and XML method

Use this package for one bounded question about a server-side fetch, file or
path operation, archive member, or XML parser. Read the family-specific
[procedure](references/selection.md) and the main web skill's common method
contract. Hosted, the contract is at
`synapse://guidance/skills/synapse-web-pentesting/references/method-contract.md`;
for native skills, open
`synapse-web-pentesting/references/method-contract.md` under the installed skill
root.

Recover the current workspace revision and referenced evidence first. Identify
the exact parser or resource boundary and keep reachability, interpretation,
side effects, and impact separate. Use live action descriptions for any
deterministic helper, execution, or canonical contribution.
