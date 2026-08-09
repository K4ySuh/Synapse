# Capability Gap Inventory

This inventory separates current adapter limits from the Authority Engine's
future authorization vocabulary. Phase 2 grants must express safe defaults and
operator-selected expansion; they must not infer permanent global ceilings from
today's narrow wrappers.

| Area | Current implementation | Phase 2 treatment |
| --- | --- | --- |
| Public PoC intelligence | references are read-only; code is not fetched or executed | keep disabled by default; any future retrieval or controlled use needs a separately reviewed action, effects, provenance, and explicit expert authority |
| SSRF | controlled external canary only; local/private targets are blocked | model target classes and callback providers as grant dimensions before expanding capability |
| XXE | benign in-band expansion only | represent external callbacks, local reads, and data exposure as distinct higher-risk actions/effects before authorization |
| sqlmap | command building only; OS shell, file/registry access, privilege escalation, and post-exploitation are blocked | preserve the current block; future raw execution requires a new action family and an explicit repository-policy decision, not a hidden flag |
| Crawler POST | only the authenticated extended workflow submits bounded non-sensitive forms by default | grant methods, state-change effects, dispatch budgets, sealed crawler volume controls, and explicit expert modes without hard-coded grant ceilings |
| Scanner profiles | named conservative profiles constrain options | allow operator-supplied bounded expert options only after their action/effect contract is explicit and auditable |

Repository policy remains authoritative today. A grant cannot bypass an adapter
capability that does not exist or a current hard safety rule. Conversely, the
Authority Engine must not encode these implementation gaps as immutable policy:
capability expansion requires its own reviewed action, scope/effects contract,
tests, and operator authorization.
