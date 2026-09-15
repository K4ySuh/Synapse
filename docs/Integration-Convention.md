# Saved-data integration convention

Synapse integrations keep replaceable interpretation and client methodology
outside the deterministic data boundary. Canonical workspace state, evidence,
scope, authority, execution, and reporting remain owned by Synapse.

## Required pieces

Every saved-data integration has these parts:

1. A Registry descriptor and live input/output contract, discoverable through
   capability search and action description.
2. A deterministic boundary that validates and parses supported saved input
   without sending traffic.
3. A normalizer that emits the existing workspace entity types and preserves
   whether each value was observed, inferred, externally reported, or unknown.
4. Canonical ingestion that links raw evidence and returns either the existing
   ingest result or a versioned contribution receipt.
5. A short hosted guidance reference for interpretation choices. It points to
   live schemas and does not copy them.
6. One benign representative fixture that proves ingestion, context recovery,
   and report projection in a temporary workspace.

Parser rejection is a validation failure. An integration must not store a
partial interpretation, promote a finding, or claim observed execution after
unsupported or malformed input. A versioned contribution with an uncertain
commit outcome is retried with the same request ID and identical payload so the
durable receipt resolves the result.

## Passive specification pilot

The pilot uses a saved OpenAPI, Swagger, or Postman document and sends no
network traffic.

| Contract part | Pilot value |
| --- | --- |
| Action ID | `spec_import.import_spec` |
| Retained legacy alias | `spec_import.import_spec` |
| Discovery | `capabilities.search`, `actions.describe`, `spec_import.capabilities` |
| Input shape | Workspace, target, saved `rawData`, optional declared format, and optional ingest switch |
| Output shape | Workspace-native adapter result plus format, entity counts, auth-scheme summaries, and canonical ingestion result when enabled |
| Canonical entities | Inferred endpoints, parameters, and `documented_auth_scheme` observations, all linked to saved-document evidence |
| Deterministic boundary | `synapse_mcp.core.saved_spec_import` |
| Compatibility wrapper | `synapse_mcp.adapters.web.spec_import` |
| Representative fixture | `MCPS/Synapse-MCP/tests/fixtures/integrations/saved-openapi.json` |
| Hosted guidance | `synapse://guidance/skills/synapse-web-pentesting/references/saved-data-integrations.md` |

The wrapper preserves the existing public action and legacy call shape. The
core module owns document detection, JSON/YAML parsing, bounded normalization,
value-preview redaction, evidence creation, and workspace ingestion. Imported
routes remain inferred and unobserved. Authentication definitions become
low-confidence observations; they are not credentials or proof of a live
authentication boundary.

Client-side interpretation uses the separate
[`contribution.v1` contract](Contribution-Contract.md). The live description of
`workspace.ingest_data` publishes its envelope and receipt schemas. This path
binds the authenticated consumer on the server and commits its receipt with
canonical evidence and entities. Both saved-spec imports and structured
contributions are recovered through `context.query` and projected into reports
from the same workspace truth.

## Future adapter classification

This convention records migration direction without scheduling a catalog
rewrite.

| Adapter group | Examples | Future boundary |
| --- | --- | --- |
| Saved external formats | Burp history/site maps, ffuf, Nmap, Nuclei, Shodan exports | Keep format validation and parsing in deterministic code; normalize through canonical ingestion with one format fixture. |
| Workspace-native passive analyzers | headers/cookies, CSRF, CORS, GraphQL, SSRF, XSS, SQLi | Keep reproducible classification in code; keep prioritization and investigative method in hosted guidance; ingest only workspace-native candidates or observations. |
| Consumer-interpreted passive facts | operator notes and methodology-derived endpoint or observation facts | Use the versioned contribution contract, source attribution, conservative confidence, and the durable receipt. |
| Active and provider-backed adapters | crawlers, probes, scanners, browser flows, external intelligence APIs | Keep Registry effects, exact scope, server-held authority, credentials, observations, and job lifecycle; a saved-data seam does not replace guarded execution. |

Core, state, and policy never choose a client skill or import a model SDK. A
client may replace its methodology while the descriptor, deterministic parser,
normalizer, receipt, context, and report contracts stay stable.
