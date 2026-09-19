# Versioned workspace contributions

`workspace.ingest_data` accepts a strict saved-data mode on modern MCP:
`source="contribution.v1"`, `format="json"`, and a JSON envelope in `rawData`.
The application Registry publishes the exact envelope and receipt schemas in
`actions.describe("workspace.ingest_data")`, under
`inputSchema.x-synapse-contribution.rawDataSchema` and
`outputSchema.x-synapse-contribution-receipt`. The frozen legacy input contract
and its parser modes remain available; legacy calls cannot use this new mode.
`rawDataSchema` remains the exact version 1.0 schema for existing consumers;
`acceptedVersions` and `rawDataSchemas` additionally publish the 1.0 and 1.1
schemas from the application models.

Version 1.0 accepts up to 100 total `endpoints` and `observations` for one
target in an existing, activated SQLite-v2 workspace. The entire envelope is
limited to 256 KiB. Unsupported collections and unknown fields fail validation
with field paths. Endpoint URLs must belong to the action's target host. The
`producer` name/version and optional timezone-bearing `sourceTimestamp` are
attribution only. The authenticated MCP consumer and workspace come from the
server's request binding. Neither producer labels nor entity data confer
runtime observation or operator review status. Finding promotion remains an
explicit review operation.

Accepted entities keep the envelope producer and `contribution.v1` marker in
canonical workspace payloads. Modern `context.query` projects those as
`attributes.sourceAttribution` and labels the submitted statement
`attributes.knowledgeState="reported"`, even when its generic storage
`lifecycle` is `observed`. The optional endpoint `source` is a contributor
label, not an observation credential. The 1.0 input schema and receipt are
unchanged; method IDs and typed analysis fields remain outside this version.

## Version 1.1 typed analysis

The same `workspace.ingest_data` action/source accepts `schemaVersion="1.1"`.
It keeps the strict 1.0 endpoint and generic-observation fields and adds up to
100 total records across `entities.endpoints`, `entities.observations`, and
`entities.analyses`. Each analysis has a typed `kind` (`candidate` or
`coverage_gap`), a concrete HTTP(S) `subject` (`url`, `method`, optional
`parameter`/`location`, and optional `entityId` for a previously saved
endpoint/parameter), an explicit `knowledgeState` (`inferred` or
`reported`), bounded `confidence` and `reason`, optional supporting/contrary
evidence IDs, and optional `methodRef` (`id` plus `sha256:<64 hex>` content
digest) and `modelLabel`. Candidate entries require a bounded
`candidateClass`; coverage gaps cannot have one. `inconclusive=true` describes
an analysis conclusion, not a validation result. No arbitrary analysis
metadata, runtime-observed claim, execution outcome, or operator-review field
is accepted.

| Submitted record | Canonical destination | Lifecycle boundary |
| --- | --- | --- |
| `endpoints` | Existing endpoint collection | Saved surface, not a traffic observation |
| `observations` | Existing generic observation collection | Existing 1.0 semantics |
| `analyses` candidate | Existing `test_candidate` observation, keyed by the deterministic method/URL/location/parameter surface ID | `candidateFor` and proposed validation detail; explicit candidate validation and finding promotion remain separate actions |
| `analyses` coverage gap | Existing `analysis_coverage_gap` observation | Gap context, never a finding or execution claim |
| Work objective | Existing `tasks.control` work item if coordination is needed | A work item does not grant authority or promote a finding |

Supporting IDs link through the ordinary entity `evidenceIds`; contrary IDs
stay separately labeled and must also name evidence in the envelope's
same-target `evidenceRefs`. The submission itself creates canonical evidence
and a receipt in the same workspace transaction. The subject URL must belong
to the action target. A supplied `subject.entityId` must resolve in the same
workspace and target to an endpoint/parameter whose canonical URL and method
match; parameter references also match name and location. This check and all
supporting/contrary evidence checks happen inside the existing contribution
transaction. `methodRef`, producer, and model label are attribution,
not authenticated identity or authority; the consumer identity remains
server-bound. `context.query` exposes the analysis conclusion, reason, candidate
class, knowledge label, method attribution, and evidence references without a
new context operation. A candidate marked `inconclusive` still has proposed
validation status until `workspace.record_candidate_validation` makes an
explicit decision. `workspace.promote_observation_to_finding` and
`workspace.mark_finding_reviewed` remain the only promotion/review path.

Version 1.1 uses existing JSON payload columns and the contribution receipt
table; no migration or second provenance store is required. A later analysis
on the same stable candidate updates its analysis conclusion, reason,
confidence, knowledge state, and latest method/producer attribution while
unioning supporting and contrary evidence. It does not replace a recorded
validation outcome, operator review, or reportability decision. The receipt
returns the same canonical candidate row ID, updated count, and committed
revision. An identical request-ID retry returns the original receipt without
another mutation; a changed payload or target conflicts. Fresh clients can
read the result through `context.query` and the existing internal report
projection without the original method package being installed.

`evidenceRefs` may name existing evidence for the same workspace and target;
`artifactRefs` may name existing artifacts in that workspace. Both are checked
inside the ingestion transaction. An entity can link a referenced evidence ID
by listing it in its own `evidenceIds`; other entities do not inherit that link.
The submission also creates one raw evidence
event and a content-addressed artifact. Its receipt names the new evidence ID,
all linked references, canonical record IDs, inserted/updated counts, and the
committed workspace revision. An unrecognized reference or malformed envelope
creates no linked evidence, entity, receipt, or revision. A staged blob may be
left unreferenced if a later transaction fails.

For a saved benign fact, call `actions.run_passive` with this input (shown as
JSON before MCP serializes the `rawData` string):

```json
{
  "actionId": "workspace.ingest_data",
  "arguments": {
    "workspaceId": "engagement-example",
    "target": "app.example.test",
    "source": "contribution.v1",
    "format": "json",
    "rawData": "{\"schemaVersion\":\"1.0\",\"requestId\":\"saved-001\",\"producer\":{\"name\":\"saved-fixture\",\"version\":\"1.2.0\"},\"entities\":{\"endpoints\":[{\"url\":\"https://app.example.test/health\",\"method\":\"GET\"}]}}"
  }
}
```

The returned `result` has this shape; IDs and revision below are illustrative:

```json
{
  "schemaVersion": "1.0",
  "submissionId": "submission-<stable-id>",
  "workspaceId": "engagement-example",
  "target": "app.example.test",
  "requestId": "saved-001",
  "producer": {"name": "saved-fixture", "version": "1.2.0"},
  "consumerRef": "sha256:<authenticated-consumer-digest>",
  "canonicalRecordIds": {"endpoints": ["entity-<stable-id>"], "observations": []},
  "evidenceIds": ["ev_<generated-id>_contribution"],
  "artifactIds": ["artifact-<content-id>"],
  "insertedCounts": {"endpoints": 1, "observations": 0},
  "updatedCounts": {"endpoints": 0, "observations": 0},
  "validationDiagnostics": [],
  "committedRevision": 2
}
```

`requestId` is unique per workspace and authenticated consumer. Retrying with
the same normalized target and parsed envelope returns the stored receipt and
does not write a second evidence event or revision. Reusing that ID for a
different target or different content returns `contribution_request_conflict`
without creating canonical evidence, entities, receipts, or a revision. The
target remains an outer Registry action argument and is checked against the
stored receipt; it is not added to the envelope fingerprint or uniqueness key.
A different consumer may use the same ID; both contributions remain in
canonical workspace state and are recoverable through `context.query` or
workspace context reads in a later session. For an uncertain commit outcome,
retry with the same target, ID, and payload so the durable receipt can resolve
the result. JSON-v1 workspaces require an explicit verified migration and
activation before using this mode.
