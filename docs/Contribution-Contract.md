# Versioned workspace contributions

`workspace.ingest_data` accepts a strict saved-data mode on modern MCP:
`source="contribution.v1"`, `format="json"`, and a JSON envelope in `rawData`.
The application Registry publishes the exact envelope and receipt schemas in
`actions.describe("workspace.ingest_data")`, under
`inputSchema.x-synapse-contribution.rawDataSchema` and
`outputSchema.x-synapse-contribution-receipt`. The frozen legacy input contract
and its parser modes remain available; legacy calls cannot use this new mode.

Version 1.0 accepts up to 100 total `endpoints` and `observations` for one
target in an existing, activated SQLite-v2 workspace. The entire envelope is
limited to 256 KiB. Unsupported collections and unknown fields fail validation
with field paths. Endpoint URLs must belong to the action's target host. The
`producer` name/version and optional timezone-bearing `sourceTimestamp` are
attribution only. The authenticated MCP consumer and workspace come from the
server's request binding. Neither producer labels nor entity data confer
runtime observation or operator review status. Finding promotion remains an
explicit review operation.

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
the same parsed envelope returns the stored receipt and does not write a second
evidence event or revision. Reusing that ID with different content returns
`contribution_request_conflict`. A different consumer may use the same ID; both
contributions remain in canonical workspace state and are recoverable through
`context.query` or workspace context reads in a later session. For an uncertain
commit outcome, retry with the same ID and payload so the durable receipt can
resolve the result. JSON-v1 workspaces require an explicit verified migration
and activation before using this mode.
