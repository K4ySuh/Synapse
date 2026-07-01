# Custom Adapter Template

This template shows the minimum shape for a workspace-native Synapse adapter.
It is intentionally safe: the example passively inspects already-ingested
endpoint metadata for missing security headers and creates workspace
observations. It does not send traffic.

## Files

```text
adapter.py
tests/test_custom_adapter.py
```

## What It Demonstrates

- `AdapterMetadata` declaration.
- Explicit `execution_mode` metadata so agents know whether the adapter is
  passive, synchronous-only, or async-by-default.
- `SynapseAdapter` subclass with `passive_analyze` and `plan` methods.
- Workspace-native `AdapterResult` output.
- Candidate observation creation with `candidate_observation`.
- Optional workspace ingestion through `workspace.ingest_data`.
- Registration into an `AdapterRegistry`.
- Unit tests that do not require network traffic.

## Running The Example Test

From the repository root:

```bash
bin/test --template
```

## Integrating A Real Custom Adapter

For internal/company adapters, keep the adapter in your own package or plugin
area, import `synapse_mcp.core.adapters`, and register it with an application
registry during MCP startup or a future plugin-loading hook. If the adapter
needs active traffic, enforce the same scope, confirmation, approval,
credential redaction, evidence, and action-recording semantics used by built-in
adapters. Active adapters should default to `execution_mode="async_default"`
and return a Synapse `jobId` through the generic `jobs.*` layer unless the
operation is deliberately tiny and bounded; those exceptions should declare
`execution_mode="sync_only"` in metadata.
