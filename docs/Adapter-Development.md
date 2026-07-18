# Adapter Development

Synapse adapters are modular assessment components that plug into the local
workspace, evidence, scope, credential, action, and finding lifecycle. They
should transform assessment signals into structured operational knowledge that
operators and AI agents can reason over.

Adapters may perform passive analysis, generate test plans, build constrained
commands, run approved active profiles, ingest external tool output, or create
candidate findings. They must not turn Synapse into an autonomous exploitation
loop.

## Adapter Categories

Adapter metadata uses these categories:

- `web`
- `network`
- `cloud`
- `identity`
- `red_team`
- `reporting`
- `custom`

Use the most specific existing category. Use `custom` for organization-specific
or template adapters that do not belong in the built-in web/network domains.

## Capabilities

Declare capabilities in `AdapterMetadata`:

- `passive_analysis`: reads existing workspace, dump, or operator-provided data.
- `test_planning`: produces operator guidance or matrix/test plans.
- `active_testing`: sends traffic or otherwise interacts with a target.
- `command_building`: builds constrained commands without running them.
- `result_ingestion`: normalizes output into workspace entities.
- `finding_generation`: creates candidate or operator-reviewed finding records.

The metadata must also declare traffic behavior, confirmation requirements,
credential requirements, third-party contact, default risk tier, produced output
types, limitations, references, execution mode, and the executor tool when the
adapter declares `active_testing`.

Execution mode is part of the contract agents use when deciding whether to poll
jobs before starting new work:

- `passive_only`: does not run active work.
- `async_default`: starts active work through `jobs.*` unless
  `background=false` is explicitly supplied.
- `sync_default`: supports `background=true`, but blocks by default for
  compatibility or ergonomics.
- `sync_only`: deliberately synchronous because the operation is tiny and
  bounded; document this in limitations.

For active adapters, set `executor_tool` to the MCP tool that sends the approved
traffic, such as `command_injection.execute_test`, `access_control.execute_matrix_test`,
or `nmap.run_profile`. This value is exposed as `executorTool` through
`adapters.list` and `adapters.capabilities` so clients do not need to infer the
execution entrypoint from naming conventions.

## Workspace-Native Results

New adapters should prefer `AdapterResult` from
`synapse_mcp.core.adapters.results`. Its `entities` bundle mirrors the persisted
workspace files:

```text
services
endpoints
parameters
findings
actions
observations
```

Candidate surfaces should normally be observations, not a separate data model.
Use `candidate_observation()` for common hypothesis-style output.

Example ingestion path:

```python
result = AdapterResult(
    adapter="example",
    mode="passive_analysis",
    workspace_id=wid,
    target=host,
    summary="Identified one candidate.",
    entities=WorkspaceEntityBundle(observations=[observation]),
)

workspace.ingest_data(
    wid,
    host,
    "adapter_result",
    "passive_analysis",
    "json",
    json.dumps(result.as_ingest_payload(), indent=2),
    {"adapter": "example"},
)
```

Use source-specific workspace parsers only when the adapter ingests an external
tool format that is not already represented as workspace entities.

When an adapter derives entities from static analysis rather than direct
traffic, keep that distinction explicit. For example, JavaScript intelligence
normalizes endpoints with `source = "js_intelligence"`, `sourceAsset`,
confidence, `derived=true`, `inferred=true`, and `observed=false`. If derived
data references an endpoint that already exists as observed workspace traffic,
prefer an observation linking the derived source to the observed endpoint rather
than mutating the observed endpoint into an inferred record.

## Evidence Behavior

Adapters should store raw or structured evidence through `workspace.ingest_data`
when results matter beyond the immediate response. This creates a raw evidence
artifact, merges normalized entities, logs a `workspace.ingest` event, and keeps
the target context compact.

Rendered report artifacts use `reports/<workspace>/`. Non-report adapter artifacts use the
adapter target's `outputs/<tool>/` tree. Keep relative report paths
workspace-report-root-relative and require `allowExternalOutput=true` for external
absolute paths, matching the documentation, perimeter, and JS app-map
exporters.

Use `evidence.log_event` for reviewed milestones and operational decisions.
Do not place secrets in evidence event data. The evidence module sanitizes
common secret fields and common embedded secret-bearing strings, but adapters
should avoid passing secret values at all.

## Finding Behavior

Automated adapters should usually create candidate observations, not confirmed
findings. Use workspace finding helpers only when the operator has reviewed the
issue or the adapter intentionally creates an `operatorReviewed=false` candidate
finding, as Nuclei ingestion does.

Keep these states distinct:

- hypothesis: `observations.json`
- candidate finding: `findings.json` with `status=candidate`
- confirmed finding: `findings.json` with operator review and evidence

## Active Adapter Requirements

Active adapters send target traffic or call external services. They must enforce
the same safety model as built-in adapters.

Adapter rules:

1. Active adapters must enforce scope validation. When a `workspaceId` is
   available, pass it into the shared guard so the workspace's own persisted
   scope is authoritative for that engagement.
2. Active adapters must require explicit confirmation.
3. Active adapters must default outputs into the workspace evidence directory.
4. Active adapters should default to asynchronous execution through the generic
   `jobs.*` layer and expose `background=false` as the explicit blocking
   override.
5. Synchronous-only active adapters must declare `execution_mode="sync_only"`
   and stay small, bounded, and documented.
6. Adapters must not expose arbitrary shell execution.
7. Adapters must redact secrets before logging evidence.
8. Adapters should normalize results into workspace observations/findings.
9. Adapters should return structured results, not raw-only output.
10. Adapters must include tests.

Use `adapters/command_utils.py` for command-style active tools. Use
`adapters/web/active_probe.py` for simple HTTP parameter probes where the
adapter needs to replace one query/form/JSON parameter with a benign payload,
apply a scoped `credentialId`, send a bounded request, and redact returned
request headers. More complex workflows should keep specialized logic while
preserving the same scope, confirmation, approval, redaction, evidence, and
action-recording semantics.

Command-style adapters should use `start_background_command()` and
`background_requested()` from `adapters/command_utils.py`, register a named
background finalizer, and persist only redacted display commands in job records.
Internal Python workflows should prefer a worker subprocess so `jobs.status`
can finalize results after an MCP server restart.

## Registration

Built-in adapters are registered in
`synapse_mcp.core.adapters.registry.build_default_registry`. Register custom
adapters into an `AdapterRegistry` during your own MCP startup or future plugin
loading flow.

At minimum, implement:

```python
class ExampleAdapter(SynapseAdapter):
    metadata = AdapterMetadata(...)

    def passive_analyze(self, args: dict[str, Any]) -> dict[str, Any]:
        ...
```

Unsupported operations should use the base `SynapseAdapter` behavior, which
raises a controlled unsupported-method exception.

## MCP Tool Exposure

The current built-in MCP tool surface is wired in
`synapse_mcp.transport.stdio_server`. For built-in adapters, add:

- tool schema entries in `TOOL_SCHEMAS`
- dispatch branches in `call_tool`
- `executor_tool` metadata for active adapters
- tests for schema/dispatch behavior
- documentation updates when the public behavior changes
- a local `docs/Version-Log.md` entry for every code change (gitignored,
  per-developer; provisioned from `docs/Version-Log.template.md` on setup)

Future custom adapter loading should preserve the same discovery model exposed
by `adapters.list` and `adapters.capabilities`.

## Testing Requirements

Each adapter should include focused tests for:

- metadata validation and registry discovery
- passive candidate detection
- workspace-native result serialization
- workspace ingestion and observation creation
- planner output structure
- active confirmation and scope gates, if active
- workspace-owned scope behavior, if the adapter accepts `workspaceId`
- redaction of credentials and secret-bearing headers, if active
- action/evidence recording, if active
- async-default behavior and `jobs.status` finalization, if active and not
  `sync_only`

Use the focused suite from the repository root:

```bash
bin/test --core
```

The custom adapter template has its own example test:

```bash
bin/test --template
```

## Company/Internal Adapters

Companies can build internal adapters without changing the core framework by
using the same primitives:

- declare `AdapterMetadata`
- return `AdapterResult`
- ingest via `source=adapter_result`
- store any adapter-specific extended model under a clearly named target
  subfolder, as the access-control adapter does
- reference reusable secrets by `credentialId`
- keep engagement-specific data in workspace state and evidence, not in
  repository prompts or shared documentation

For active internal adapters, prefer narrow named profiles and explicit
operator approvals over generic execution hooks.
