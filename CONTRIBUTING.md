# Contributing

Synapse changes should preserve the safety and evidence model first. Keep
target-specific facts out of project documentation and store engagement context
in workspace state, evidence, fingerprints, scope notes, or operator-provided
memories.

## Development Setup

Use Python 3.10 or newer. The Python MCP package can be installed in editable
mode when local packaging behavior needs to be checked:

```bash
python3 -m pip install -e .
```

Most day-to-day development can run directly from the checkout:

```bash
bin/test
```

For launcher or environment changes, also run:

```bash
bin/check-setup
```

## Change Guidelines

- Keep changes scoped to the relevant module and existing architecture.
- Preserve scope checks, `confirm=true` gates, approval metadata, credential
  redaction, bounded execution, local evidence logging, and passive/active
  separation.
- Prefer workspace-native `AdapterResult` output for new adapters so ingestion,
  observations, findings, actions, and evidence references stay consistent.
- Use `adapters.list` and `adapters.capabilities` metadata for discoverability.
- Do not commit generated runtime data from `DATA/` except intentional
  placeholders.
- Update `docs/Version-Log.md` for implementation or documentation changes.

## Tests

Run all tests from the repository root:

```bash
bin/test
```

Useful focused modes:

```bash
bin/test --core
bin/test --template
bin/test --core -k access_control
```

When a change affects launcher behavior, local tools, or environment wiring,
run:

```bash
bin/check-setup
```

## Documentation

Update the closest durable documentation for the behavior changed:

- root overview and current capabilities: `README.md`,
- architecture and data flow: `docs/Architecture.md`,
- module and tool surface: `docs/Implementation-Map.md`,
- setup and operations: `docs/Operations.md`,
- component-specific behavior: files under `MCPS/`,
- dated history: `docs/Version-Log.md`.

Keep `AGENTS.md` environment-neutral. It is shared as the Synapse MCP main
prompt and should not contain engagement-specific routes, credentials, targets,
or stack assumptions.
