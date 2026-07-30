# ADR-0007: Application outcome model and the protocol error boundary

- Status: Proposed
- Date: 2026-07-30
- Owners: Synapse architectural lead
- Applies from: Phase 1
- Supersedes: None

## Context

ADR-0002 requires that application services not depend on MCP types. Measured at
`4bcba55`, the module-level dependency direction is already clean: neither
`core/` nor `adapters/` imports `transport/`.

The error contract is not clean. `McpError` is defined in `core/errors.py` and
carries a JSON-RPC error code. It is raised at **281 sites**, of which **260
(93%) are in `core/` and `adapters/`** — the layers that become the application
layer — and only 21 in `transport/`:

| Code | Meaning | Sites |
| ---: | --- | ---: |
| `-32602` | invalid arguments | 231 |
| `-32000` | generic operational failure | 24 |
| `-32001` | authorization or approval required | 14 |
| `-32002` | scope denial | 9 |
| `-32601` | unknown method/tool | 2 |
| `-32003` | tool deadline exceeded | 1 |

Phase 0 finding O-1/O-3 established that the `-32001` / `-32002` split is an
*existing observable safety contract*, not an accident: an agent can distinguish
"you need approval" from "that target is out of scope" from the wire response
alone. Phase 2 must map its reason codes onto this taxonomy or explicitly
supersede it.

Phase 1 must therefore define typed application outcomes without either
rewriting 260 raise sites or freezing JSON-RPC numbering into the application
layer permanently.

## Decision

Define seven typed application outcomes as a discriminated union generic in the
success payload: `Success[T]`, `ValidationFailure`, `UnavailableCapability`,
`PolicyDenial`, `ApprovalRequired`, `ExecutionFailure`, `ExecutionUnknown`.

**Translate at the registry executor boundary.** The executor wrapper catches
`McpError` and converts it into the corresponding outcome, carrying the original
code verbatim on the outcome as `legacy_code`. Protocol projection emits
`legacy_code` when present, and the default mapping only when it is absent.
Newly written code raises typed outcomes directly; the 260 existing sites are
not touched.

The existing transport validator remains before typed model validation. Its
strict, non-coercing behavior, permissive handling of unknown public fields, and
special omission of `confirm` from required-field rejection are compatibility
semantics. Generated typed models mirror them with strict validation,
`extra="allow"`, reserved-leading-underscore rejection, and runtime-optional
`confirm`.

The reverse semantic mapping is explicit. `-32602` becomes
`ValidationFailure`; `-32002` becomes `PolicyDenial`; and `-32000` becomes
`ExecutionFailure`. `-32001` becomes `ApprovalRequired` when the action declares
`confirm` and the supplied value is not exactly true, otherwise
`UnavailableCapability`. The application-side `-32003` job-saturation rejection
becomes `ExecutionFailure` carrying `legacy_code=-32003` because dispatch truth
is known. A transport `ToolCallTimeout` constructs `ExecutionUnknown` and keeps
the existing generic or `jobs.status` message.

`ApprovalRequired` is reachable in Phase 1 only as a translation of the legacy
caller-asserted confirmation gate; it does not activate the Phase 2 Authority
Engine. `Success` additionally carries
`payload_signals_error: bool`, preserving the current behaviour in which an
error payload can be returned inside an `isError: false` envelope.

## Invariants

- The `-32001` / `-32002` / `-32000` / `-32003` taxonomy is preserved by both
  validation ordering and verbatim code/message projection.
- No application module imports `synapse_mcp.transport`; an architecture test
  enforces it. Python permits several module-level and deferred circular-import
  forms, so this is test-enforced rather than structurally prevented.
- Phase 1 introduces no new error code and changes no existing message text,
  except the `jobs.status` deadline variant that Phase 1 newly *freezes* without
  altering.
- Typed validation never runs ahead of `validate_tool_arguments`, and required
  `confirm` remains runtime-optional for all 44 affected schemas.

## Alternatives considered

### Rewrite all 260 core/adapter raise sites to typed outcomes

- Benefits: One error model everywhere; the shim disappears immediately.
- Costs: A 260-site rewrite across `credentials.py` (65 sites), `workspace.py`
  (28), and eleven adapters, during a phase whose exit criterion is that public
  behaviour is unchanged.
- Reason rejected: It is a broad rewrite, forbidden by the program guardrails,
  and it is the most likely single way to silently regress the safety taxonomy
  that O-1/O-3 identified as load-bearing.

### Adopt `McpError` as the application error type

- Benefits: Zero migration cost; it already lives in `core/`.
- Costs: Permanently freezes JSON-RPC numbering into the application layer and
  makes the Phase 3 protocol change far harder, since every error site would
  then encode the old protocol's codes by contract rather than by accident.
- Reason rejected: It renames the problem instead of solving it, and ADR-0002's
  dependency rule would be satisfied only on a technicality.

### Map outcomes to codes purely by outcome type, discarding the original code

- Benefits: A single small mapping table; conceptually clean.
- Costs: `UnavailableCapability` and `ApprovalRequired` both ship as `-32001`
  today (a missing session key versus a missing confirmation). A type-only
  mapping must pick one, changing the wire response for the other.
- Reason rejected: It changes observable behaviour in Phase 1, which the phase
  forbids. Carrying `legacy_code` defers that cleanup to Phase 3 where it
  belongs, with a compatibility record under ADR-0004.

## Consequences

- Positive: Application code gains a typed outcome model without a rewrite, and
  the safety taxonomy is preserved by construction rather than by diligence.
- Negative: A translation shim exists and will persist across several phases. It
  is a known, bounded piece of debt that shrinks as sites migrate.
- Negative: Outcome type alone cannot replace `legacy_code` during Phase 1
  because the legacy numbering is overloaded.
- Operational: Error behaviour on every unmigrated path is bit-for-bit
  unchanged.
- Security: The approval/scope distinction an operator relies on cannot be
  collapsed by a Phase 1 mapping error.
- Compatibility: Verified against the Phase 0 `errors.json` cases and the
  `-32001`/`-32002` result fixtures.

## Migration and rollback

Introduce outcomes and the translation shim with the registry. Migrated actions
return typed outcomes; unmigrated actions keep the legacy path untouched. As
later phases rewrite call sites to raise typed outcomes natively, the shim's
coverage shrinks and can eventually be deleted. Rollback for any action is to
restore its legacy dispatch branch; no storage or public name is involved.

## Verification

- `test_outcome_projection_preserves_legacy_error_taxonomy` — every outcome with
  a `legacy_code` projects that code unchanged.
- `test_required_confirm_omission_contract_for_all_tools` — scans all 174 tools
  and freezes the current outcome for all 44 schemas that require `confirm`.
- `test_slice_input_models_match_legacy_runtime_validation_semantics`.
- `test_jobs_status_timeout_message_variant_is_frozen`.
- `test_application_layer_has_no_transport_imports`.
- All Phase 0 Tier-1 `errors.json` cases and the `-32001` / `-32002` Tier-2
  fixtures pass unchanged.
