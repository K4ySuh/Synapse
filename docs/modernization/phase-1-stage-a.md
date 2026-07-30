# Phase 1 Stage A — Application Core and Typed Action Registry: design checkpoint

- Phase: 1, Stage A (design only — no production code)
- Precondition: Phase 0 local compatibility evidence **PASS**; the program gate
  remains **CONDITIONAL** until the remote Python 3.10–3.13 matrix and external
  sign-off are evidenced in the Phase 0 handoff
- Baseline for this design: `4bcba55`
- Governing ADR: `ADR-0002-typed-core-action-registry.md` (Accepted)
- New ADRs justified here: `ADR-0007` (outcome model and error boundary), `ADR-0008` (action identity)
- Author: architectural lead
- Status: **revised after independent review — awaiting checkpoint approval.
  Stage B requires both this approval and the Phase 0 program gate.**

Every measurement below was derived from the live `TOOL_SCHEMAS` and the dispatch
body at `4bcba55`, not from prior documents. Reproduction commands are in §10.

---

## 1. Executive summary

The seam is buildable, and the 174-tool surface is fully representable. The
first submission nevertheless overfit five judgment columns to tool-family
heuristics. This revision publishes the decision rules, adds the implementation
target and application-use-case dimensions, and corrects the audited
misclassifications (§2, Appendix A). No row remains unclassified; the
conditional cases are represented explicitly rather than forced into a
misleading read/write bucket.

Stage A found one condition the brief did not anticipate, and it reshapes the
phase. **JSON-RPC protocol codes are already pervasive inside the layers that
become the application layer**: 281 `McpError` raise sites, of which **260 (93%)
live in `core/` and `adapters/`** and only 21 in `transport/`. ADR-0002's rule —
"application services must not import MCP request, result, context, or content
classes" — is satisfied literally today (`McpError` is defined in
`core/errors.py`, and neither `core/` nor `adapters/` imports `transport/`), but
the *spirit* is not: the application layer is hard-wired to a JSON-RPC numbering
scheme.

The phase therefore has to choose between rewriting 260 raise sites (a broad
rewrite, forbidden by the guardrails and by this phase's own non-goals) and
translating at a boundary. **This design translates at the executor boundary and
leaves the 260 sites untouched** (D-3, ADR-0007). That choice is what keeps
Phase 1 a structural change rather than a behavioural one, and it is the single
most consequential decision in this document.

All seven decisions D-1 … D-7 are closed below. Three findings are recorded for
later phases (§11); none permits Stage B to bypass either gate stated above.

---

## 2. Inventory of all 174 tools (brief §2.1)

Full per-tool table: **Appendix A**. Mechanical cells are generated from the live
schema and dispatch AST. Judgment cells are assigned by the ordered §2.2 rules
after inspection of the emitted implementation target; §10 states the
reproduction boundary so a reviewer can re-derive every cell.

### 2.1 Surface shape

| Measure | Value |
| --- | ---: |
| Tools | 174 (174 unique names) |
| Dotted namespaces | 38 |
| Tools with no namespace | 2 |
| Namespaces holding exactly one tool | 3 (`project`, `dumps`, `sitemap`) |
| Tools exposing `confirm` | 47 |
| Tools exposing `background` | 8 |
| Tools exposing `disableTraffic` | 20 |
| Tools exposing `allowStateChanging` | 1 |
| Tools with a top-level `credentialId` or `apiKey` property | 24 |
| Tools taking `workspaceId` | 101 |
| Tools with no arguments at all | 25 |

The 24 count is syntactic: 22 schemas expose `credentialId` and two expose
`apiKey`. `CredentialPolicy` is a semantic classification and also records
nested credential references and credential-store access, so its totals are not
expected to equal 24. D-2 defines both axes and Appendix A makes the distinction
auditable.

The baseline's "40 namespaces" is 38 dotted roots + 2 dotless names. D-1 adopts
40 canonical packs while explicitly covering the six three-segment public names.

### 2.2 Side-effect classes

Eleven classes cover the surface. `background_submit` is not one of them:
background execution is dispatch/task behavior, not an effect. Classification
uses the operation's primary authority-relevant effect; cross-cutting evidence
logging and optional normalized ingestion do not replace the class of the
analysis or probe that produced them. The ordered rules below, not a name
prefix, determine the cell.

| Side-effect class | Tools |
| --- | ---: |
| `read_only` | 48 |
| `passive_analysis` | 39 |
| `workspace_write` | 19 |
| `active_probe` | 19 |
| `report_build` | 18 |
| `third_party_read` | 13 |
| `credential_write` | 11 |
| `local_destructive` | 3 |
| `runtime_config_write` | 2 |
| `job_control` | 1 (`jobs.cancel`) |
| `authorization_config_write` | 1 (`scope.set`) |

Other dimensions: risk `none` 93 / `low` 47 / `moderate` 19 / `high` 15; scope
`not_applicable` 139 / `required` 22 / `checked_downstream` 13; credential
requirement `none` 142 / `optional` 22 / `required` 10; idempotency `pure_read`
109 / `idempotent_write` 23 / `non_idempotent` 38 / `conditional` 3 /
`idempotent_control` 1.
Credential access is `none` 137 / `credential_use` 22 /
`secret_state_write` 11 / `redacted_metadata_read` 4.

The ordered judgment rules are:

| Dimension | Ordered derivation rule |
| --- | --- |
| Side effect | Inspect the implementation target and documented behavior. Choose the primary effect with this precedence when an operation has multiple first-order effects: destructive local cleanup; authorization mutation; credential mutation/authentication; target traffic/scanner execution; third-party intelligence; runtime configuration; report/artifact rendering; durable workspace/evidence mutation; local passive computation; otherwise read-only. Cross-cutting audit/normalization writes do not replace the producing operation's class. Background capability never participates in this decision. |
| Risk | `high` for authorization, credential mutation/authentication, or destructive cleanup; `moderate` for target traffic or scanner execution; `low` for third-party calls, durable state/artifact writes, runtime configuration, and redacted credential reads; `none` for local reads/computation. |
| Scope | `required` when the operation itself can send target traffic; `checked_downstream` for third-party intelligence adapters that scope-check supplied target indicators; otherwise `not_applicable`. |
| Credentials | Requirement is `required` when a credential/secret must be supplied or a specific stored credential is selected, `optional` when an execution path or nested context may resolve one, otherwise `none`. A separate `CredentialAccess` field records metadata reads and secret-state writes, so `*.session_key.clear` is not mislabeled merely because it has no credential argument. |
| Idempotency | Classify replay of the primary operation, excluding mandatory cross-cutting audit events (otherwise almost every Synapse call collapses to one class). `pure_read` has no primary mutation; `idempotent_write` repeats without duplicating a primary logical entity; `non_idempotent` sends traffic, appends primary state, allocates an identity, or submits work; `conditional` depends on a named input mode recorded in `IdempotencyPolicy.condition`; `idempotent_control` is repeat-safe control. `evidence.log_event` remains non-idempotent because append is its primary effect. |

These rules corrected, among others: all five crawler/scanner runners to
`active_probe`; both background JS actions to their real passive/workspace
effects; all four no-traffic `prepare_replay` builders to `read_only`; six
runtime/session configuration operations away from `third_party_read`;
credential setup-check/get policy; every arbitrary-output-path renderer to a
write idempotency/risk; nested access-control credentials; and append/create
operations such as `evidence.log_event` and `workspace.create_finding`.

**Side-effect class and task policy are orthogonal.** Eight tools expose
`background`; their effects remain credential write, passive analysis,
workspace write, or active probe. `TaskPolicy.background_capable` records only
the dispatch choice.

### 2.3 Timeout tiers

Derived from `_tool_deadline_seconds` (`transport/stdio_server.py:129`):

| Tier | Seconds | Tools |
| --- | ---: | ---: |
| `STATUS` | 30 | 1 (`jobs.status`, by name equality) |
| `FAST` | 15 | 23 (`FAST_TOOLS` set) |
| `DEFAULT` | 45 | 150 |

### 2.4 Passive-recordable set

`_is_recordable_passive_analysis_tool` selects **15** tools: name ends with
`.analyze_workspace` or `.passive_analyze`, minus an excluded-root denylist.

Finding: the denylist names six roots (`documentation`, `access_control`,
`perimeter`, `fingerprint`, `js`, `nuclei`) but **only two of them can ever
match** the suffix rule — `perimeter.analyze_workspace` and
`fingerprint.analyze_workspace`. The other four roots own no tool with either
suffix, so those entries are dead. Recorded, not fixed: turning recordability
into explicit descriptor data (D-7) makes the denylist unnecessary rather than
requiring it to be corrected.

### 2.5 Application use cases and implementation targets

The required use-case grouping is functional, not an authority rule:

| Application use case | Tools |
| --- | ---: |
| Web assessment | 62 |
| Engagement state and evidence | 24 |
| Reporting | 20 |
| Infrastructure and OSINT | 18 |
| CVE intelligence | 11 |
| Credentials and authentication | 10 |
| Application discovery | 10 |
| Scanner execution | 9 |
| Control plane | 5 |
| Local artifacts | 5 |

Appendix A adds both the use case and the exact legacy callable reached by each
dispatch branch. The implementation target was extracted from
`_call_tool_impl`; it is Stage B's wiring input and the audit evidence for the
five judgment columns.

---

## 3. Module boundaries (brief §2.2)

```
synapse_mcp/
  app/                      # NEW — the application layer
    actions/
      descriptor.py         # ActionDescriptor + typed policy submodels
      outcomes.py           # the seven ActionOutcome variants
      registry.py           # ActionRegistry: discovery, registration, consistency
      packs/                # one module per pack; descriptors + typed models only
    services/               # use-case orchestration (deliberately thin in Phase 1)
  core/                     # unchanged
  adapters/                 # unchanged
  transport/
    stdio_server.py         # public behaviour unchanged
    projection.py           # NEW — descriptor -> legacy schema entry + dispatch
    legacy_projection_map.py# NEW — legacy names/serializers, transport-owned
```

**Allowed imports.** `app/` may import `core/` and `adapters/`. `transport/` may
import `app/`, `core/`, `adapters/`. `core/` and `adapters/` import neither
`app/` nor `transport/` (verified true for `transport/` today).

**`app/` must not import `transport/`.** Python's circular-import behavior does
not make that edge structurally impossible: module imports and deferred imports
can both load successfully on supported interpreters. The boundary is therefore
test-enforced with a full AST import scan. This is an explicit language/runtime
limitation, not a claimed structural property.

**Schema ownership is split by kind, without duplication.** The exact input
contract lives beside its application input model as a typed
`InputContractDocument`; the model class is generated from that document and
retains it as typed class metadata. The descriptor already carries the model in
its `input_model` field, so there is no fifteenth descriptor field and no public
bare dictionary. The transport-owned projection map carries only genuinely
protocol-specific facts: the legacy public name and serializer/argument-adapter
selection. Transport projects `inputSchema` from
`descriptor.input_model.contract_document`; it does not maintain another schema
literal.

---

## 4. The `ActionDescriptor` contract (brief §2.3)

All fourteen required fields, no bare `dict[str, Any]` in any public position.
`ActionDescriptor`, `ActionExecutor`, and `ActionRequest` are generic in the
same input/output types.

```python
@dataclass(frozen=True, slots=True)
class InputContractDocument:
    json_bytes: bytes                      # exact ordered inputSchema JSON
    sha256: str

class ActionInput(BaseModel):
    contract_document: ClassVar[InputContractDocument]
    model_config = ConfigDict(strict=True, extra="allow")
```

`make_input_model(document)` validates the document once, builds strict nested
models (including `oneOf`, enum, bounds, array items, and nested required
fields), and attaches the same typed document to the resulting class.

```python
@dataclass(frozen=True, slots=True)
class ActionDescriptor:
    id: ActionId                          # canonical "pack.local_name" (D-1)
    pack: str                             # owning pack; == id.pack
    title: str
    summary: str
    input_model: type[ActionInput]        # pydantic BaseModel subclass
    output_model: type[ActionOutput]      # pydantic BaseModel subclass
    side_effect_class: SideEffectClass    # enum, the 11 values of §2.2
    risk_class: RiskClass                 # none | low | moderate | high
    scope_policy: ScopePolicy             # typed submodel, see D-2
    credential_policy: CredentialPolicy   # typed submodel, see D-2
    idempotency_policy: IdempotencyPolicy # typed submodel
    task_policy: TaskPolicy               # deadline tier + background capability
    executor: ActionExecutor              # Protocol, see below
    availability: Availability            # available | unavailable(reason)
```

```python
class ActionExecutor(Protocol):
    @property
    def input_model(self) -> type[TInput]: ...
    @property
    def output_model(self) -> type[TOutput]: ...
    def __call__(self, request: ActionRequest[TInput]) -> ActionOutcome[TOutput]: ...
```

`ActionRequest` carries the validated typed input plus an `ExecutionContext`
(workspace id, correlation id, deadline, and the caller's legacy approval
assertion). **An executor never receives raw args and never returns a raw
string.** Runtime registration checks the executor's declared model identities
against the descriptor, not merely protocol method presence.

The five previously implicit types are:

```python
@dataclass(frozen=True, slots=True)
class ScopePolicy:
    requirement: ScopeRequirement        # not_applicable|required|checked_downstream
    target_fields: tuple[str, ...]
    enforcement: Enforcement

@dataclass(frozen=True, slots=True)
class CredentialPolicy:
    requirement: CredentialRequirement  # none|optional|required
    access: CredentialAccess             # none|credential_use|redacted_metadata_read|secret_state_write
    reference_fields: tuple[str, ...]    # dotted paths may name nested contexts
    enforcement: Enforcement

@dataclass(frozen=True, slots=True)
class IdempotencyPolicy:
    mode: IdempotencyClass               # the five values in §2.2
    replay_safe: bool
    condition: str | None                # e.g. "non-idempotent when background=true"
    enforcement: Enforcement

@dataclass(frozen=True, slots=True)
class Availability:
    state: AvailabilityState             # available|unavailable
    reason: str | None

@dataclass(frozen=True, slots=True)
class ExecutionContext:
    workspace_id: str | None
    correlation_id: str
    deadline_seconds: float
    legacy_approval_asserted: bool | None
```

`TaskPolicy` carries the deadline tier as data, removing the `jobs.status` name
special case, and gives passive recordability a defined home (D-4, D-7):

```python
@dataclass(frozen=True)
class TaskPolicy:
    deadline_tier: DeadlineTier           # FAST=15s | STATUS=30s | DEFAULT=45s
    background_capable: bool
    passive_recordable: bool
```

---

## 5. Command / result / error contracts (brief §2.4)

Seven outcomes, as a discriminated union. Generic in the success payload type;
never a bare dict.

| Outcome | Meaning | Legacy projection |
| --- | --- | --- |
| `Success[TOutput]` | executed, typed payload | result envelope, `isError: false` |
| `ValidationFailure` | input rejected | `-32602` |
| `UnavailableCapability` | dependency/session/key absent | `-32001` (see §11 F-2) |
| `PolicyDenial` | scope denial | `-32002` |
| `ApprovalRequired` | legacy caller confirmation absent; Phase 2 later supplies durable authority | `-32001` |
| `ExecutionFailure` | ran and failed | `-32000` |
| `ExecutionUnknown` | deadline exceeded / dispatch truth unknown | `-32003` |

Two properties make this projection exact rather than approximate:

1. **Every outcome carries `legacy_code: int | None`.** When an outcome
   originates from a translated `McpError`, the original code is carried verbatim
   and the projection emits it unchanged. The table above is the default for
   outcomes raised by *new* code, not a re-derivation of existing behaviour.
2. **`Success` carries `payload_signals_error: bool`** (D-7), preserving the
   error-payload-inside-success-envelope behaviour exactly without either losing
   the distinction or silently fixing it.

The reverse translation is explicit because legacy codes are overloaded:

| Legacy condition | Application outcome |
| --- | --- |
| `-32602` from legacy validation/implementation | `ValidationFailure` |
| `-32001` while a declared `confirm` input is not exactly `true` | `ApprovalRequired` |
| other `-32001` | `UnavailableCapability` |
| `-32002` | `PolicyDenial` |
| `-32000` | `ExecutionFailure` |
| `-32003` raised by an application operation (currently JS job saturation) | `ExecutionFailure` carrying `legacy_code=-32003`, because dispatch truth is known and nothing ran |
| `ToolCallTimeout` caught by transport | transport constructs `ExecutionUnknown`; projection preserves the existing generic or `jobs.status` message |

`ApprovalRequired` is therefore reachable in Phase 1 only as a semantic
translation of the existing caller-asserted confirmation gate. That does not
activate the Phase 2 authority engine. `ExecutionUnknown` has a concrete Phase 1
producer at the timeout boundary even though no executor can return it after a
transport timeout.

---

## 6. Registry lifecycle and duplicate detection (brief §2.5)

Descriptors are declared in `app/actions/packs/*.py` and registered at import of
the `packs` package. `ActionRegistry.register()` raises at **import/discovery
time**, never at dispatch, on any of:

- duplicate `ActionId`;
- `descriptor.pack != descriptor.id.pack`;
- `input_model`/`output_model` not a `BaseModel` subclass;
- executor is not callable or its declared `input_model`/`output_model`
  identities differ from the descriptor;
- `scope_policy.requirement is REQUIRED` while `side_effect_class` is
  `read_only` or `report_build`;
- `active_probe` without `moderate|high` risk, required scope, and
  `non_idempotent` replay policy;
- any policy declaring `enforcement=ENFORCED_BY_EXECUTOR` during Phase 1 (D-2);
- `availability=unavailable` without a reason string.

`ActionRegistry.execute()` is the only supported dispatch entry. It invokes the
configured policy evaluator before the executor; protocol projections cannot
retrieve/call the executor directly. In Phase 1 the evaluator is a compatibility
pass-through because the exact legacy confirm/scope/credential gates remain
inside the wrapped implementations. This reconciles
`DECLARED_NOT_ENFORCED` metadata with ADR-0002's no-bypass invariant without
pretending the future Authority Engine already exists.

---

## 7. Dependency graph and the architecture test (brief §2.7)

```
transport/  ──>  app/  ──>  core/
     │            │            ^
     │            └──>  adapters/  ──┘
     └────────────────>  core/, adapters/
```

No edge from `core/` or `adapters/` or `app/` back into `transport/`.

**Enforcing test: `test_application_layer_has_no_transport_imports`** (new, in
`tests/test_architecture_boundaries.py`). It walks every module under
`synapse_mcp/app/` with `ast`, collects `Import`/`ImportFrom` targets, and asserts
none resolves to `synapse_mcp.transport` — including deferred imports inside
function bodies, which a runtime import check would miss.

A second test, `test_core_and_adapters_do_not_import_app_or_transport`, pins the
direction that is already true today so Phase 1 cannot quietly reverse it.

---

## 8. Legacy projection and the contract-test strategy (brief §2.6, §2.8)

### 8.1 Schema projection

The frozen surface is 174 ordered tools at exactly 99,337 compact bytes, pinned
independently of fixture equality. **Pydantic-generated JSON Schema will not
reproduce those bytes** (ordering, `title` injection, `anyOf` shapes), and
chasing byte-equality out of a model generator would consume the phase and still
drift.

Decision: **one frozen input-contract document generates both the Pydantic model
and the legacy `inputSchema` projection**. The pack declares the literal once as
an `InputContractDocument`; `make_input_model()` creates the strict model and
attaches the typed document to the class. The descriptor carries that class in
its existing `input_model` field. The transport map contains no schema.

This closes the "one source" requirement without a fifteenth field or a public
`dict[str, Any]`. It also makes byte equality practical: the transport parses
the document's exact JSON bytes and preserves insertion order rather than asking
Pydantic to regenerate JSON Schema.

Legacy validation ordering is frozen:

```text
handle(tools/call)
  -> validate_tool_arguments(name, raw_args)       # remains first and authoritative
       - strict/non-coercing legacy type checks
       - unknown fields accepted
       - leading "_" fields rejected
       - required "confirm" deliberately skipped
  -> input_model.model_validate(raw_args)          # same semantics, typed value
  -> ActionRegistry.execute(request)
  -> legacy implementation wrapper
```

Generated input models use `ConfigDict(strict=True, extra="allow")`; integer
strings do not coerce, unknown public fields remain accepted, and a pre-validator
rejects reserved leading-underscore keys. A schema-level `required` entry for
`confirm` becomes an optional typed field with default `None` for runtime
validation only; discovery continues to emit the frozen required list. This
explicitly preserves the legacy carve-out at
`validate_tool_arguments`.

Enforcing tests:

- `test_slice_input_models_match_legacy_runtime_validation_semantics` covers
  non-coercion, permissive extras, reserved fields, defaults, and omitted
  confirmation;
- `test_required_confirm_omission_contract_for_all_tools` scans all 174 schemas,
  proves the fixture covers exactly the 44 with required `confirm`, and replays
  their current 42 errors plus two successful dry-run outcomes byte-semantically.

### 8.2 Dispatch projection

The dispatch body has two shapes, and the slice deliberately spans both:
**71 branches serialize in the transport** (`json.dumps(..., indent=2)`) and
**103 return a pre-serialized string from the module or adapter**. Defaults are
applied in *both* places — `workspace.prepare_target_context` defaults
`maxTokens` to 1500 in the transport, while `headers_cookies.analyze_workspace`
defaults `maxCandidates` to 100 inside the adapter. The generated model preserves
the distinction between omitted and supplied fields. The Phase 1 legacy wrapper
uses `model_dump(exclude_unset=True)`, so those defaults still execute at their
existing layers rather than being duplicated in model metadata. Slice tests pin
both omissions.

The transport-owned projection map records, per action, which serializer applies.
`indent=2` is frozen output formatting and is preserved verbatim.

### 8.3 Which fixture gates which slice operation

| Operation | Class | Gating Phase 0 fixture | Equivalence |
| --- | --- | --- | --- |
| `workspace.summary` | read_only | `results/workspace_summary.json` | normalized-exact |
| `workspace.prepare_target_context` | read_only | `results/workspace_prepare_target_context.json` | normalized-exact |
| `headers_cookies.analyze_workspace` | passive_analysis | `results/headers_cookies_analyze_workspace.json` | normalized-exact |
| `cors.execute_test` | active_probe | `results/cors_execute_test_disabled_traffic.json`, plus `cors_execute_test_unconfirmed.json` (`-32001`) | normalized-exact |
| `crawler.crawl` | active_probe | `results/crawler_crawl_background_submitted.json`, plus `crawler_crawl_unconfirmed.json` (`-32001`) and `crawler_crawl_out_of_scope.json` (`-32002`) | normalized-exact |
| `jobs.status` | read_only | `results/jobs_status_terminal.json`; `includeResult=True` stays shape-asserted | normalized-exact / shape |

All six also remain gated by the Tier-1 `tools_list.json` count and byte pins.

### 8.4 New contract work owned by Phase 1

- **D-5:** freeze the `jobs.status` `-32003` message variant, which Phase 0 left
  unfrozen while freezing the generic one. Test:
  `test_jobs_status_timeout_message_variant_is_frozen`. Add it as a new case in
  `errors.json` under the existing fixed-deadline patching approach. This is
  ledgered in `contract-changes.md`; **do not reopen Phase 0.**
- **Confirmation validation:** add `confirm_omission.json` and the exhaustive
  test above. Add the unconfirmed CORS Tier-2 fixture so both approval-sensitive
  slice operations are independently gated.
- **D-4 validation beyond the slice:**
  `test_descriptor_deadline_matches_legacy_for_all_tools` asserts, for all 174
  names, that `_tool_deadline_seconds(name)` equals the descriptor-derived
  deadline. This covers the 23 `FAST` tools immediately even though none is in
  the slice, closing the "designed against two of three tiers" gap now rather
  than at each later migration.
- `test_passive_recording_unchanged_for_the_fifteen_recordable_tools`.

---

## 9. Decisions D-1 … D-7 (all closed)

### D-1 — action IDs, including dotless and three-segment names → **split once at the first dot**

The two dotless tools are not a matched pair; they come from different features:
`approve_pretext_candidate` is implemented in `adapters/social/pretext_generator.py`
and `mark_detection_outcome` in `core/purple_team/gap_analysis.py`.
Six public names have three segments:
`cve.session_key.{set,clear,status}` and
`shodan.session_key.{set,clear,status}`.

| Option | Verdict |
| --- | --- |
| Registry inherits legacy names verbatim, dotless included | Rejected — every consumer of `ActionId` needs a special case forever |
| Split at the last dot | Rejected — invents `cve.session_key` and `shodan.session_key` pseudo-packs while `cve` and `shodan` still own other actions, producing 42 packs |
| Opaque slugs / integer ids | Rejected — unreadable, and forces a lookup table to say anything about an action |
| **Split once at the first dot; the local action name may have multiple segments** | **Chosen** |

`ActionId` parses `pack.local_name`, where both are non-empty and every segment
matches `[a-z][a-z0-9_]*`. It splits once at the first dot:
`cve.session_key.set` is pack `cve`, local name `session_key.set`. The orphans
become `social.approve_pretext_candidate` and
`purple_team.mark_detection_outcome`. The result is exactly **40 packs**. The
three single-tool packs remain legitimate.

**Public names do not change.** The legacy name is stored explicitly in the
projection map, never derived from the id by convention — deriving it would
require a special case for exactly the two tools this decision exists to
normalize. Recorded as ADR-0008.

### D-2 — declared-but-not-enforced → **an explicit enforcement discriminator**

Every policy submodel carries:

```python
class Enforcement(StrEnum):
    DECLARED_NOT_ENFORCED = "declared_not_enforced"
    ENFORCED_BY_EXECUTOR  = "enforced_by_executor"
```

In Phase 1 **every** policy is `DECLARED_NOT_ENFORCED`, and §6's consistency
check rejects any descriptor claiming otherwise — so the registry cannot start
looking like an authority engine before ADR-0003 lands. `confirm=true` remains
caller-asserted; `maxTokens` remains advisory.

Two supporting rules: policy metadata is **not** rendered into projected tool
descriptions (an agent must not read a declared policy as a control), and the
field is named for what it is rather than something aspirational like `enabled`.
Every protocol call still passes through `ActionRegistry.execute()` and its
pass-through evaluator before the wrapper invokes the legacy implementation;
the implementation's current gates remain authoritative in Phase 1.

### D-3 — outcome → error-code projection → **translate at the executor boundary; do not rewrite 260 sites**

The measured condition:

| Layer | `McpError` raise sites | Codes |
| --- | ---: | --- |
| `adapters/` | 135 | `-32602`×121, `-32000`×6, `-32001`×5, `-32002`×2, `-32003`×1 |
| `core/` | 125 | `-32602`×99, `-32000`×17, `-32002`×7, `-32001`×2 |
| `transport/` | 21 | `-32602`×11, `-32001`×7, `-32601`×2, `-32000`×1 |
| **Total** | **281** | `-32602`×231, `-32000`×24, `-32001`×14, `-32002`×9, `-32601`×2, `-32003`×1 |

| Option | Verdict |
| --- | --- |
| Rewrite all 260 core/adapter sites to typed outcomes | Rejected — a broad rewrite, forbidden by the guardrails and this phase's non-goals; also the single most likely way to regress the safety taxonomy |
| Redefine `McpError` as the application error type | Rejected — freezes a JSON-RPC numbering scheme into the application layer permanently, and makes Phase 3's protocol change vastly harder |
| **Registry executor catches `McpError`, translates to a typed outcome, carries `legacy_code` verbatim; new code raises typed outcomes** | **Chosen** |

This preserves O-1/O-3 through two mechanisms: the legacy validator runs before
typed validation, including its required-`confirm` carve-out; and translated
outcomes carry the original code/message rather than re-deriving them.
`test_outcome_projection_preserves_legacy_error_taxonomy` guards projection;
`test_required_confirm_omission_contract_for_all_tools` guards the previously
missed pre-executor path. The reverse semantic map is the table in §5.

Migration property: as sites migrate to typed outcomes in later phases, the
translation shim shrinks. Recorded as ADR-0007.

### D-4 — timeout selection → **descriptor data, validated across all 174 now**

`TaskPolicy.deadline_tier` replaces the name-equality special case.
`_tool_deadline_seconds` becomes a projection over the registry with an explicit
fallback for unmigrated tools. The all-174 equivalence test in §8.4 validates the
23 `FAST` tools immediately, so their later migration is mechanical.

### D-5 — the `jobs.status` timeout variant → **Phase 1 freezes it**

Closed as directed: new case in `errors.json`, test named in §8.4, and a
`contract-changes.md` ledger row in the same change. Phase 0 is not reopened.

### D-6 — what counts as a legitimate snapshot change → **a ledger entry, or the change is illegitimate**

Extending ADR-0004's classification: any change that adds, removes, or changes a
committed fixture must add a row to
`docs/modernization/contract-changes.md`:

| Field | Requirement |
| --- | --- |
| Fixture | path |
| Change reference | `same commit` (the only self-reference possible inside a commit) or a prior/follow-up SHA |
| Classification | `exact` / `semantically equivalent` / `intentionally changed` |
| Justification | why the old bytes were wrong, not why the new ones are convenient |
| Approver | the architectural lead, named |

Honest limit: a commit cannot contain its own SHA, and a test cannot decide
whether a justification is *good*. `same commit` is the canonical reference for
an atomic fixture+ledger change. What is testable is that a change is loud:
`test_fixture_inventory_is_pinned` asserts the exact filename set, and fixture
content changes fail their contract tests with a key-path diff.

### D-7 — passive recording and the error-in-success envelope → **explicit descriptor data + an explicit outcome flag**

`side_effect_class` alone does not determine recordability, so
`TaskPolicy.passive_recordable` carries the boolean, seeded to exactly the 15
tools the current heuristic selects. This is its concrete home in the 14-field
contract. The suffix rule and partly-dead root denylist (§2.4) are unnecessary
for migrated actions.

`Success.payload_signals_error` preserves `_tool_result_has_error` semantics: the
recording suppression behaves identically, and the distinction is visible in the
type system instead of implied by a string check. **Phase 1 does not fix
`isError` being hard-coded `false`** — that is Phase 3's, and the flag is what
makes the eventual fix a one-line projection change.

---

## 10. Reproduction

```bash
bin/test                                    # 418 core + 2 template
bin/test --core -k contracts                # 33
bin/test --core -k modernization_docs       # 5
```

Inventory derivation, from the package root, with `SYNAPSE_ROOT` set to a scratch
directory: import `synapse_mcp.transport.stdio_server`, read `TOOL_SCHEMAS` for
the schema columns, `FAST_TOOLS` and `_tool_deadline_seconds` for the deadline
tier, `_is_recordable_passive_analysis_tool` for recordability, and parse the
`_call_tool_impl` body for serializer and implementation target. Application use
case follows §2.5. Side-effect, risk, scope, credential, and idempotency follow
the ordered §2.2 rules after inspection of the cited implementation target and
schema/description; no judgment cell is derived from the tool-name string.

---

## 11. Findings recorded for later phases

- **F-1 — `scope.set` exposes no `confirm` property.** The write that defines
  which targets are authorized is the only `authorization_config_write` in the
  surface, is classified `high` risk, and takes no confirmation argument — while
  `workspace.delete`, a materially smaller decision, does. This is a schema-level
  observation about the authority model, not a defect introduced here. **Phase 2
  input:** whichever authority model ADR-0003 lands must decide whether editing
  the authorization allowlist is itself an authority-bearing action. Phase 1
  changes nothing about it.
- **F-2 — `UnavailableCapability` and `ApprovalRequired` share `-32001` today.**
  A missing third-party session key and a missing operator confirmation are
  semantically different but wire-identical. Phase 1 preserves the conflation
  exactly (via `legacy_code`). **Phase 3 input:** separating them is a public
  error-contract change and needs a compatibility record under ADR-0004.
- **F-3 — selected input modes change replay behavior.**
  `js.analyze_static` is a pure local analysis synchronously and
  `js.normalize_endpoints` is a convergent workspace write, but either allocates
  a new job when backgrounded. `scope.set` is a convergent configuration write
  without `workspaceId` but also creates/updates workspace state when it is
  supplied. All three are explicitly `conditional`; Phase 2 must evaluate the
  selected execution mode, not only the base action.

A tracked integrity prerequisite from Phase 0 remains open and must land before
Phase 2 persists authority state. Nothing in this design depends on it.

---

## 12. What Stage B implements

In the suggested commit order from the phase task, gated on this checkpoint and
the Phase 0 program gate:

1. `refactor(core): define typed application action contracts` — `app/actions/`
   descriptor, outcomes, policies. No registrations yet.
2. `refactor(core): add action registry and consistency checks` — registry,
   discovery, the §6 checks, the §7 architecture tests.
3. `refactor(mcp): project legacy vertical slice from registry` — six
   descriptors, projection map, dispatch projection.
4. `test(mcp): prove vertical-slice contract equivalence` — §8.3 fixture gating,
   §8.4 new contract work, including exhaustive required-confirm omission
   equivalence.
5. `docs(modernization): document action migration pattern` — the contributor
   guide for migrating action 7 through 174.

Non-goals restated: no Authority Grants, no SQLite, no compact public surface, no
MCP SDK adoption, no AGENTS/skills restructuring, no new adapters, no publicly
exposed generic action execution, no legacy removal date, no migration beyond the
six-operation slice.

---

## Appendix A — full 174-tool inventory

Columns: **Pack** is the canonical pack under D-1 (the two dotless tools show
their assigned pack); three-segment public names split once at the first dot.
**Use case** follows §2.5. **Side-effect class**, **Risk**, **Scope**, **Cred**
(requirement), **Cred access**, and **Idempotency** follow the ordered §2.2
rules after inspection of **Implementation target** and the frozen
schema/description. This keeps a session-key clear visibly classified as a
secret-state write even though it requires no credential argument.
**Task/deadline** is `sync|background_capable` / deadline tier, read from
`FAST_TOOLS` and `_tool_deadline_seconds`. **confirm** is the presence of a
`confirm` property in the frozen schema. **Passive-rec** is
`_is_recordable_passive_analysis_tool`. **Serialized by** is `transport` where
the dispatch branch calls `json.dumps`, `executor` where the module returns a
pre-serialized string. **Implementation target** is extracted from the matching
`_call_tool_impl` branch.

| # | Tool | Pack | Use case | Side-effect class | Risk | Scope | Cred | Cred access | Task/deadline | Idempotency | confirm | Passive-rec | Serialized by | Implementation target |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | :-: | :-: | --- | --- |
| 1 | `jobs.list` | jobs | control_plane | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | transport | `background_jobs.list_jobs` |
| 2 | `jobs.status` | jobs | control_plane | read_only | none | not_applicable | none | none | sync/STATUS | pure_read | · | · | transport | `background_jobs.status` |
| 3 | `jobs.cancel` | jobs | control_plane | job_control | low | not_applicable | none | none | sync/FAST | idempotent_control | · | · | transport | `background_jobs.cancel` |
| 4 | `adapters.list` | adapters | control_plane | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | transport | `adapter_registry.list` |
| 5 | `adapters.capabilities` | adapters | control_plane | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | transport | `adapter_registry.capabilities` |
| 6 | `documentation.list_templates` | documentation | reporting | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | transport | `documentation.list_templates` |
| 7 | `documentation.list_layers` | documentation | reporting | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `documentation.list_layers` |
| 8 | `perimeter.analyze_workspace` | perimeter | reporting | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `perimeter.analyze_workspace` |
| 9 | `perimeter.build_summary` | perimeter | reporting | report_build | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `perimeter.build_summary` |
| 10 | `perimeter.render_report` | perimeter | reporting | report_build | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `perimeter.render_report` |
| 11 | `documentation.build_report_context` | documentation | reporting | report_build | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `documentation.build_report_context` |
| 12 | `documentation.build_layer_report_context` | documentation | reporting | report_build | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `documentation.build_layer_report_context` |
| 13 | `documentation.build_workspace_report_context` | documentation | reporting | report_build | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `documentation.build_workspace_report_context` |
| 14 | `documentation.plan_scope_groups` | documentation | reporting | report_build | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `documentation.plan_scope_groups` |
| 15 | `documentation.prepare_validation_batch` | documentation | reporting | report_build | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `documentation.prepare_validation_batch` |
| 16 | `documentation.render_workspace_report_batches` | documentation | reporting | report_build | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `documentation.render_workspace_report_batches` |
| 17 | `documentation.build_finding_context` | documentation | reporting | report_build | none | not_applicable | optional | credential_use | sync/DEFAULT | pure_read | · | · | transport | `documentation.build_finding_context` |
| 18 | `documentation.build_finding_draft` | documentation | reporting | report_build | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `documentation.build_finding_draft` |
| 19 | `documentation.build_evidence_pack` | documentation | reporting | report_build | none | not_applicable | optional | credential_use | sync/DEFAULT | pure_read | · | · | transport | `documentation.build_evidence_pack` |
| 20 | `documentation.summarize_coverage` | documentation | reporting | report_build | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `documentation.summarize_coverage` |
| 21 | `documentation.render_markdown` | documentation | reporting | report_build | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `documentation.render_markdown` |
| 22 | `documentation.render_layer_report` | documentation | reporting | report_build | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `documentation.render_layer_report` |
| 23 | `documentation.render_workspace_report` | documentation | reporting | report_build | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `documentation.render_workspace_report` |
| 24 | `documentation.render_assessment_summary` | documentation | reporting | report_build | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `documentation.render_assessment_summary` |
| 25 | `documentation.export_json` | documentation | reporting | report_build | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `documentation.export_json` |
| 26 | `scope.set` | scope | engagement_state | authorization_config_write | high | not_applicable | none | none | sync/DEFAULT | conditional | · | · | transport | `scope.save_scope + workspace.create_workspace` |
| 27 | `project.start` | project | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | non_idempotent | · | · | transport | `evidence.ensure_project + evidence.log_event + scope.save_scope + workspace.create_workspace + credentials.auth_process_guidance + fingerprint.from_dump` |
| 28 | `scope.check_target` | scope | engagement_state | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | transport | `scope.check_target` |
| 29 | `workspace.create` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `workspace.create_workspace` |
| 30 | `workspace.add_target` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `workspace.add_target` |
| 31 | `workspace.ingest_data` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | non_idempotent | · | · | transport | `workspace.ingest_data` |
| 32 | `workspace.prepare_target_context` | workspace | engagement_state | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `workspace.prepare_target_context` |
| 33 | `workspace.summary` | workspace | engagement_state | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `workspace.workspace_summary` |
| 34 | `workspace.delete` | workspace | engagement_state | local_destructive | high | not_applicable | none | none | sync/DEFAULT | non_idempotent | Y | · | transport | `workspace.delete_workspace` |
| 35 | `workspace.create_finding` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | non_idempotent | · | · | transport | `workspace.create_finding` |
| 36 | `workspace.update_finding` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `workspace.update_finding` |
| 37 | `workspace.promote_observation_to_finding` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | non_idempotent | · | · | transport | `workspace.promote_observation_to_finding` |
| 38 | `workspace.link_evidence_to_finding` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `workspace.link_evidence_to_finding` |
| 39 | `workspace.mark_finding_reviewed` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `workspace.mark_finding_reviewed` |
| 40 | `approve_pretext_candidate` | social | engagement_state | workspace_write | low | not_applicable | none | none | sync/FAST | idempotent_write | Y | · | transport | `pretext_generator.approve_pretext_candidate` |
| 41 | `mark_detection_outcome` | purple_team | engagement_state | workspace_write | low | not_applicable | none | none | sync/FAST | idempotent_write | · | · | transport | `gap_analysis.mark_detection_outcome` |
| 42 | `workspace.set_entity_reportable` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | non_idempotent | · | · | transport | `workspace.set_entity_reportable` |
| 43 | `workspace.record_candidate_validation` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | non_idempotent | · | · | transport | `workspace.record_candidate_validation` |
| 44 | `workspace.curate_candidate` | workspace | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | non_idempotent | · | · | transport | `workspace.curate_candidate` |
| 45 | `workspace.export_finding_context` | workspace | engagement_state | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `workspace.export_finding_context` |
| 46 | `credentials.set` | credentials | credentials_auth | credential_write | high | not_applicable | required | secret_state_write | sync/DEFAULT | non_idempotent | Y | · | transport | `credentials.save_credential` |
| 47 | `credentials.list` | credentials | credentials_auth | read_only | low | not_applicable | none | redacted_metadata_read | sync/FAST | pure_read | · | · | transport | `credentials.list_credentials` |
| 48 | `credentials.set_auth_profile` | credentials | credentials_auth | credential_write | high | not_applicable | required | secret_state_write | sync/DEFAULT | non_idempotent | Y | · | transport | `credentials.save_auth_profile` |
| 49 | `credentials.set_browser_auth_profile` | credentials | credentials_auth | credential_write | high | not_applicable | required | secret_state_write | sync/DEFAULT | non_idempotent | Y | · | transport | `credentials.save_browser_auth_profile` |
| 50 | `credentials.authenticate` | credentials | credentials_auth | credential_write | high | required | required | secret_state_write | sync/DEFAULT | non_idempotent | Y | · | transport | `credentials.authenticate` |
| 51 | `credentials.browser_auth_check_setup` | credentials | credentials_auth | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `credentials.browser_auth_check_setup` |
| 52 | `credentials.browser_authenticate` | credentials | credentials_auth | credential_write | high | required | required | secret_state_write | background_capable/DEFAULT | non_idempotent | Y | · | transport | `credentials.browser_authenticate` |
| 53 | `credentials.validate_session` | credentials | credentials_auth | credential_write | high | required | required | secret_state_write | sync/DEFAULT | non_idempotent | Y | · | transport | `credentials.validate_session` |
| 54 | `credentials.get` | credentials | credentials_auth | read_only | low | not_applicable | required | redacted_metadata_read | sync/FAST | pure_read | · | · | transport | `credentials.get_credential` |
| 55 | `credentials.delete` | credentials | credentials_auth | credential_write | high | not_applicable | required | secret_state_write | sync/DEFAULT | non_idempotent | Y | · | transport | `credentials.delete_credential` |
| 56 | `dumps.list` | dumps | local_artifacts | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | transport | `dumps.list_dumps` |
| 57 | `cache.inspect_scope_data` | cache | local_artifacts | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | transport | `cache.inspect_scope_data` |
| 58 | `cache.clean_out_of_scope` | cache | local_artifacts | local_destructive | high | not_applicable | none | none | sync/DEFAULT | non_idempotent | Y | · | transport | `cache.clean_out_of_scope` |
| 59 | `cache.inspect_generated_artifacts` | cache | local_artifacts | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | transport | `cache.inspect_generated_artifacts` |
| 60 | `cache.clean_generated_artifacts` | cache | local_artifacts | local_destructive | high | not_applicable | none | none | sync/DEFAULT | non_idempotent | Y | · | transport | `cache.clean_generated_artifacts` |
| 61 | `sqli.analyze_workspace` | sqli | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `sqlmap_adapter.analyze_workspace` |
| 62 | `sqli.analyze_dump` | sqli | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `sqlmap_adapter.analyze_dump` |
| 63 | `sqli.build_sqlmap_command` | sqli | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `sqlmap_adapter.build_command` |
| 64 | `xss.analyze_workspace` | xss | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `xss_adapter.analyze_workspace` |
| 65 | `xss.analyze_dump` | xss | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `xss_adapter.analyze_dump` |
| 66 | `xss.generate_test_code` | xss | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `xss_adapter.generate_test_code` |
| 67 | `xss.execute_test` | xss | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `xss_adapter.execute_test` |
| 68 | `spec_import.capabilities` | spec_import | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `spec_import.capabilities` |
| 69 | `headers_cookies.capabilities` | headers_cookies | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `headers_cookies.capabilities` |
| 70 | `jwt.capabilities` | jwt | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `jwt_analysis.capabilities` |
| 71 | `csrf.capabilities` | csrf | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `csrf.capabilities` |
| 72 | `csrf.analyze_workspace` | csrf | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `csrf.analyze_workspace` |
| 73 | `csrf.generate_test_plan` | csrf | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `csrf.generate_test_plan` |
| 74 | `cors.capabilities` | cors | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `cors.capabilities` |
| 75 | `cors.analyze_workspace` | cors | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `cors.analyze_workspace` |
| 76 | `cors.generate_test_plan` | cors | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `cors.generate_test_plan` |
| 77 | `cors.execute_test` | cors | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `cors.execute_test` |
| 78 | `insecure_deser.capabilities` | insecure_deser | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `insecure_deser.capabilities` |
| 79 | `insecure_deser.analyze_workspace` | insecure_deser | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `insecure_deser.analyze_workspace` |
| 80 | `xxe.capabilities` | xxe | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `xxe.capabilities` |
| 81 | `xxe.analyze_workspace` | xxe | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `xxe.analyze_workspace` |
| 82 | `xxe.generate_test_plan` | xxe | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `xxe.generate_test_plan` |
| 83 | `xxe.execute_test` | xxe | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `xxe.execute_test` |
| 84 | `graphql.capabilities` | graphql | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `graphql.capabilities` |
| 85 | `graphql.analyze_workspace` | graphql | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `graphql.analyze_workspace` |
| 86 | `graphql.generate_test_plan` | graphql | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `graphql.generate_test_plan` |
| 87 | `graphql.execute_test` | graphql | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `graphql.execute_test` |
| 88 | `tls_posture.capabilities` | tls_posture | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `tls_posture.capabilities` |
| 89 | `tls_posture.analyze_workspace` | tls_posture | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `tls_posture.analyze_workspace` |
| 90 | `jwt.analyze` | jwt | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `jwt_analysis.analyze` |
| 91 | `headers_cookies.analyze_workspace` | headers_cookies | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `headers_cookies.analyze_workspace` |
| 92 | `spec_import.import_spec` | spec_import | web_assessment | workspace_write | low | not_applicable | none | none | sync/DEFAULT | non_idempotent | · | · | executor | `spec_import.import_spec` |
| 93 | `ssrf.analyze_workspace` | ssrf | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `ssrf_adapter.analyze_workspace` |
| 94 | `ssrf.generate_test_plan` | ssrf | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `ssrf_adapter.generate_test_plan` |
| 95 | `ssrf.execute_test` | ssrf | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `ssrf_adapter.execute_test` |
| 96 | `open_redirect.analyze_workspace` | open_redirect | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `open_redirect_adapter.analyze_workspace` |
| 97 | `open_redirect.generate_test_plan` | open_redirect | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `open_redirect_adapter.generate_test_plan` |
| 98 | `open_redirect.execute_test` | open_redirect | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `open_redirect_adapter.execute_test` |
| 99 | `command_injection.analyze_workspace` | command_injection | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `command_injection_adapter.analyze_workspace` |
| 100 | `command_injection.generate_test_plan` | command_injection | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `command_injection_adapter.generate_test_plan` |
| 101 | `command_injection.prepare_replay` | command_injection | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `command_injection_adapter.prepare_replay` |
| 102 | `command_injection.execute_test` | command_injection | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `command_injection_adapter.execute_test` |
| 103 | `cve.capabilities` | cve | cve_intelligence | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | executor | `cve_intel.capabilities` |
| 104 | `cve.sources` | cve | cve_intelligence | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | executor | `cve_intel.sources` |
| 105 | `cve.set_source_endpoint` | cve | cve_intelligence | runtime_config_write | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | Y | · | executor | `cve_intel.set_source_endpoint` |
| 106 | `cve.reset_source_endpoint` | cve | cve_intelligence | runtime_config_write | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | Y | · | executor | `cve_intel.reset_source_endpoint` |
| 107 | `cve.session_key.set` | cve | cve_intelligence | credential_write | high | not_applicable | required | secret_state_write | sync/DEFAULT | idempotent_write | Y | · | executor | `cve_intel.set_session_key` |
| 108 | `cve.session_key.clear` | cve | cve_intelligence | credential_write | high | not_applicable | none | secret_state_write | sync/DEFAULT | idempotent_write | Y | · | executor | `cve_intel.clear_session_key` |
| 109 | `cve.session_key.status` | cve | cve_intelligence | read_only | low | not_applicable | none | redacted_metadata_read | sync/FAST | pure_read | · | · | executor | `cve_intel.session_key_status` |
| 110 | `cve.correlate` | cve | cve_intelligence | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `cve_intel.correlate` |
| 111 | `cve.plan_tests` | cve | cve_intelligence | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | · | · | executor | `cve_intel.plan_tests` |
| 112 | `cve.prepare_replay` | cve | cve_intelligence | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `cve_intel.prepare_replay` |
| 113 | `cve.execute_test` | cve | cve_intelligence | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `cve_intel.execute_test` |
| 114 | `ssti.capabilities` | ssti | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `ssti.capabilities` |
| 115 | `ssti.passive_analyze` | ssti | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `ssti.passive_analyze` |
| 116 | `ssti.plan_tests` | ssti | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `ssti.plan_tests` |
| 117 | `ssti.prepare_replay` | ssti | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `ssti.prepare_replay` |
| 118 | `ssti.execute_test` | ssti | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `ssti.execute_test` |
| 119 | `lfi.capabilities` | lfi | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `lfi_rfi.capabilities` |
| 120 | `lfi.passive_analyze` | lfi | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `lfi_rfi.passive_analyze` |
| 121 | `lfi.plan_tests` | lfi | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `lfi_rfi.plan_tests` |
| 122 | `lfi.execute_test` | lfi | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `lfi_rfi.execute_test` |
| 123 | `ssi.capabilities` | ssi | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `ssi.capabilities` |
| 124 | `ssi.passive_analyze` | ssi | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | Y | executor | `ssi.passive_analyze` |
| 125 | `ssi.plan_tests` | ssi | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `ssi.plan_tests` |
| 126 | `ssi.prepare_replay` | ssi | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `ssi.prepare_replay` |
| 127 | `ssi.execute_test` | ssi | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `ssi.execute_test` |
| 128 | `access_control.capabilities` | access_control | web_assessment | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `access_control.capabilities` |
| 129 | `access_control.identify_objects` | access_control | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `access_control.identify_objects` |
| 130 | `access_control.record_context` | access_control | web_assessment | workspace_write | low | not_applicable | optional | credential_use | sync/DEFAULT | idempotent_write | · | · | executor | `access_control.record_context` |
| 131 | `access_control.build_test_matrix` | access_control | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `access_control.build_test_matrix` |
| 132 | `access_control.plan_tests` | access_control | web_assessment | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `access_control.plan_tests` |
| 133 | `access_control.execute_matrix_test` | access_control | web_assessment | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `access_control.execute_matrix_test` |
| 134 | `js.capabilities` | js | app_discovery | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `js_intel.capabilities` |
| 135 | `js.discover_assets` | js | app_discovery | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `js_intel.discover_assets` |
| 136 | `js.fetch_assets` | js | app_discovery | active_probe | moderate | required | optional | credential_use | sync/DEFAULT | non_idempotent | Y | · | executor | `js_intel.fetch_assets` |
| 137 | `js.analyze_static` | js | app_discovery | passive_analysis | none | not_applicable | none | none | background_capable/DEFAULT | conditional | · | · | executor | `js_intel.analyze_static` |
| 138 | `js.normalize_endpoints` | js | app_discovery | workspace_write | low | not_applicable | none | none | background_capable/DEFAULT | conditional | · | · | executor | `js_intel.normalize_endpoints` |
| 139 | `js.build_app_model` | js | app_discovery | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `js_intel.build_app_model` |
| 140 | `js.render_app_map` | js | app_discovery | report_build | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | executor | `js_intel.render_app_map` |
| 141 | `sitemap.from_dump` | sitemap | app_discovery | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | executor | `crawler_adapter.sitemap_from_dump` |
| 142 | `crawler.crawl` | crawler | app_discovery | active_probe | moderate | required | optional | credential_use | background_capable/DEFAULT | non_idempotent | Y | · | executor | `crawler_adapter.crawl` |
| 143 | `crawler.extended` | crawler | app_discovery | active_probe | moderate | required | optional | credential_use | background_capable/DEFAULT | non_idempotent | Y | · | executor | `crawler_adapter.crawl_extended` |
| 144 | `ffuf.profiles` | ffuf | scanner_execution | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | executor | `ffuf_adapter.list_profiles` |
| 145 | `ffuf.build_command` | ffuf | scanner_execution | read_only | none | not_applicable | optional | credential_use | sync/DEFAULT | pure_read | · | · | transport | `ffuf_adapter.build_command` |
| 146 | `ffuf.run_profile` | ffuf | scanner_execution | active_probe | moderate | required | optional | credential_use | background_capable/DEFAULT | non_idempotent | Y | · | executor | `ffuf_adapter.run_profile` |
| 147 | `nuclei.profiles` | nuclei | scanner_execution | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | executor | `nuclei_adapter.list_profiles` |
| 148 | `nuclei.build_command` | nuclei | scanner_execution | read_only | none | not_applicable | optional | credential_use | sync/DEFAULT | pure_read | · | · | transport | `nuclei_adapter.build_command` |
| 149 | `nuclei.run_profile` | nuclei | scanner_execution | active_probe | moderate | required | optional | credential_use | background_capable/DEFAULT | non_idempotent | Y | · | executor | `nuclei_adapter.run_profile` |
| 150 | `nmap.profiles` | nmap | scanner_execution | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | executor | `nmap_adapter.list_profiles` |
| 151 | `nmap.build_command` | nmap | scanner_execution | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `nmap_adapter.build_command` |
| 152 | `nmap.run_profile` | nmap | scanner_execution | active_probe | moderate | required | none | none | background_capable/DEFAULT | non_idempotent | Y | · | executor | `nmap_adapter.run_profile` |
| 153 | `shodan.session_key.set` | shodan | infrastructure_osint | credential_write | high | not_applicable | required | secret_state_write | sync/DEFAULT | idempotent_write | Y | · | executor | `shodan_adapter.set_session_key` |
| 154 | `shodan.session_key.clear` | shodan | infrastructure_osint | credential_write | high | not_applicable | none | secret_state_write | sync/DEFAULT | idempotent_write | Y | · | executor | `shodan_adapter.clear_session_key` |
| 155 | `shodan.session_key.status` | shodan | infrastructure_osint | read_only | low | not_applicable | none | redacted_metadata_read | sync/FAST | pure_read | · | · | executor | `shodan_adapter.session_key_status` |
| 156 | `shodan.host` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `shodan_adapter.host_lookup` |
| 157 | `shodan.internetdb` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `shodan_adapter.internetdb_lookup` |
| 158 | `shodan.domain` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `shodan_adapter.domain_info` |
| 159 | `shodan.resolve` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `shodan_adapter.resolve` |
| 160 | `shodan.reverse` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `shodan_adapter.reverse` |
| 161 | `shodan.search_count` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `shodan_adapter.search_count` |
| 162 | `shodan.search` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `shodan_adapter.search` |
| 163 | `shodan.search_facets` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `shodan_adapter.search_facets` |
| 164 | `shodan.search_filters` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `shodan_adapter.search_filters` |
| 165 | `shodan.target_summary` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/DEFAULT | pure_read | Y | · | executor | `shodan_adapter.target_summary` |
| 166 | `shodan.company_queries` | shodan | infrastructure_osint | third_party_read | low | checked_downstream | none | none | sync/FAST | pure_read | · | · | executor | `shodan_adapter.company_queries` |
| 167 | `evidence.log_event` | evidence | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | non_idempotent | · | · | transport | `evidence.log_event` |
| 168 | `evidence.tail` | evidence | engagement_state | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | transport | `evidence.tail_events` |
| 169 | `evidence.init_project` | evidence | engagement_state | workspace_write | low | not_applicable | none | none | sync/DEFAULT | idempotent_write | · | · | transport | `evidence.ensure_project` |
| 170 | `evidence.host_context` | evidence | engagement_state | read_only | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `evidence.host_context` |
| 171 | `fingerprint.from_dump` | fingerprint | infrastructure_osint | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `fingerprint.from_dump` |
| 172 | `fingerprint.analyze_workspace` | fingerprint | infrastructure_osint | passive_analysis | none | not_applicable | none | none | sync/DEFAULT | pure_read | · | · | transport | `fingerprint.analyze_workspace` |
| 173 | `fingerprint.probe_versions` | fingerprint | infrastructure_osint | active_probe | moderate | required | none | none | sync/DEFAULT | non_idempotent | Y | · | transport | `fingerprint.probe_versions` |
| 174 | `fingerprint.read_host` | fingerprint | infrastructure_osint | read_only | none | not_applicable | none | none | sync/FAST | pure_read | · | · | transport | `fingerprint.read_host_fingerprint` |
