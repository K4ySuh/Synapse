# ADR-0008: Action identity and pack scheme

- Status: Proposed
- Date: 2026-07-30
- Owners: Synapse architectural lead
- Applies from: Phase 1
- Supersedes: None

## Context

The 174-tool surface usually uses `namespace.action` naming. Measured at
`4bcba55`: 38 dotted first-segment namespaces, 3 of which hold exactly one tool
(`project`, `dumps`, `sitemap`), plus **two tools with no namespace at all**:

- `approve_pretext_candidate`, implemented in `adapters/social/pretext_generator.py`
- `mark_detection_outcome`, implemented in `core/purple_team/gap_analysis.py`

They are not a matched pair; they are orphans from two unrelated features. The
baseline metric "40 namespaces" counts each dotless name as its own namespace,
which is why the figure disagrees with a plain namespace count.

Six names have three segments:
`cve.session_key.{set,clear,status}` and
`shodan.session_key.{set,clear,status}`. An identity rule must decide whether
their pack is the first segment (`cve`, `shodan`) or everything before the last
segment (`cve.session_key`, `shodan.session_key`).

Phase 1 introduces `ActionDescriptor.id` and `ActionDescriptor.pack`. Public tool
names cannot change in Phase 1 — that is an exit criterion — so this is a
question about *internal* identity and about whether `pack` absorbs the namespace
concept. Recorded in the program kickoff as D-8 specifically so it would not be
discovered mid-implementation.

## Decision

`ActionId` is a value object that parses `pack.local_name` by splitting once at
the first dot. `pack` is one non-empty segment. `local_name` is one or more
non-empty dot-separated segments; every segment matches
`[a-z][a-z0-9_]*`. A name without a dot is rejected at construction.

Thus `cve.session_key.set` has pack `cve` and local name `session_key.set`;
`shodan.session_key.status` has pack `shodan`. Splitting at the last dot was
rejected because it would introduce two pseudo-packs while `cve` and `shodan`
still own other actions, raising the canonical pack count from 40 to 42.

The two orphans are assigned the pack in which they already live:
`social.approve_pretext_candidate` and `purple_team.mark_detection_outcome`. The
three single-tool namespaces are unchanged — a one-action pack is legitimate and
needs no special handling.

**The legacy public name is stored explicitly in the transport-owned projection
map, never derived from the `ActionId` by convention.** Public names are
unchanged.

## Invariants

- Every registered action has a canonical `pack.local_name` id; there is no
  dotless `ActionId`, and `local_name` may contain additional segments.
- `descriptor.pack == descriptor.id.pack`, enforced at registration.
- The registry contains exactly 40 packs for the 174-action baseline.
- Legacy public names are data in the projection map, not a derivation rule.
- Phase 1 changes no public tool name; `tools/list` remains 174 ordered entries
  at 99,337 compact bytes.

## Alternatives considered

### Registry inherits legacy names verbatim, dotless entries included

- Benefits: No mapping layer; internal and public identity are the same string.
- Costs: `ActionId` cannot guarantee a pack, so every consumer that groups,
  filters, or authorizes by pack needs a special case for exactly two tools —
  permanently, and in code that has not been written yet.
- Reason rejected: It propagates a naming accident into the type system of every
  later phase, including the Phase 2 authority model that will want to reason
  about packs.

### Opaque slugs or integer action ids

- Benefits: Fully decoupled from public naming; renames become free.
- Costs: Unreadable in logs, evidence, and review; any statement about an action
  requires a lookup table.
- Reason rejected: Synapse's operational artifacts are meant to be inspectable by
  a human operator. Opaque identity works against the product's core property.

### Split at the last dot

- Benefits: The local action is always one segment.
- Costs: Session-key helpers become two new packs even though they share
  implementation modules and policy context with the rest of `cve` and
  `shodan`; pack-level grants would fragment one capability.
- Reason rejected: First-segment ownership matches the existing module and
  functional grouping and preserves the measured 40-pack model.

### Derive the legacy name from the id by rule (strip the pack for known orphans)

- Benefits: No projection map entry per action.
- Costs: The rule needs a hard-coded exception list containing exactly the two
  tools this ADR exists to normalize.
- Reason rejected: A convention with an exception list is a lookup table with
  worse ergonomics and a failure mode that only appears at projection time.

## Consequences

- Positive: Every action has a well-formed, greppable identity; pack-level
  reasoning is total rather than "total except two".
- Negative: One projection-map entry per action. This is deliberate — the map is
  also where the serializer choice and argument adapter live, so the entry is not
  redundant.
- Operational: No change an operator or agent can observe.
- Security: Pack-level policy reasoning in Phase 2 has no gap to special-case.
- Compatibility: Guaranteed by the Tier-1 `tools_list.json` fixture plus the
  independent count and byte pins.

## Migration and rollback

Assign ids as actions migrate; the projection map is populated in the same commit
as each descriptor. Rollback for any action is to restore its legacy dispatch
branch. No public name, storage format, or protocol version is involved.

## Verification

- `test_action_ids_are_well_formed_pack_and_local_name`.
- `test_three_segment_action_ids_split_at_the_first_dot`.
- `test_registry_has_forty_canonical_packs`.
- `test_projection_map_covers_every_migrated_action_and_preserves_legacy_names`.
- `test_duplicate_action_id_fails_registration`.
- Tier-1 `tools_list.json` equality plus the 174-count and 99,337-byte pins.
