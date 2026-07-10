---
name: synapse-dev
description: >
  Drive development of Synapse, a local-first MCP server for authorized offensive-security
  agentic operations (entity hierarchy Workspace → Target → Finding; adapter framework;
  access-control BOLA/BFLA/BOPLA testing; consolidated operator/high-level reports). Use
  this skill whenever the work involves the Synapse repository, an MCP/adapter for offensive
  security, or any task that mentions Synapse, synapse_mcp, access_control.py, the adapter
  framework, workspace/finding/evidence normalization, or the operator/high-level report
  model — including reviewing the codebase, writing implementation task specs for Codex or
  Claude Code, and verifying completed work. Use it even when the user only says "review
  this" or "spec this out" in a Synapse context, and use it both in chat (review/spec
  drafting) and in Claude Code (working in the repo directly).
---

# Synapse Development

Synapse is a local-first MCP control plane for authorized offensive-security agentic
operations. The operator drives; the agent acts through guarded adapters; Synapse normalizes
results into durable workspace state. This skill covers the project's working loop: **review
the code, write a precise implementation spec, hand it to an implementer (Codex or Claude
Code), then verify the work end to end.**

The defining principle of this workflow: **architectural decisions live upstream, in the
spec.** A downstream implementer should make *no* architectural judgment calls. If a spec
leaves a design choice open, that is a defect in the spec, not a decision for the implementer.

## When you are doing what

There are three modes. Identify which one the request is in before acting.

1. **Review** — read part of the codebase and report correctness bugs, gaps, design risks.
   Output is a prose findings list grouped by severity. Verify claims against the code; do
   not assert behavior you have not read.
2. **Spec** — turn a known problem (often from a review) into a self-contained task an
   implementer can execute without judgment. Output is one or more task specs in the
   canonical format below.
3. **Verify** — confirm an implementer's completed work satisfies the spec and violates no
   contract. Output is a pass/fail assessment with evidence.

A typical session flows review → spec → (implementer works) → verify. Cross-validating a
review against a second reviewer (e.g. Codex) before specifying is an established pattern —
strong alignment raises confidence; disagreement is where the real design questions hide.

## First steps in any Synapse session

- **Orient before editing.** The repo root holds the package under `MCPS/Synapse-MCP/`.
  Read `references/architecture.md` for the layout, the load-bearing contracts, and the
  guardrails. Do this before reviewing or specifying anything non-trivial — the contracts
  are what make a spec safe.
- **Tests are the source of truth.** Run the harness, not bare `pytest`:
  ```bash
  bin/test
  ```
  It uses the repo `.venv` (Playwright is installed there for screenshot checks). A bare
  `pytest` is unreliable unless the package is installed or `PYTHONPATH` is set.
- **Respect the DATA/ privacy rule.** Real engagement data lives under `DATA/` (gitignored).
  Never put client hostnames, credentials, or real targets in committed code, docs, specs,
  or examples. Use obviously fictional placeholders (e.g. `app.acme-demo.test`).
- **Maintain the local version log.** Every code change must update `docs/Version-Log.md`.
  This is a **local, gitignored, per-developer scratch log** (provisioned from
  `docs/Version-Log.template.md` by `bin/check-setup`) — it is personal dev history, not a
  committed repo artifact, so do not read it to ground your understanding of the codebase and
  do not assume another clone has the same contents. Shared, shipped history lives in the
  committed root `CHANGELOG.md`; summarize the user-facing narrative there at ship time.

## Reviewing

Read the actual code before claiming anything. Search/grep to confirm a function's real
shape; don't review from memory of "how code like this usually works." For each issue,
classify it as a **correctness bug**, a **gap** (missing field/behavior that will hurt in
real use), or a **design risk** (fine now, costly later), and say why it matters in
operational terms. Group findings by severity, lead with the highest-impact, and end with
what is already solid — an honest review names strengths, not just defects.

When a claim is consequential (especially anything about the report presentation boundary or
access-control semantics), verify it against the code in this session rather than trusting a
prior reviewer's wording. Restating someone else's review without checking is how subtle
errors propagate.

## Specifying (the core deliverable)

A Synapse task spec exists so an implementer can act mechanically. Write every spec in the
canonical structure. Use `references/task-spec-format.md` for the full templates (a
Codex-style spec and a Claude Code agentic-session spec) and a worked example. The minimum
fields, always present:

```
TASK — short imperative title
FILES — exact paths the change touches
PROBLEM / WRONG BEHAVIOR — what the code does now and how to see it
WHY IT MATTERS — the operational consequence (false positive, data leak, duplicate, etc.)
EXPECTED BEHAVIOR — the precise correct behavior, no ambiguity left open
REGRESSION TESTS — the test(s) that must pass, with concrete inputs and expected outputs
NON-GOALS — explicit guardrails so the implementer doesn't expand scope
```

Rules that keep specs safe:

- **No open architectural decisions.** If implementing the spec requires choosing a contract
  (key strategy, normalization boundary, redaction mode behavior), decide it in the spec and
  state it. Threading workspace context into a parser, for example, is an architecture call —
  resolve it upstream (see the two-phase normalization contract in `references/architecture.md`).
- **Name the regression, not just the feature.** If a bug duplicates findings, the test is
  "ingest the same result twice → one finding," with the exact keys. Vague tests let wrong
  implementations pass.
- **Flag test-contract changes.** If a fix changes behavior an existing passing test encodes,
  say so in the spec and tell the implementer to update that test to the new contract — or
  they will be blindsided by a "passing" test that enforces the old behavior.
- **Carry the guardrails.** Every spec restates the relevant non-goals: no database, no new
  report engine, no RBAC/ABAC engine, no frontend framework, no broad rewrite. Keep changes
  small and legible. Workspace/agent data stays rich; Operator and High-Level report views are
  internal presentation modes, not a client-safe redaction boundary.
- **Order by operational impact.** For the current local-only report model,
  prioritize incorrect execution, normalization, relationships, candidate
  applicability, and workflow state over new internal redaction behavior. A
  future explicit client export restores strict confidentiality/redaction as a
  first-class contract.

If the spec is for Claude Code rather than Codex, frame it as an agentic session: an
inspect → implement → verify loop per task, one commit per task, `bin/test` green as the gate,
and a standing instruction to **stop and report** rather than improvise if a task can't be
done within the guardrails. The detail belongs in `references/task-spec-format.md`.

## Verifying

Verification is end-to-end, not a glance at the diff. Read `references/verification-checklist.md`
and work it. In short: the regression tests named in the spec must exist and pass; `bin/test`
must be green overall; the relevant contract must be intact (re-read the touched contract in
`references/architecture.md` and confirm the change honors it); and no guardrail was crossed
(no new engine/DB, no workspace-data redaction, no scope creep). Confirm the local,
gitignored `docs/Version-Log.md` has an entry for code changes. Report pass/fail per task with the
evidence you checked, and call out anything the implementer changed beyond the spec.

## Reference files

- `references/architecture.md` — repo layout, the load-bearing contracts (two-phase
  normalization, `_entity_key` stability, adapter metadata, operator-control gates, the
  two-report internal presentation model, access-control semantics), and the global guardrails.
  Read first.
- `references/task-spec-format.md` — the canonical spec templates (Codex and Claude Code
  variants) and a full worked example.
- `references/verification-checklist.md` — the end-to-end verification procedure.
