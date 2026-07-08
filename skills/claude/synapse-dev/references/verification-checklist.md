# Verification Checklist

Verifying an implementer's work is end-to-end, not a diff glance. Work this procedure and
report pass/fail per task with the evidence you actually checked.

## 1. Tests
- Run `bin/test` (repo `.venv`, not bare `pytest`). The whole suite must be green, not just
  the new tests.
- Confirm the **specific regression tests named in the spec exist** and assert what the spec
  said — with the concrete inputs/outputs specified. A fix without its named regression test
  is not done, even if the suite is green (the bug can silently return).
- If the spec flagged an existing test that encoded old behavior, confirm that test was updated
  to the new contract rather than deleted or left asserting the old behavior.

## 2. Contract integrity
Re-read the relevant contract in `architecture.md` and confirm the change honors it:
- **Two-phase normalization:** no workspace context leaked into a parser; workspace-only fields
  computed at ingest, not parse.
- **`_entity_key` stability:** keys don't mutate on evidence linking; no `action:action|` or
  `type:|` collisions introduced.
- **Typed models:** new persisted fields are declared on the matching entity model.
- **Operator-control gates:** confirmation/scope/credential gates still intact; nothing now
  sends traffic without `confirm`, and secrets still flow by reference.
- **Access-control semantics:** success stays 200–299; ownership (not array position) drives
  baseline/substitutions; BOPLA behavior still differentiated; strict-context default intact.
- **Report presentation boundary:** Operator and High-Level views are internal presentation
  modes, not a redaction boundary; workspace/agent data stays rich; every canonical section
  still renders with an explicit empty-state line; coverage uses workspace scope and doesn't
  mislabel passive as active.

## 3. Guardrails
Confirm no guardrail was crossed: no database, no new report engine/framework/plugin system,
no RBAC engine, no broad rewrite; change is small and legible; no real client data committed.

## 4. Local version log
For code changes, confirm the local `docs/Version-Log.md` was updated. It is a gitignored,
per-developer scratch log (provisioned from `docs/Version-Log.template.md` on setup) — local
dev history, not a committed artifact to read for grounding. Shipped, shared history is
summarized into the committed root `CHANGELOG.md`.

## 5. Scope discipline
Diff the change against the spec. Call out anything the implementer changed **beyond** the
spec — even improvements. Out-of-scope edits are a finding to report, not silently accept;
they may carry unreviewed risk.

## 6. Report
For each task: PASS or FAIL, the evidence checked (which tests ran, which contract you
re-read, what you confirmed), and any deviations. If FAIL, state precisely what's missing or
wrong and the smallest correction — don't hand back a vague "needs work."

## Cross-validation (optional but valuable)
For high-stakes changes (access-control semantics, the report presentation boundary), a second
independent review (e.g. Codex) raises confidence. Strong agreement is reassuring; disagreement
points at exactly the spot that needs a human design decision.
