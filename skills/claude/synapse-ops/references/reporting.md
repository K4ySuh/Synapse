# Reporting

Matches the repo's `docs/Reporting-Model.md`. Reports are **internal Synapse/operator artifacts**,
not client deliverables. They are **views over workspace state and evidence** — the workspace plus
evidence is the single rich source of truth. Reports are never the source of truth.

## Data flow
```
adapter output
  -> evidence / normalized workspace state   (rich, local-first, agent-facing)
  -> layer context                           (core/documentation/layers.py)
  -> report model                            (internal presentation metadata)
  -> renderer / exporter                     (layer_renderer.py, exporters.py)
  -> Markdown / HTML / JSON artifact
```

## The two views (both internal)
A generated HTML report contains two presentation views in one self-contained file:
- **Operator Report** — detailed operational view with full traceability: credential references,
  approval IDs, replay IDs, evidence references, local artifact paths, adapter metadata, execution
  context.
- **High-Level Report** — internal summary view with less operational noise: summary, confirmed
  findings, candidate observations, key access-control/auth/JS/perimeter results, coverage, gaps,
  recommended next steps.

The switch is static CSS + minimal inline JS (e.g. `body.high-level .operator-only { display:none }`).
This is acceptable **only because the report is internal** — hidden values still exist in the HTML
source and in workspace state.

## Redaction is not a boundary here (current durable model)
- The Operator/High-Level difference is **density and usability, not security**.
- Do **not** call High-Level safe, redacted, external, or client-facing. High-level means concise
  internal summary, not sanitized deliverable. Do not assume High-Level reports are safe to share
  externally.
- The `safe` redaction mode is **a deprecated compatibility input** for older calls — not a client
  deliverable, not the goal of the report layer. Do not build or spec new safe/sanitized redaction
  into reports unless the operator explicitly requests it as new scope.
- A future `client_export` / `deliverable` mode may implement true redaction and field omission as
  a separate feature. Until then, treat every report as internal-only.
- Never achieve presentation simplicity by redacting workspace JSON or stripping detail from
  agent-facing responses — weakening the workspace weakens the agent.

## Section rendering & coverage (already in place)
- Consolidated workspace reports (`documentation.render_workspace_report`) span every layer and
  **never truncate or skip sections**. Each layer's full canonical section set renders in a fixed
  order; a section with no data renders its header plus an explicit, visually muted empty-state
  line (e.g. "No replay results recorded.") so a reader can tell "tested, no result" from "not in
  the report."
- Coverage (`documentation.summarize_coverage`) reflects execution policy: it prefers
  workspace-local scope (global as fallback) and only counts an action active when
  `is_active_action()` finds a positive signal (approval metadata, traffic, an active action type,
  or a known active adapter). Passive work (report generation, import, passive normalization,
  operator notes, static analysis without traffic) is never counted as active.

## Report quality rules
- Keep candidates visually and textually **distinct** from confirmed findings.
- Include coverage and testing gaps; include recommended next steps.
- Keep local paths and operational references available to the operator (Operator view).
- Self-contained and offline-safe: no external fonts, CSS, scripts, or remote images.
- **Never ship demo/sample ACME rows in production output** — fictional rows are for templates only.
