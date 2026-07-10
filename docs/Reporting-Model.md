# Reporting Model

## Purpose

Synapse keeps a single, rich source of truth — the workspace — and produces
internal HTML views over it for the operator and their team. The workspace and
its evidence are local-first and agent-facing: they stay complete so the
operator and the agent always have full operational context.

Current Beta reports are **local internal artifacts, not client deliverables**. They are
operator artifacts with an Operator / High-Level presentation toggle in the
same HTML file. The toggle reduces visual density; it is not a confidentiality
or redaction boundary.

## Data Flow

```text
adapter output
  -> evidence / normalized workspace state   (rich, local-first, agent-facing)
  -> layer context                           (core/documentation/layers.py)
  -> report model                            (internal presentation metadata)
  -> renderer / exporter                     (layer_renderer.py, exporters.py)
  -> Markdown / HTML / JSON artifact
```

Adapters produce workspace entities and raw evidence. The documentation builder
reads that state, assembles a report/layer context, and the renderer/exporter
emits the final artifact. Internal HTML reports may contain operational
references in the source even when the High-Level view hides them visually.

## The Two Views

Generated HTML reports contain two internal presentation views:

- **Operator Report** — detailed operational view with traceability such as
  credential references, approval IDs, replay IDs, evidence references, local
  artifact paths, adapter metadata, and execution context where available.
- **High-Level Report** — internal summary view with less operational noise,
  focused on summary, confirmed findings, candidate observations, key access
  control/auth/JS/perimeter results, coverage, gaps, and recommended next steps.

The consolidated report opens on the **Operator** view by default; render with
`redactionMode: high_level` (or use the in-report toggle) to start in the
High-Level view. The document title stays view-neutral because both views ship in
the same HTML file.

The view switch is implemented with static CSS and minimal inline JavaScript.
For example, high-level mode can hide cells marked `operator-only`:

```css
body.high-level .operator-only { display: none; }
body.operator .high-level-only { display: none; }
```

This is acceptable only because the generated HTML is internal. Hidden values
may still exist in the HTML source.

## Workspace Data vs Report Output

Workspace JSON and agent-facing tool responses are **always rich and complete**.
They are not redacted. The agent keeps access to local file paths, evidence IDs,
approval IDs, credential references, JS artifact paths, and adapter metadata so
it can reason and act. Weakening the workspace would weaken the agent.

Reports are never the source of truth. Workspace state plus evidence are. A
report is a point-in-time, presentation-scoped projection of that state.

## Internal Presentation Rules

Report tables may mark high-detail columns such as `Credential ID`, `Approval
ID`, `Local Path`, `Replay ID`, `Exploit Reference`, and similar operational
references as `operator-only`. High-Level view hides those columns for
readability, but the values remain in the HTML source and in workspace state.
The set of `operator-only` headers is defined in
`layer_renderer._is_operator_only_header()`; hide a column there rather than
stripping data from the layer context (reports are internal, not client
deliverables).

Candidate / review items render as compact tables grouped by category (one
table per analyzer category such as open redirect, command injection, SSRF),
not as a single flat dump or one callout card per row. The category is the
group heading and rows are ordered by severity; confirmed findings keep their
own callout treatment so candidates stay visually distinct from findings.

`Confidence` is an agent-time signal: it is retained in workspace state and
agent-facing observations but is **not** rendered as a report column. It informs
how the agent assembles a report; it is not report content.

The existing `safe` redaction mode is retained only as a deprecated
compatibility input for older calls. Internal field hiding is not an enforcement
boundary or a current operational priority. A future explicit `client_export`
or `deliverable` generator may implement strict omission/redaction as a separate
feature.

## Layer Report Contract

Seven normalized passive layers (perimeter, JavaScript, authentication, access
control, web vulnerabilities, CVE exposure, and engagement coverage) share one
shape: they read existing workspace state and model artifacts, apply internal
presentation metadata, and expose summary / sections / gaps / recommended next
steps. They render HTML by default and send no active traffic. The CVE layer
("Suggested CVEs & Exploitability") ranks
known-exploited (KEV) candidates first and keeps raw exploit/PoC URLs in an
`operator-only` column, consistent with the presentation-only rules above.

Consolidated workspace reports span every layer and **never truncate or skip
sections**. Each layer's full canonical section set always renders in a fixed
order; a section with no data renders its header plus an explicit, visually muted
empty-state line (for example, "No replay results recorded.") rather than being
dropped. This guarantees a reader can tell the difference between "tested, no
result" and "not present in the report."

Coverage reporting reflects execution policy and an honest active/passive split:
`summarize_coverage()` prefers the workspace-local scope (falling back to the
global scope) and only counts an action as active when `is_active_action()` finds
a positive active signal (approval metadata, traffic, an active action type, or a
known active adapter). Passive work — documentation/report generation, workspace
import, passive normalization, operator notes, static analysis without traffic —
is never counted as active.

## What Reports Must Not Do

- Must not be treated as the source of truth; workspace state and evidence are.
- Must not imply active validation without approved-action / active-traffic
  evidence — coverage and assessment language must match what was actually,
  actively tested.
- Must not claim the High-Level view is sanitized, client-facing, redacted, or
  safe for external distribution.
- Must not depend on external resources: generated HTML embeds its image assets,
  stylesheet, and script, and uses local system-font fallbacks. It contains no
  external CSS, scripts, fonts, or remote images.
- Must not include demo/sample ACME rows in production output.
- Must not achieve presentation simplicity by redacting workspace JSON or
  stripping detail from agent-facing responses.
