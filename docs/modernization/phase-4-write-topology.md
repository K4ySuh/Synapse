# Phase 4 State Write Topology

Status: Task 4A inventory, checked against `c9e6d46` on 2026-08-24.

This inventory is the extraction boundary for State Store v2. It records every
direct durable writer in `synapse_mcp` before repository extraction. JSON v1
remains authoritative unless a workspace has an explicit, verified v2 selector;
Task 4A does not create that selector for production workspaces and does not
dual-write.

## Authoritative operational state

| Owner | Durable paths | Writer/locking behavior | Phase 4 repository boundary |
| --- | --- | --- | --- |
| `core/workspace.py` | `DATA/workspaces/<id>/workspace.json`, `scope.json`, target metadata, target entity JSON, evidence Markdown, raw ingest snapshots, report decisions | `_write_json` uses atomic replace; multi-record mutations use `workspace_lock`; some derived files are direct writes | `WorkspaceRepository` and the per-workspace repository bundle. JSON-v1 adapter delegates to the existing module; SQLite-v2 owns migrated metadata, scope, targets, entities, relations, findings, evidence metadata, revisions, and audit. |
| `core/evidence.py` | global and organization/host `events.jsonl`, metadata JSON | append/direct writes without the workspace lock | `EvidenceRepository`; existing append/index behavior is retained by the JSON-v1 adapter. SQLite-v2 audit/evidence writes are workspace-local and transactional. |
| `core/background_jobs.py` | workspace job records plus stdout/stderr/result sidecars | record replacement under `workspace_lock`, revision compare, subprocess stream files, bounded cleanup | Future `TaskRepository`; Task 4A creates execution tables but does not move live jobs. |
| `policy/repository.py` | `DATA/workspaces/<id>/authority/state.json` | atomic replacement under `workspace_lock`, repository and grant revisions | Future authority repository adapter; Task 4A creates the constrained authority schema but does not migrate grants, secret state, or dispatch traffic. |
| `app/facade/resources.py` | modern transport `resources.json` | atomic replacement under a file lock; records opaque resource bindings to local paths | `ArtifactRepository` for immutable bytes and artifact metadata. Existing resource tokens remain JSON-v1 behavior in 4A. |
| `app/facade/services.py` | modern transport `operations.json` | atomic replacement under a file lock; request-state handles and arguments | Future request-state repository. Task 4A schema stores only opaque references and non-secret metadata. |
| `core/scope.py` | configured scope JSON | atomic replacement under a file lock | Scope snapshots in SQLite-v2; global operator scope stays unchanged in 4A. |
| `core/credentials.py` | credential metadata and encrypted/permission-confined secret files | atomic replacement and store locks | Explicitly excluded: credential bodies, cookies, bearer values, and encryption keys never enter SQLite. Only future opaque references may be stored. |

## Derived outputs and adapter working files

These writes are artifacts, caches, reports, or bounded worker inputs rather
than relational truth. They remain file-backed in Task 4A and become eligible
for CAS ingestion only through an explicit later caller change.

| Owner | Write class |
| --- | --- |
| `core/atomic_io.py` | shared atomic replace and advisory file-lock primitive |
| `core/cache.py` | cache history, manifests, and retention cleanup |
| `core/execution.py`, `core/job_worker.py` | planned output and worker result sidecars |
| `core/fingerprint.py`, `core/perimeter.py` | fingerprints and rendered perimeter outputs |
| `core/documentation/batching.py`, `core/documentation/exporters.py` | self-contained report files and batch indexes |
| `adapters/web/crawler_adapter.py` | crawler state, worker arguments, JSON, Mermaid, and SVG outputs |
| `adapters/web/js_intel.py` | worker arguments/state, fetched script assets, indexes, and rendered maps |
| `adapters/web/cve_intel.py` | source cache/state replacement under its own lock |
| `adapters/web/nuclei_adapter.py` | bounded scanner input URL file |

## Extraction rules

1. Application code selects a `WorkspaceRepositoryBundle`; it does not infer a
   database or artifact path. An absent selector means JSON v1.
2. The JSON-v1 adapter calls the existing workspace/evidence APIs so their
   normalization, locks, sanitization, IDs, and evidence fan-out remain intact.
3. SQLite-v2 SQL is confined to `synapse_mcp/state/` and versioned migration
   resources. Connections and filesystem readiness are also owned there.
4. Domain rows, the monotonic workspace revision, change-log entries, and the
   audit event commit in one transaction. Artifact bytes install and fsync
   before their metadata transaction; an unreferenced installed blob is safe.
5. Live jobs, authority evaluation, resource tokens, operation handles,
   credentials, report rendering, and the Phase 3 context facade are not cut
   over in Task 4A.
