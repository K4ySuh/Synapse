"""Task 4A State Store v2 and workspace-local CAS acceptance tests."""

from __future__ import annotations

import ast
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from synapse_mcp.state import (
    ArtifactCollisionError,
    ArtifactLimitError,
    ArtifactLimits,
    ArtifactRecord,
    ArtifactStoreError,
    AuditRecord,
    ContentAddressedArtifactRepository,
    EntityRecord,
    EvidenceRecord,
    RelationRecord,
    SQLiteWorkspaceRepository,
    StateConflictError,
    StateIntegrityError,
    StateReadinessError,
    StateStoreError,
    TargetRecord,
    VerticalSlice,
    WorkspaceRecord,
    online_backup,
    repository_bundle,
    selected_store_version,
)
from synapse_mcp.state.connections import ConnectionFactory
from synapse_mcp.state.migrations import schema_hash
from synapse_mcp.state.readiness import probe_state_store_runtime, select_sqlite_runtime


ROOT = Path(__file__).resolve().parents[3]
STATE_PACKAGE = ROOT / "MCPS" / "Synapse-MCP" / "synapse_mcp" / "state"


class Phase4AStateStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _repository(self, workspace_id: str = "alpha") -> SQLiteWorkspaceRepository:
        return SQLiteWorkspaceRepository(workspace_id, self.root / workspace_id)

    def _initialize(self, workspace_id: str = "alpha") -> SQLiteWorkspaceRepository:
        repository = self._repository(workspace_id)
        revision = repository.initialize(
            WorkspaceRecord(workspace_id, organization="Example Org", notes="isolated v2 test"),
            audit=AuditRecord(f"audit-{workspace_id}-1", "workspace.create", "Created isolated v2 workspace."),
        )
        self.assertEqual(revision, 1)
        return repository

    @staticmethod
    def _slice(
        artifact: ArtifactRecord | None,
        *,
        prefix: str = "one",
        target_id: str = "target-one",
        target_natural_key: str = "example.test",
    ) -> VerticalSlice:
        entity_a = EntityRecord(
            f"entity-{prefix}-a",
            "endpoint",
            f"GET:https://example.test/{prefix}",
            target_id=target_id,
            payload={"method": "GET", "path": f"/{prefix}"},
        )
        entity_b = EntityRecord(
            f"entity-{prefix}-b",
            "parameter",
            f"query:{prefix}",
            target_id=target_id,
            payload={"name": prefix, "location": "query"},
        )
        evidence_id = f"evidence-{prefix}"
        return VerticalSlice(
            scope_snapshot_id=f"scope-{prefix}",
            scope={"hosts": ["example.test"]},
            targets=(TargetRecord(target_id, target_natural_key, payload={"target": "example.test"}),),
            entities=(entity_a, entity_b),
            relations=(
                RelationRecord(
                    f"relation-{prefix}",
                    entity_a.entity_id,
                    entity_b.entity_id,
                    "accepts_parameter",
                ),
            ),
            evidence=(EvidenceRecord(evidence_id, "Observed endpoint and parameter.", target_id=target_id),),
            artifact=artifact,
            evidence_artifact_links=((evidence_id, artifact.artifact_id),) if artifact else (),
            audit=AuditRecord(f"audit-{prefix}", "workspace.slice", "Committed vertical slice."),
        )

    def test_vertical_slice_reopens_with_exact_revision_records_and_integrity(self) -> None:
        repository = self._initialize()
        source = self.root / "evidence.txt"
        source.write_text("bounded evidence\n", encoding="utf-8")
        artifact = repository.artifacts.ingest_path(source, media_type="text/plain", origin="test")

        self.assertEqual(repository.apply_vertical_slice(self._slice(artifact), expected_revision=1), 2)
        repository.verify_integrity()

        reopened = self._repository()
        snapshot = reopened.snapshot()
        self.assertEqual(snapshot["revision"], 2)
        self.assertEqual(snapshot["workspace"]["workspaceId"], "alpha")
        self.assertEqual(len(snapshot["scopeSnapshots"]), 1)
        self.assertEqual(len(snapshot["targets"]), 1)
        self.assertEqual(len(snapshot["entities"]), 2)
        self.assertEqual(len(snapshot["relations"]), 1)
        self.assertEqual(len(snapshot["evidence"]), 1)
        self.assertEqual(snapshot["artifacts"][0]["artifactId"], artifact.artifact_id)
        self.assertEqual([event["revision"] for event in snapshot["auditEvents"]], [1, 2])

        process = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import json,sys; from pathlib import Path; "
                    "from synapse_mcp.state import SQLiteWorkspaceRepository; "
                    "print(json.dumps(SQLiteWorkspaceRepository('alpha', Path(sys.argv[1])).snapshot(), sort_keys=True))"
                ),
                str(self.root / "alpha"),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        process_snapshot = json.loads(process.stdout)
        self.assertEqual(process_snapshot["revision"], 2)
        self.assertEqual(process_snapshot["artifacts"][0]["digest"], artifact.digest)

        with reopened.connection_factory.connect() as connection:
            pragmas = {
                "journal": connection.execute("PRAGMA journal_mode").fetchone()[0],
                "foreignKeys": connection.execute("PRAGMA foreign_keys").fetchone()[0],
                "synchronous": connection.execute("PRAGMA synchronous").fetchone()[0],
                "timeout": connection.execute("PRAGMA busy_timeout").fetchone()[0],
            }
            stored_hash = connection.execute(
                "SELECT value FROM store_metadata WHERE key='schema_hash'"
            ).fetchone()[0]
        self.assertEqual(str(pragmas["journal"]).lower(), "wal")
        self.assertEqual(pragmas["foreignKeys"], 1)
        self.assertEqual(pragmas["synchronous"], 2)
        self.assertGreater(pragmas["timeout"], 0)
        self.assertEqual(stored_hash, schema_hash())

    def test_revision_conflict_duplicate_natural_key_and_foreign_key_fail_typed(self) -> None:
        repository = self._initialize()
        repository.apply_vertical_slice(self._slice(None), expected_revision=1)
        with self.assertRaises(StateConflictError) as stale:
            repository.apply_vertical_slice(self._slice(None, prefix="stale"), expected_revision=1)
        self.assertEqual(stale.exception.reason_code, "workspace_revision_conflict")

        duplicate = self._slice(
            None,
            prefix="duplicate",
            target_id="target-duplicate",
            target_natural_key="example.test",
        )
        with self.assertRaises(StateConflictError) as conflict:
            repository.apply_vertical_slice(duplicate, expected_revision=2)
        self.assertEqual(conflict.exception.reason_code, "state_natural_key_conflict")
        self.assertEqual(repository.revision(), 2)

        other = self._initialize("bravo")
        cross_workspace = VerticalSlice(
            scope_snapshot_id="scope-bravo",
            scope={"hosts": ["bravo.test"]},
            targets=(),
            entities=(EntityRecord("entity-bravo", "endpoint", "bravo", target_id="target-one"),),
            relations=(),
            evidence=(),
            artifact=None,
            evidence_artifact_links=(),
            audit=AuditRecord("audit-bravo-2", "workspace.slice", "Invalid cross-workspace slice."),
        )
        with self.assertRaises(StateIntegrityError) as foreign_key:
            other.apply_vertical_slice(cross_workspace, expected_revision=1)
        self.assertEqual(foreign_key.exception.reason_code, "state_foreign_key_violation")
        self.assertEqual(other.revision(), 1)

    def test_concurrent_revision_compare_and_swap_commits_once(self) -> None:
        self._initialize()

        def write(prefix: str) -> int | str:
            repository = self._repository()
            try:
                return repository.apply_vertical_slice(
                    self._slice(
                        None,
                        prefix=prefix,
                        target_id=f"target-{prefix}",
                        target_natural_key=f"{prefix}.test",
                    ),
                    expected_revision=1,
                )
            except StateConflictError as exc:
                return exc.reason_code

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(write, ("left", "right")))
        self.assertIn(2, outcomes)
        self.assertIn("workspace_revision_conflict", outcomes)
        self.assertEqual(self._repository().revision(), 2)

    def test_audit_is_append_only_and_schema_covers_required_groups(self) -> None:
        repository = self._initialize()
        expected_tables = {
            "store_metadata", "schema_migrations", "workspace_revisions", "change_log",
            "workspaces", "scope_snapshots", "targets", "entities", "entity_relations",
            "findings", "review_events", "evidence", "artifacts", "evidence_artifacts",
            "actions", "action_dispatches", "tasks", "task_events", "authority_grants",
            "authority_grant_revisions", "step_ups", "request_states", "budget_windows",
            "reconciliations", "audit_events", "migration_runs", "migration_orphans", "id_mappings",
        }
        with repository.connection_factory.connect() as connection:
            actual = {
                row[0]
                for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            self.assertTrue(expected_tables.issubset(actual))
            request_state_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(request_states)")
            }
            self.assertEqual(
                request_state_columns,
                {
                    "request_state_id",
                    "workspace_id",
                    "action_id",
                    "grant_id",
                    "opaque_state_ref",
                    "state",
                    "expires_at",
                    "created_revision",
                    "updated_revision",
                    "created_at",
                    "updated_at",
                },
            )
            with self.assertRaises(Exception) as append_only:
                connection.execute("UPDATE audit_events SET summary='changed' WHERE event_id='audit-alpha-1'")
        self.assertIn("audit_events_append_only", str(append_only.exception))

    def test_runtime_and_filesystem_readiness_fail_closed(self) -> None:
        unsupported_runtime = select_sqlite_runtime(
            stdlib_sqlite_version="3.50.0",
            apsw_sqlite_version="3.51.2",
        )
        runtime_factory = ConnectionFactory(
            self.root / "runtime" / "state.sqlite3",
            readiness=unsupported_runtime,
        )
        with self.assertRaises(StateReadinessError) as runtime:
            runtime_factory.open()
        self.assertEqual(runtime.exception.reason_code, "sqlite_runtime_too_old")

        filesystem_factory = ConnectionFactory(
            self.root / "network" / "state.sqlite3",
            readiness=probe_state_store_runtime(),
            filesystem_type_resolver=lambda _path: "nfs4",
        )
        with self.assertRaises(StateReadinessError) as filesystem:
            filesystem_factory.open()
        self.assertEqual(filesystem.exception.reason_code, "network_filesystem_unsupported")

        unsupported_factory = ConnectionFactory(
            self.root / "fuse" / "state.sqlite3",
            readiness=probe_state_store_runtime(),
            filesystem_type_resolver=lambda _path: "fuse",
        )
        with self.assertRaises(StateReadinessError) as unsupported:
            unsupported_factory.open()
        self.assertEqual(unsupported.exception.reason_code, "filesystem_unsupported")

    def test_online_backup_uses_binding_api_and_reopens(self) -> None:
        repository = self._initialize()
        backup_path = self.root / "backup" / "state.sqlite3"
        self.assertEqual(online_backup(repository.connection_factory, backup_path), backup_path)
        backup_factory = ConnectionFactory(backup_path)
        with backup_factory.connect() as connection:
            row = connection.execute(
                "SELECT revision FROM workspace_revisions WHERE workspace_id='alpha'"
            ).fetchone()
        self.assertEqual(row, (1,))

    def test_absent_selector_keeps_json_v1_default(self) -> None:
        workspace_root = self.root / "existing-json-workspace"
        workspace_root.mkdir()
        (workspace_root / "workspace.json").write_text('{"workspaceId":"existing-json-workspace"}', encoding="utf-8")
        self.assertEqual(selected_store_version(workspace_root), "json-v1")
        self.assertFalse((workspace_root / "state-v2" / "store-selector.json").exists())
        bundle = repository_bundle("existing-json-workspace", self.root)
        self.assertEqual(bundle.store_version, "json-v1")
        self.assertEqual(bundle.workspace.workspace_id, "existing-json-workspace")

    def test_state_package_is_transport_independent_and_sql_is_local(self) -> None:
        for path in STATE_PACKAGE.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom):
                    self.assertFalse(str(node.module or "").startswith("mcp"), f"{path} imports MCP")
                elif isinstance(node, ast.Import):
                    self.assertFalse(any(alias.name.startswith("mcp") for alias in node.names), f"{path} imports MCP")
        inventory = (ROOT / "docs" / "modernization" / "phase-4-write-topology.md").read_text(encoding="utf-8")
        self.assertIn("remains authoritative unless", inventory)
        self.assertIn("core/background_jobs.py", inventory)
        self.assertIn("policy/repository.py", inventory)


class Phase4AArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.workspace_root = self.root / "alpha"
        self.repository = ContentAddressedArtifactRepository("alpha", self.workspace_root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_symlink_and_traversal_fail_closed(self) -> None:
        source = self.root / "source.txt"
        source.write_text("source", encoding="utf-8")
        link = self.root / "link.txt"
        try:
            link.symlink_to(source)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links are unavailable")
        with self.assertRaises(ArtifactStoreError) as symlink:
            self.repository.ingest_path(link)
        self.assertEqual(symlink.exception.reason_code, "artifact_symlink_forbidden")
        with self.assertRaises(ArtifactStoreError) as traversal:
            self.repository.path_for_digest("../../outside")
        self.assertEqual(traversal.exception.reason_code, "artifact_digest_invalid")

        directory = self.root / "symlink-tree"
        directory.mkdir()
        (directory / "nested-link").symlink_to(source)
        with self.assertRaises(ArtifactStoreError) as nested:
            self.repository.ingest_path(directory)
        self.assertEqual(nested.exception.reason_code, "artifact_symlink_forbidden")

    def test_network_filesystem_is_rejected_before_artifact_write(self) -> None:
        source = self.root / "network.bin"
        source.write_bytes(b"network")
        repository = ContentAddressedArtifactRepository(
            "alpha",
            self.workspace_root,
            filesystem_type_resolver=lambda _path: "nfs",
        )
        with self.assertRaises(ArtifactStoreError) as rejected:
            repository.ingest_path(source)
        self.assertEqual(rejected.exception.reason_code, "network_filesystem_unsupported")
        self.assertFalse(repository.root.exists())

    def test_directory_count_and_byte_limits(self) -> None:
        directory = self.root / "tree"
        directory.mkdir()
        (directory / "one").write_bytes(b"12")
        (directory / "two").write_bytes(b"34")
        count_repository = ContentAddressedArtifactRepository(
            "alpha",
            self.workspace_root,
            limits=ArtifactLimits(file_count=1, total_bytes=100, per_file_bytes=100),
        )
        with self.assertRaises(ArtifactLimitError) as count:
            count_repository.ingest_path(directory)
        self.assertEqual(count.exception.reason_code, "artifact_file_count_limit")
        bytes_repository = ContentAddressedArtifactRepository(
            "alpha",
            self.workspace_root,
            limits=ArtifactLimits(file_count=10, total_bytes=3, per_file_bytes=10),
        )
        with self.assertRaises(ArtifactLimitError) as total:
            bytes_repository.ingest_path(directory)
        self.assertEqual(total.exception.reason_code, "artifact_total_bytes_limit")

    def test_directory_manifest_is_canonical_and_contains_blob_digests(self) -> None:
        directory = self.root / "manifest-tree"
        directory.mkdir()
        (directory / "z.txt").write_text("last", encoding="utf-8")
        nested = directory / "a"
        nested.mkdir()
        (nested / "first.txt").write_text("first", encoding="utf-8")
        record = self.repository.ingest_path(directory, origin="test-directory")
        self.assertEqual(record.media_type, "application/vnd.synapse.directory+json")
        manifest = json.loads(record.path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["type"], "synapse-directory-v1")
        self.assertEqual([item["path"] for item in manifest["entries"]], ["a/first.txt", "z.txt"])
        for entry in manifest["entries"]:
            blob = self.repository.path_for_digest(entry["digest"])
            self.assertTrue(blob.is_file())
            self.assertEqual(blob.stat().st_size, entry["size"])

    def test_collision_mismatch_fails(self) -> None:
        source = self.root / "good.bin"
        source.write_bytes(b"good")
        digest = sha256(b"good").hexdigest()
        target = self.repository.path_for_digest(digest)
        target.parent.mkdir(parents=True)
        target.write_bytes(b"evil")
        with self.assertRaises(ArtifactCollisionError) as collision:
            self.repository.ingest_path(source)
        self.assertEqual(collision.exception.reason_code, "artifact_collision_mismatch")

    def test_concurrent_same_blob_is_idempotent(self) -> None:
        source = self.root / "same.bin"
        source.write_bytes(os.urandom(256 * 1024))

        def ingest(_index: int) -> ArtifactRecord:
            repository = ContentAddressedArtifactRepository("alpha", self.workspace_root)
            return repository.ingest_path(source)

        with ThreadPoolExecutor(max_workers=8) as executor:
            records = list(executor.map(ingest, range(16)))
        self.assertEqual(len({record.digest for record in records}), 1)
        self.assertTrue(all(record.path == records[0].path for record in records))
        self.assertEqual(sha256(records[0].path.read_bytes()).hexdigest(), records[0].digest)

    def test_interrupted_ingest_leaves_only_verified_unreferenced_blob(self) -> None:
        source = self.root / "interrupt.bin"
        source.write_bytes(b"installed-before-metadata")

        def interrupt(stage: str) -> None:
            if stage == "after_install":
                raise RuntimeError("injected interruption")

        repository = ContentAddressedArtifactRepository(
            "alpha",
            self.workspace_root,
            fault_injector=interrupt,
        )
        with self.assertRaises(RuntimeError):
            repository.ingest_path(source)
        digest = sha256(source.read_bytes()).hexdigest()
        installed = repository.path_for_digest(digest)
        self.assertTrue(installed.is_file())
        self.assertEqual(sha256(installed.read_bytes()).hexdigest(), digest)
        incoming = repository.incoming_root
        self.assertEqual(list(incoming.glob("*.part")), [])

    def test_cross_workspace_access_fails(self) -> None:
        source = self.root / "artifact.bin"
        source.write_bytes(b"workspace bound")
        record = self.repository.ingest_path(source)
        with self.assertRaises(ArtifactStoreError) as mismatch:
            self.repository.resolve(record.artifact_id, workspace_id="bravo")
        self.assertEqual(mismatch.exception.reason_code, "artifact_workspace_mismatch")

    def test_metadata_never_commits_before_blob_and_transaction_failure_rolls_back(self) -> None:
        repository = SQLiteWorkspaceRepository("alpha", self.workspace_root)
        repository.initialize(
            WorkspaceRecord("alpha"),
            audit=AuditRecord("audit-alpha-1", "workspace.create", "Created workspace."),
        )
        missing_digest = "0" * 64
        missing = ArtifactRecord(
            f"sha256:{missing_digest}",
            missing_digest,
            1,
            "application/octet-stream",
            "test",
            repository.artifacts.path_for_digest(missing_digest),
        )
        with self.assertRaises(StateIntegrityError) as absent:
            repository.apply_vertical_slice(Phase4AStateStoreTests._slice(missing), expected_revision=1)
        self.assertEqual(absent.exception.reason_code, "artifact_blob_not_installed")

        source = self.root / "installed.bin"
        source.write_bytes(b"installed")
        artifact = repository.artifacts.ingest_path(source)

        def fail(_stage: str) -> None:
            raise RuntimeError("injected database interruption")

        with self.assertRaises(StateStoreError):
            repository.apply_vertical_slice(
                Phase4AStateStoreTests._slice(artifact),
                expected_revision=1,
                fault_injector=fail,
            )
        self.assertEqual(repository.revision(), 1)
        self.assertEqual(repository.snapshot()["artifacts"], [])
        self.assertTrue(artifact.path.is_file())
        repository.verify_integrity()


if __name__ == "__main__":
    unittest.main()
