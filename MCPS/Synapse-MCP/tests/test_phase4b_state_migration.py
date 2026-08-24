"""Task 4B deterministic migration, bundle, cutover, and rollback acceptance."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
import unittest

from synapse_mcp.state import (
    MIGRATION_STAGES,
    SQLiteWorkspaceRepository,
    StateBundleService,
    StateConflictError,
    StateIntegrityError,
    StateMigrationService,
    StateSelectionError,
    canonical_digest,
)
from synapse_mcp.state.connections import immediate_transaction
from synapse_mcp.state.migrations import apply_migrations
from synapse_mcp.state.cli import run as run_state_cli
from synapse_mcp.core import atomic_io, workspace


ROOT = Path(__file__).resolve().parents[3]
FIXTURES = ROOT / "MCPS" / "Synapse-MCP" / "tests" / "fixtures" / "state_v1"
STATE_PACKAGE = ROOT / "MCPS" / "Synapse-MCP" / "synapse_mcp" / "state"


class Phase4BStateMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.data_root = self.root / "DATA"
        self.workspace_root = self.data_root / "workspaces" / "beta-complete"
        self.workspace_root.parent.mkdir(parents=True)
        shutil.copytree(FIXTURES / "complete", self.workspace_root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _migration(self, data_root: Path | None = None) -> StateMigrationService:
        return StateMigrationService(data_root or self.data_root)

    def _bundles(self, data_root: Path | None = None) -> StateBundleService:
        return StateBundleService(data_root or self.data_root)

    @staticmethod
    def _tree_bytes(root: Path) -> dict[str, str]:
        return {
            path.relative_to(root).as_posix(): sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*"))
            if path.is_file()
        }

    def _migrate(self) -> dict:
        return self._migration().migrate("beta-complete", apply=True)

    def _bundle_copy(self, source: Path, name: str) -> Path:
        destination = self.root / name
        shutil.copytree(source, destination)
        return destination

    @staticmethod
    def _rewrite_bundle(path: Path, payload: dict) -> None:
        unsigned = dict(payload)
        unsigned.pop("contentDigest", None)
        payload["contentDigest"] = canonical_digest(unsigned)
        (path / "bundle.json").write_text(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_every_checked_beta_fixture_migrates_twice_without_duplicates(self) -> None:
        fixture_names = sorted(path.name for path in FIXTURES.iterdir() if path.is_dir())
        self.assertEqual(fixture_names, ["complete"])
        first = self._migrate()
        first_digest = first["migrationRun"]["verification"]["verificationDigest"]
        first_counts = first["migrationRun"]["verification"]["counts"]
        second = self._migrate()
        self.assertEqual(second["migrationRun"]["verification"]["verificationDigest"], first_digest)
        self.assertEqual(second["migrationRun"]["verification"]["counts"], first_counts)
        self.assertTrue(second["migrationRun"]["verification"]["success"])
        self.assertEqual(first_counts["entity_relations"], {"actual": 1, "expected": 1})
        self.assertEqual(first_counts["review_events"], {"actual": 1, "expected": 1})
        export_one = self._bundles().export("beta-complete", self.root / "same-one")
        export_two = self._bundles().export("beta-complete", self.root / "same-two")
        self.assertEqual(export_one["contentDigest"], export_two["contentDigest"])
        manifest = json.loads((self.root / "same-one" / "bundle.json").read_text(encoding="utf-8"))
        persisted_stages = json.loads(
            manifest["tables"]["migration_runs"][0]["counts_json"]
        )["stages"]
        self.assertEqual(
            persisted_stages,
            {stage: "completed" for stage in MIGRATION_STAGES},
        )

    def test_termination_after_every_stage_resumes_to_identical_state(self) -> None:
        self._migrate()
        baseline = self._bundles().export("beta-complete", self.root / "baseline")["contentDigest"]
        for stage in MIGRATION_STAGES:
            with self.subTest(stage=stage):
                data_root = self.root / f"interrupt-{stage}"
                workspace = data_root / "workspaces" / "beta-complete"
                workspace.parent.mkdir(parents=True)
                shutil.copytree(FIXTURES / "complete", workspace)
                interrupted = False

                def terminate(completed: str) -> None:
                    nonlocal interrupted
                    if completed == stage and not interrupted:
                        interrupted = True
                        raise RuntimeError(f"termination:{stage}")

                service = self._migration(data_root)
                with self.assertRaisesRegex(RuntimeError, f"termination:{stage}"):
                    service.migrate("beta-complete", apply=True, fault_injector=terminate)
                resumed = service.migrate("beta-complete", apply=True)
                self.assertTrue(resumed["migrationRun"]["verification"]["success"])
                digest = self._bundles(data_root).export(
                    "beta-complete", self.root / f"resumed-{stage}"
                )["contentDigest"]
                self.assertEqual(digest, baseline)

    def test_inventory_and_dry_run_do_not_change_workspace_bytes(self) -> None:
        before = self._tree_bytes(self.workspace_root)
        inventory = self._migration().inventory("beta-complete")
        dry_run = self._migration().migrate("beta-complete", apply=False)
        self.assertEqual(self._tree_bytes(self.workspace_root), before)
        self.assertEqual(dry_run["inventory"]["sourceDigest"], inventory["sourceDigest"])
        self.assertFalse((self.workspace_root / "state-v2").exists())
        self.assertFalse(dry_run["wouldActivate"])

    def test_snapshot_is_exact_and_activation_is_blocked_on_failed_verification(self) -> None:
        contaminated = self.workspace_root / "foreign.json"
        contaminated.write_text('{"workspaceId":"another-workspace"}\n', encoding="utf-8")
        with self.assertRaises(StateIntegrityError) as failure:
            self._migrate()
        self.assertEqual(failure.exception.reason_code, "migration_verification_failed")
        run = self._migration().status("beta-complete")["migrationRun"]
        self.assertFalse(run["verification"]["success"])
        self.assertTrue(any(item["blocking"] for item in run["orphans"]))
        with self.assertRaises(StateSelectionError) as activation:
            self._migration().activate("beta-complete")
        self.assertEqual(activation.exception.reason_code, "migration_not_verified")
        self.assertFalse((self.workspace_root / "state-v2" / "store-selector.json").exists())
        snapshot = self.workspace_root / "state-v2" / "migration" / "pre-cutover" / "files" / "workspace.json"
        self.assertEqual(snapshot.read_bytes(), (self.workspace_root / "workspace.json").read_bytes())

    def test_rejected_secret_body_is_an_orphan_without_dangling_database_reference(self) -> None:
        secret_body = self.workspace_root / "targets" / "example.test" / "evidence" / "session.txt"
        secret_body.write_text("Authorization: Bearer fixture-session-material\n", encoding="utf-8")
        rejected_digest = sha256(secret_body.read_bytes()).hexdigest()
        with self.assertRaises(StateIntegrityError) as failure:
            self._migrate()
        self.assertEqual(failure.exception.reason_code, "migration_verification_failed")
        run = self._migration().status("beta-complete")["migrationRun"]
        self.assertIn(f"sha256:{rejected_digest}", run["rejectedArtifactIds"])
        self.assertTrue(
            any(item["reasonCode"] == "artifact_secret_material" for item in run["orphans"])
        )
        repository = SQLiteWorkspaceRepository("beta-complete", self.workspace_root)
        with repository.connection_factory.connect() as connection:
            artifact = connection.execute(
                "SELECT 1 FROM artifacts WHERE digest=?", (rejected_digest,)
            ).fetchone()
            dangling = connection.execute(
                "SELECT COUNT(*) FROM evidence_artifacts ea LEFT JOIN artifacts a "
                "ON a.workspace_id=ea.workspace_id AND a.artifact_id=ea.artifact_id "
                "WHERE a.artifact_id IS NULL"
            ).fetchone()[0]
        self.assertIsNone(artifact)
        self.assertEqual(dangling, 0)

    def test_activation_and_pre_write_rollback_restore_absent_json_selector(self) -> None:
        self._migrate()
        activated = self._migration().activate("beta-complete")
        self.assertEqual(activated["selectedStore"], "sqlite-v2")
        self.assertTrue(activated["rollbackAllowed"])
        workspace_metadata = self.workspace_root / "workspace.json"
        original = workspace_metadata.read_text(encoding="utf-8")
        with self.assertRaises(StateSelectionError) as shared_writer:
            atomic_io.atomic_write_text(workspace_metadata, original)
        self.assertEqual(shared_writer.exception.reason_code, "json_v1_write_after_activation")
        original_workspaces_root = workspace.WORKSPACES_DIR
        workspace.WORKSPACES_DIR = self.data_root / "workspaces"
        try:
            with self.assertRaises(StateSelectionError) as direct_writer:
                workspace.store_raw_evidence(
                    "beta-complete",
                    "example.test",
                    "fixture",
                    "passive",
                    "txt",
                    "must not be written",
                )
        finally:
            workspace.WORKSPACES_DIR = original_workspaces_root
        self.assertEqual(direct_writer.exception.reason_code, "json_v1_write_after_activation")
        self.assertEqual(workspace_metadata.read_text(encoding="utf-8"), original)
        rolled_back = self._migration().rollback("beta-complete")
        self.assertEqual(rolled_back["selectedStore"], "json-v1")
        self.assertFalse((self.workspace_root / "state-v2" / "store-selector.json").exists())
        atomic_io.atomic_write_text(workspace_metadata, original)

    def test_rollback_restores_existing_json_selector_byte_for_byte(self) -> None:
        selector = self.workspace_root / "state-v2" / "store-selector.json"
        selector.parent.mkdir()
        original = b'{\n  "version": 1,\n  "authoritativeStore": "json-v1"\n}\n'
        selector.write_bytes(original)
        self._migrate()
        self._migration().activate("beta-complete")
        self.assertNotEqual(selector.read_bytes(), original)
        rolled_back = self._migration().rollback("beta-complete")
        self.assertEqual(rolled_back["selectedStore"], "json-v1")
        self.assertEqual(selector.read_bytes(), original)

    def test_post_first_v2_write_rollback_refuses_data_loss(self) -> None:
        self._migrate()
        self._migration().activate("beta-complete")
        repository = SQLiteWorkspaceRepository("beta-complete", self.workspace_root)
        with repository.connection_factory.connect() as connection:
            apply_migrations(connection)
            with immediate_transaction(connection):
                connection.execute(
                    "UPDATE workspace_revisions SET revision=2 WHERE workspace_id='beta-complete'"
                )
        with self.assertRaises(StateConflictError) as refusal:
            self._migration().rollback("beta-complete")
        self.assertEqual(refusal.exception.reason_code, "rollback_v2_data_loss_risk")
        self.assertEqual(self._migration().status("beta-complete")["selectedStore"], "sqlite-v2")

    def test_verification_detects_lifecycle_content_drift_with_stable_identity(self) -> None:
        self._migrate()
        repository = SQLiteWorkspaceRepository("beta-complete", self.workspace_root)
        with repository.connection_factory.connect() as connection:
            apply_migrations(connection)
            with immediate_transaction(connection):
                connection.execute(
                    "UPDATE actions SET state='tampered' WHERE action_id='action-passive-header'"
                )
        report = self._migration().verify("beta-complete")
        self.assertFalse(report["success"])
        self.assertTrue(
            any(
                failure["reasonCode"] == "content_mismatch"
                and failure.get("table") == "actions"
                for failure in report["failures"]
            )
        )

    def test_export_import_export_is_semantically_and_hash_equivalent(self) -> None:
        self._migrate()
        first = self._bundles().export("beta-complete", self.root / "bundle-source")
        import_root = self.root / "IMPORTED"
        imported = self._bundles(import_root).import_bundle(self.root / "bundle-source")
        second = self._bundles(import_root).export("beta-complete", self.root / "bundle-imported")
        self.assertEqual(imported["contentDigest"], first["contentDigest"])
        self.assertEqual(second["contentDigest"], first["contentDigest"])
        self.assertEqual(
            json.loads((self.root / "bundle-source" / "bundle.json").read_text(encoding="utf-8")),
            json.loads((self.root / "bundle-imported" / "bundle.json").read_text(encoding="utf-8")),
        )

    def test_import_rejects_format_traversal_hash_duplicate_and_cross_workspace(self) -> None:
        self._migrate()
        bundle = self.root / "valid-bundle"
        self._bundles().export("beta-complete", bundle)

        unsupported = self._bundle_copy(bundle, "unsupported")
        payload = json.loads((unsupported / "bundle.json").read_text(encoding="utf-8"))
        payload["formatVersion"] = 99
        self._rewrite_bundle(unsupported, payload)
        with self.assertRaises(StateIntegrityError) as error:
            self._bundles(self.root / "unsupported-data").import_bundle(unsupported)
        self.assertEqual(error.exception.reason_code, "bundle_format_unsupported")

        duplicate = self._bundle_copy(bundle, "duplicate")
        payload = json.loads((duplicate / "bundle.json").read_text(encoding="utf-8"))
        payload["tables"]["targets"].append(dict(payload["tables"]["targets"][0]))
        self._rewrite_bundle(duplicate, payload)
        with self.assertRaises(StateIntegrityError) as error:
            self._bundles(self.root / "duplicate-data").import_bundle(duplicate)
        self.assertEqual(error.exception.reason_code, "bundle_duplicate_identity")

        cross = self._bundle_copy(bundle, "cross")
        payload = json.loads((cross / "bundle.json").read_text(encoding="utf-8"))
        payload["tables"]["targets"][0]["workspace_id"] = "foreign"
        self._rewrite_bundle(cross, payload)
        with self.assertRaises(StateIntegrityError) as error:
            self._bundles(self.root / "cross-data").import_bundle(cross)
        self.assertEqual(error.exception.reason_code, "bundle_cross_workspace")

        traversal = self._bundle_copy(bundle, "traversal")
        payload = json.loads((traversal / "bundle.json").read_text(encoding="utf-8"))
        payload["artifacts"][0]["path"] = "../escape"
        self._rewrite_bundle(traversal, payload)
        with self.assertRaises(StateIntegrityError) as error:
            self._bundles(self.root / "traversal-data").import_bundle(traversal)
        self.assertEqual(error.exception.reason_code, "bundle_artifact_path_invalid")

        tampered = self._bundle_copy(bundle, "tampered")
        artifact = next((tampered / "artifacts").rglob("[0-9a-f]" * 64))
        artifact.write_bytes(b"tampered")
        with self.assertRaises(StateIntegrityError) as error:
            self._bundles(self.root / "tampered-data").import_bundle(tampered)
        self.assertEqual(error.exception.reason_code, "bundle_artifact_hash_mismatch")

    def test_credentials_bearers_cookies_keys_and_raw_handles_never_enter_v2_or_export(self) -> None:
        credential_secret = "credential-secret-should-never-migrate"
        bearer_secret = "bearer-secret-should-never-migrate"
        cookie_secret = "cookie-secret-should-never-migrate"
        request_key = "request-state-key-should-never-migrate"
        opaque_request = "opaque-request-handle-should-never-migrate"
        opaque_step_up = "opaque-step-up-handle-should-never-migrate"
        credential_path = self.workspace_root / "credentials" / "credential.json"
        credential_path.parent.mkdir()
        credential_path.write_text(
            json.dumps({"credentialId": "credential-reference", "secret": credential_secret}),
            encoding="utf-8",
        )
        authority_path = self.workspace_root / "authority" / "state.json"
        authority = json.loads(authority_path.read_text(encoding="utf-8"))
        authority["requestStates"][opaque_request] = {
            "requestStateId": opaque_request,
            "workspaceId": "beta-complete",
            "actionId": "action-passive-header",
            "grantId": "grant-fixture",
            "status": "pending",
            "createdAt": "2026-01-02T03:20:00Z",
            "expiresAt": "2026-01-02T04:20:00Z",
            "requestStateKey": request_key,
            "authorization": f"Bearer {bearer_secret}",
            "cookie": cookie_secret,
        }
        authority["stepUps"][opaque_step_up] = {
            "grantId": "grant-fixture",
            "grantRevision": 1,
            "authorizationFingerprint": "safe-fingerprint",
            "approvedBy": "operator-fixture",
            "createdAt": "2026-01-02T03:20:00Z",
            "expiresAt": "2026-01-02T04:20:00Z",
        }
        authority["decisions"].append(
            {
                "auditId": "audit-secret-regression",
                "at": "2026-01-02T03:20:00Z",
                "kind": "approval_required",
                "reason": "fixture",
                "requestStateId": opaque_request,
                "stepUpId": opaque_step_up,
                "accessToken": bearer_secret,
            }
        )
        authority_path.write_text(json.dumps(authority, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        result = self._migrate()
        self.assertEqual(result["migrationRun"]["verification"]["counts"]["request_states"]["actual"], 1)
        self.assertEqual(result["migrationRun"]["verification"]["counts"]["step_ups"]["actual"], 1)
        bundle = self.root / "secret-scan-bundle"
        self._bundles().export("beta-complete", bundle)
        database_bytes = b"".join(
            path.read_bytes()
            for path in (self.workspace_root / "state-v2").glob("state.sqlite3*")
            if path.is_file()
        )
        export_bytes = b"".join(path.read_bytes() for path in bundle.rglob("*") if path.is_file())
        for forbidden in (
            credential_secret,
            bearer_secret,
            cookie_secret,
            request_key,
            opaque_request,
            opaque_step_up,
        ):
            encoded = forbidden.encode("utf-8")
            self.assertNotIn(encoded, database_bytes)
            self.assertNotIn(encoded, export_bytes)
        manifest = json.loads((bundle / "bundle.json").read_text(encoding="utf-8"))
        self.assertTrue(
            all(
                str(row["source_id"]).startswith("sha256:")
                for row in manifest["tables"]["id_mappings"]
                if row["source_kind"] in {"request_state", "step_up"}
            )
        )

    def test_state_modules_remain_transport_independent_and_cli_surface_is_complete(self) -> None:
        forbidden = ("import mcp", "from mcp", "transport.", "McpError")
        for path in STATE_PACKAGE.rglob("*.py"):
            source = path.read_text(encoding="utf-8")
            for marker in forbidden:
                self.assertNotIn(marker, source, f"{marker} leaked into {path.name}")
        cli_source = (STATE_PACKAGE / "cli.py").read_text(encoding="utf-8")
        for command in ("inventory", "migrate", "verify", "activate", "rollback", "status", "export", "import"):
            self.assertIn(f'"{command}"', cli_source)

    def test_operator_cli_executes_every_versioned_command(self) -> None:
        prefix = ["--data-root", str(self.data_root)]
        inventory = run_state_cli([*prefix, "inventory", "beta-complete"])
        self.assertEqual(inventory["workspaceId"], "beta-complete")
        dry_run = run_state_cli(
            [*prefix, "migrate", "beta-complete", "--dry-run"]
        )
        self.assertTrue(dry_run["dryRun"])
        applied = run_state_cli([*prefix, "migrate", "beta-complete", "--apply"])
        self.assertTrue(applied["migrationRun"]["verification"]["success"])
        verified = run_state_cli([*prefix, "verify", "beta-complete"])
        self.assertTrue(verified["success"])
        self.assertEqual(
            run_state_cli([*prefix, "status", "beta-complete"])["selectedStore"],
            "json-v1",
        )
        self.assertEqual(
            run_state_cli([*prefix, "activate", "beta-complete"])["selectedStore"],
            "sqlite-v2",
        )
        self.assertEqual(
            run_state_cli([*prefix, "rollback", "beta-complete"])["selectedStore"],
            "json-v1",
        )
        bundle = self.root / "cli-bundle"
        exported = run_state_cli(
            [*prefix, "export", "beta-complete", "--output", str(bundle)]
        )
        imported_root = self.root / "CLI-IMPORTED"
        imported = run_state_cli(
            [
                "--data-root",
                str(imported_root),
                "import",
                str(bundle),
            ]
        )
        self.assertEqual(imported["contentDigest"], exported["contentDigest"])


if __name__ == "__main__":
    unittest.main()
