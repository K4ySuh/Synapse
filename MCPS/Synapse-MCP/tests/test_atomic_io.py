import os
import threading
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from synapse_mcp.core import atomic_io
from synapse_mcp.core.errors import McpError


class AtomicIoTests(unittest.TestCase):
    def test_replace_failure_leaves_original_intact(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "state.json"
            path.write_text("original", encoding="utf-8")

            with patch.object(atomic_io.os, "replace", side_effect=OSError("replace failed")):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    atomic_io.atomic_write_text(path, "replacement")

            self.assertEqual(path.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(root.glob(f"{path.name}.*.tmp")), [])

    def test_write_failure_leaves_original_intact(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "state.json"
            path.write_text("original", encoding="utf-8")

            with patch.object(atomic_io.os, "fsync", side_effect=OSError("sync failed")):
                with self.assertRaisesRegex(OSError, "sync failed"):
                    atomic_io.atomic_write_text(path, "replacement")

            self.assertEqual(path.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(root.glob(f"{path.name}.*.tmp")), [])

    def test_new_file_created_with_exact_mode_defeating_umask(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "credentials.json"
            previous_umask = os.umask(0)
            try:
                atomic_io.atomic_write_text(path, "first", mode=0o600)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

                path.chmod(0o644)
                atomic_io.atomic_write_text(path, "second", mode=0o600)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            finally:
                os.umask(previous_umask)

    def test_mode_none_uses_umask_default(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "workspace.json"
            previous_umask = os.umask(0o027)
            try:
                atomic_io.atomic_write_text(path, "state", mode=None, fsync=False)
            finally:
                os.umask(previous_umask)

            self.assertEqual(path.stat().st_mode & 0o777, 0o640)

    def test_fsync_false_skips_fsync(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            calls: list[int] = []
            with patch.object(atomic_io.os, "fsync", side_effect=calls.append):
                atomic_io.atomic_write_text(path, "without-sync", fsync=False)
                self.assertEqual(calls, [])

                atomic_io.atomic_write_text(path, "with-sync", fsync=True)

            self.assertGreaterEqual(len(calls), 1)

    def test_file_lock_is_exclusive_with_timeout(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            failures: list[BaseException] = []
            entered: list[bool] = []

            def contend() -> None:
                try:
                    with atomic_io.file_lock(path, timeout_seconds=0.2):
                        entered.append(True)
                except BaseException as exc:
                    failures.append(exc)

            with atomic_io.file_lock(path):
                thread = threading.Thread(target=contend)
                thread.start()
                thread.join(timeout=2)

            self.assertFalse(thread.is_alive())
            self.assertEqual(entered, [])
            self.assertEqual(len(failures), 1)
            self.assertIsInstance(failures[0], McpError)
            self.assertEqual(failures[0].code, -32000)

    def test_file_lock_is_reentrant_in_one_thread(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            with atomic_io.file_lock(path):
                with atomic_io.file_lock(path):
                    self.assertTrue(path.with_name(f"{path.name}.lock").exists())


if __name__ == "__main__":
    unittest.main()
