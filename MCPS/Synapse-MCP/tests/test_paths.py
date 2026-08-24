import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


class PathResolutionTests(unittest.TestCase):
    def _synapse_python_for_env(self, env: dict[str, str]) -> Path:
        code = """
import json
from synapse_mcp.core.paths import synapse_python
print(json.dumps({"python": synapse_python()}))
"""
        output = subprocess.check_output([sys.executable, "-c", code], env=env, text=True)
        return Path(json.loads(output)["python"])

    def test_synapse_python_interpreter_precedence(self) -> None:
        with TemporaryDirectory() as configured_tmp, TemporaryDirectory() as repo_tmp, TemporaryDirectory() as active_tmp:
            configured_root = Path(configured_tmp)
            configured = configured_root / "runtime" / "python"
            configured_env = os.environ.copy()
            configured_env["SYNAPSE_ROOT"] = str(configured_root)
            configured_env["SYNAPSE_DATA_DIR"] = "DATA"
            configured_env["SYNAPSE_DUMP_DIR"] = "workspaces"
            configured_env["SYNAPSE_PYTHON"] = str(configured)

            repo_root = Path(repo_tmp)
            repo_python = repo_root / ".venv" / "bin" / "python"
            repo_python.parent.mkdir(parents=True)
            repo_python.write_text("", encoding="utf-8")
            repo_env = os.environ.copy()
            repo_env["SYNAPSE_ROOT"] = str(repo_root)
            repo_env["SYNAPSE_DATA_DIR"] = "DATA"
            repo_env["SYNAPSE_DUMP_DIR"] = "workspaces"
            repo_env.pop("SYNAPSE_PYTHON", None)
            repo_env.pop("VIRTUAL_ENV", None)

            active_root = Path(active_tmp)
            active_repo_python = active_root / ".venv" / "bin" / "python"
            active_python = active_root / "active" / "bin" / "python"
            active_repo_python.parent.mkdir(parents=True)
            active_python.parent.mkdir(parents=True)
            active_repo_python.write_text("", encoding="utf-8")
            active_python.write_text("", encoding="utf-8")
            active_env = os.environ.copy()
            active_env["SYNAPSE_ROOT"] = str(active_root)
            active_env["SYNAPSE_DATA_DIR"] = "DATA"
            active_env["SYNAPSE_DUMP_DIR"] = "workspaces"
            active_env["VIRTUAL_ENV"] = str(active_python.parent.parent)
            active_env.pop("SYNAPSE_PYTHON", None)

            cases = [
                ("configured", configured_env, configured),
                ("repo_venv", repo_env, repo_python),
                ("active_virtual_env", active_env, active_python),
            ]
            for name, env, expected in cases:
                with self.subTest(name=name):
                    self.assertEqual(self._synapse_python_for_env(env), expected)


    def test_synapse_python_does_not_dereference_symlinked_interpreter(self) -> None:
        # A venv's bin/python is a symlink to the base interpreter. Resolving the
        # symlink would drop venv isolation, so background workers would run under
        # the base interpreter and lose venv-only deps (Playwright, Selenium).
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "base" / "python3"
            target.parent.mkdir(parents=True)
            target.write_text("", encoding="utf-8")
            venv_python = root / ".venv" / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            venv_python.symlink_to(target)

            env = os.environ.copy()
            env["SYNAPSE_ROOT"] = str(root)
            env["SYNAPSE_DATA_DIR"] = "DATA"
            env["SYNAPSE_DUMP_DIR"] = "workspaces"
            env["SYNAPSE_PYTHON"] = str(venv_python)

            result = self._synapse_python_for_env(env)
            self.assertEqual(result, venv_python)
            # The buggy version returned the dereferenced base interpreter.
            self.assertNotEqual(str(result), os.path.realpath(venv_python))

    def test_relative_data_paths_resolve_from_synapse_root_not_cwd(self) -> None:
        with TemporaryDirectory() as root_tmp, TemporaryDirectory() as cwd_tmp:
            root = Path(root_tmp)
            cwd = Path(cwd_tmp)
            env = os.environ.copy()
            env["SYNAPSE_ROOT"] = str(root)
            env["SYNAPSE_DATA_DIR"] = "DATA"
            env["SYNAPSE_DUMP_DIR"] = "workspaces"

            code = """
import json
from synapse_mcp.core.paths import DATA_DIR, DUMP_DIR
from synapse_mcp.core import workspace

workspace.create_workspace("engagement", organization="Client")
print(json.dumps({
    "dataDir": str(DATA_DIR),
    "dumpDir": str(DUMP_DIR),
    "cwdDataExists": __import__("pathlib").Path.cwd().joinpath("DATA").exists(),
    "workspaceExists": DATA_DIR.joinpath("workspaces", "engagement", "state-v2", "state.sqlite3").exists(),
    "selectorExists": DATA_DIR.joinpath("workspaces", "engagement", "state-v2", "store-selector.json").exists(),
}))
"""
            output = subprocess.check_output([sys.executable, "-c", code], cwd=cwd, env=env, text=True)
            result = json.loads(output)

            self.assertEqual(Path(result["dataDir"]), root / "DATA")
            self.assertEqual(Path(result["dumpDir"]), root / "DATA" / "workspaces")
            self.assertTrue(result["workspaceExists"])
            self.assertTrue(result["selectorExists"])
            self.assertFalse(result["cwdDataExists"])

    def test_data_dir_outside_synapse_root_is_rejected(self) -> None:
        with TemporaryDirectory() as root_tmp, TemporaryDirectory() as data_tmp:
            env = os.environ.copy()
            env["SYNAPSE_ROOT"] = root_tmp
            env["SYNAPSE_DATA_DIR"] = data_tmp

            proc = subprocess.run(
                [sys.executable, "-c", "from synapse_mcp.core.paths import DATA_DIR"],
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("SYNAPSE_DATA_DIR must resolve under SYNAPSE_ROOT", proc.stderr)


if __name__ == "__main__":
    unittest.main()
