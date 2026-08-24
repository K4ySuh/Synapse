"""Phase 3R interpreter, readiness, and legacy rollback regressions."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from synapse_mcp.transport.modern.readiness import check_modern_readiness


ROOT = Path(__file__).resolve().parents[3]
RESOLVER = ROOT / "bin" / "resolve-synapse-python"
CONFIG_PRINTER = ROOT / "bin" / "print-mcp-config"
LEGACY_LAUNCHER = ROOT / "MCPS" / "Synapse-MCP" / "bin" / "synapse-mcp"
LEGACY_TOOLS_FIXTURE = (
    ROOT / "MCPS" / "Synapse-MCP" / "tests" / "fixtures" / "legacy_contracts" / "tools_list.json"
)


def _clean_environment() -> dict[str, str]:
    environment = dict(os.environ)
    environment.pop("SYNAPSE_PYTHON", None)
    environment.pop("VIRTUAL_ENV", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


class Phase3RRuntimeReadinessTests(unittest.TestCase):
    def test_interpreter_resolution_priority_and_invalid_explicit_override(self) -> None:
        default = subprocess.run(
            [str(RESOLVER)],
            cwd=ROOT,
            env=_clean_environment(),
            text=True,
            capture_output=True,
            check=True,
        )
        self.assertEqual(Path(default.stdout.strip()).resolve(), (ROOT / ".venv/bin/python").resolve())

        with TemporaryDirectory() as temporary:
            virtual_environment = Path(temporary) / "active"
            (virtual_environment / "bin").mkdir(parents=True)
            (virtual_environment / "bin" / "python").symlink_to(Path(sys.executable).resolve())
            environment = _clean_environment()
            environment["VIRTUAL_ENV"] = str(virtual_environment)
            active = subprocess.run(
                [str(RESOLVER)], cwd=ROOT, env=environment, text=True, capture_output=True, check=True
            )
            self.assertEqual(
                Path(active.stdout.strip()).resolve(),
                (virtual_environment / "bin" / "python").resolve(),
            )

        environment = _clean_environment()
        environment["SYNAPSE_PYTHON"] = "/definitely/missing/synapse-python"
        invalid = subprocess.run(
            [str(RESOLVER)], cwd=ROOT, env=environment, text=True, capture_output=True, check=False
        )
        self.assertEqual(invalid.returncode, 127)
        self.assertIn("SYNAPSE_PYTHON is not executable", invalid.stderr)

    def test_config_printer_uses_the_resolved_runnable_interpreter(self) -> None:
        default = subprocess.run(
            [str(CONFIG_PRINTER), "--modern-compact"],
            cwd=ROOT,
            env=_clean_environment(),
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        self.assertIn(f'command = "{ROOT / ".venv/bin/python"}"', default)
        with TemporaryDirectory() as temporary:
            wrapper = Path(temporary) / "synapse-python"
            wrapper.write_text(f"#!/usr/bin/env sh\nexec '{sys.executable}' \"$@\"\n", encoding="utf-8")
            wrapper.chmod(0o700)
            environment = _clean_environment()
            environment["SYNAPSE_PYTHON"] = str(wrapper)
            rendered = subprocess.run(
                [str(CONFIG_PRINTER), "--modern-compact"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
            self.assertIn(f'command = "{wrapper}"', rendered)
            self.assertNotIn('command = "' + str(ROOT / ".venv/bin/python") + '"', rendered)

            active_environment = Path(temporary) / "active" / "bin"
            active_environment.mkdir(parents=True)
            active_wrapper = active_environment / "python"
            active_wrapper.write_text(
                f"#!/usr/bin/env sh\nexec '{sys.executable}' \"$@\"\n",
                encoding="utf-8",
            )
            active_wrapper.chmod(0o700)
            environment = _clean_environment()
            environment["VIRTUAL_ENV"] = str(active_environment.parent)
            active = subprocess.run(
                [str(CONFIG_PRINTER), "--modern-compact"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=True,
            ).stdout
            self.assertIn(f'command = "{active_wrapper}"', active)

    def test_modern_readiness_requires_private_material_state_and_binding(self) -> None:
        (ROOT / "DATA").mkdir(exist_ok=True)
        with TemporaryDirectory(dir=ROOT / "DATA") as temporary:
            root = Path(temporary)
            missing = check_modern_readiness(
                identity_bindings=root / "missing-bindings.json",
                request_state_keyring=root / "missing-keyring.json",
                state_dir=root / "missing-state",
                principal="operator:test",
            )
            self.assertFalse(missing.ready)
            self.assertTrue(missing.failures)

            bindings = root / "bindings.json"
            keyring = root / "keyring.json"
            state = root / "state"
            state.mkdir()
            bindings.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "principals": {
                            "operator:test": {
                                "defaultWorkspace": "fixture",
                                "default": {
                                    "executionProfile": "observe",
                                    "authoritySessionId": "fixture-session",
                                },
                                "workspaces": {},
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )
            keyring.write_text(
                json.dumps({"version": 1, "keys": ["hex:" + "55" * 32]}),
                encoding="utf-8",
            )
            bindings.chmod(0o600)
            keyring.chmod(0o600)
            ready = check_modern_readiness(
                identity_bindings=bindings,
                request_state_keyring=keyring,
                state_dir=state,
                principal="operator:test",
            )
            self.assertTrue(ready.ready, ready.failures)
            self.assertIn("resolvable principal/workspace authority binding", ready.checks)
            environment = _clean_environment()
            environment.update(
                {
                    "SYNAPSE_PYTHON": sys.executable,
                    "SYNAPSE_MODERN_IDENTITY_BINDINGS": str(bindings),
                    "SYNAPSE_MODERN_REQUEST_STATE_KEYRING": str(keyring),
                    "SYNAPSE_MODERN_STATE_DIR": str(state),
                    "SYNAPSE_MODERN_STDIO_PRINCIPAL": "operator:test",
                }
            )
            setup = subprocess.run(
                [str(ROOT / "bin/check-setup"), "--modern"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
                check=True,
            )
            self.assertIn("LEGACY READY", setup.stdout)
            self.assertIn("MODERN READY", setup.stdout)

    def test_frozen_legacy_launcher_needs_neither_sdk_nor_modern_operator_material(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            shadow = root / "mcp.py"
            shadow.write_text("raise RuntimeError('modern SDK import is forbidden in rollback')\n", encoding="utf-8")
            environment = _clean_environment()
            environment.update(
                {
                    "SYNAPSE_PYTHON": sys.executable,
                    "PYTHONPATH": f"{root}:{ROOT / 'MCPS/Synapse-MCP'}",
                    "SYNAPSE_MODERN_IDENTITY_BINDINGS": str(root / "absent-bindings.json"),
                    "SYNAPSE_MODERN_REQUEST_STATE_KEYRING": str(root / "absent-keyring.json"),
                }
            )
            request = '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n'
            process = subprocess.run(
                [str(LEGACY_LAUNCHER)],
                cwd=ROOT,
                env=environment,
                input=request,
                text=True,
                capture_output=True,
                check=True,
            )
            observed = json.loads(process.stdout)
            expected = json.loads(LEGACY_TOOLS_FIXTURE.read_text(encoding="utf-8"))
            self.assertEqual(observed["result"], expected["result"])
            self.assertEqual(len(observed["result"]["tools"]), 174)


if __name__ == "__main__":
    unittest.main()
