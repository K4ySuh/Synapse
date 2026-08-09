import asyncio
import json
import os
import socket
import subprocess
import sys
import unittest
from importlib.metadata import version
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from helpers import isolated_state
from mcp import Client, StdioServerParameters, stdio_client
from mcp.types import InputRequiredResult

from synapse_mcp.app.actions import REGISTRY
from synapse_mcp.core import workspace
from synapse_mcp.core.errors import McpError
from synapse_mcp.transport.modern_spike import (
    ACTIVE_ACTION_ID,
    MODERN_ACTION_IDS,
    MODERN_PROTOCOL_REVISION,
    MODERN_SDK_VERSION,
    MODERN_SPIKE_ENV,
    build_server,
)


class ModernSpikeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self._feature = patch.dict(os.environ, {MODERN_SPIKE_ENV: "1"})
        self._feature.start()

    def tearDown(self) -> None:
        self._feature.stop()

    async def test_exact_action_surface_schemas_annotations_and_negotiation(self) -> None:
        server = build_server()
        async with Client(server) as client:
            discovered = await client.list_tools()
            self.assertEqual(client.protocol_version, MODERN_PROTOCOL_REVISION)
            self.assertEqual([tool.name for tool in discovered.tools], list(MODERN_ACTION_IDS))
            schema_bytes = 0
            for tool in discovered.tools:
                with self.subTest(tool=tool.name):
                    self.assertEqual(tool.input_schema["type"], "object")
                    self.assertNotIn("confirm", tool.input_schema.get("properties", {}))
                    self.assertEqual(tool.output_schema["type"], "object")
                    self.assertGreater(len(tool.output_schema.get("properties", {})), 2)
                    self.assertIsNotNone(tool.annotations)
                    schema_bytes += len(
                        json.dumps(
                            {"input": tool.input_schema, "output": tool.output_schema},
                            separators=(",", ":"),
                        ).encode("utf-8")
                    )
            self.assertGreater(schema_bytes, 3_000)
            self.assertLess(schema_bytes, 30_000)

    async def test_structured_success_typed_error_and_active_input_required_without_dispatch(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("modern", hosts=["app.example.test"])
                async with Client(build_server(), raise_exceptions=False) as client:
                    result = await client.call_tool("workspace.summary", {"workspaceId": "modern"})
                    self.assertFalse(result.is_error)
                    self.assertIsInstance(result.structured_content, dict)
                    self.assertEqual(result.structured_content["targetCount"], 1)
                    self.assertEqual(result.content[0].text, "Workspace summary: completed")
                    REGISTRY.get("workspace.summary").output_model.model_validate(result.structured_content)

                    with patch.object(
                        workspace,
                        "workspace_summary",
                        side_effect=McpError(-32000, "deterministic fixture failure"),
                    ):
                        error = await client.call_tool("workspace.summary", {"workspaceId": "modern"})
                    self.assertTrue(error.is_error)
                    self.assertIsNone(error.structured_content)
                    self.assertIn("execution_failure", error.content[0].text)

                    with patch.object(REGISTRY, "execute", side_effect=AssertionError("dispatch bypass")):
                        required = await client.session.call_tool(
                            ACTIVE_ACTION_ID,
                            {"confirm": True},
                            allow_input_required=True,
                        )
                    self.assertIsInstance(required, InputRequiredResult)
                    self.assertEqual(required.result_type, "input_required")
                    self.assertEqual(required.meta["synapse/status"], "approval_required")
                    self.assertEqual(required.meta["synapse/dispatch"], "not_started")

    async def test_stdio_transport(self) -> None:
        environment = dict(os.environ)
        environment[MODERN_SPIKE_ENV] = "1"
        parameters = StdioServerParameters(
            command=sys.executable,
            args=["-m", "synapse_mcp.transport.modern_spike", "--transport", "stdio"],
            env=environment,
        )
        async with Client(stdio_client(parameters)) as client:
            discovered = await client.list_tools()
            self.assertEqual(client.protocol_version, MODERN_PROTOCOL_REVISION)
            self.assertEqual([tool.name for tool in discovered.tools], list(MODERN_ACTION_IDS))

    async def test_streamable_http_loopback_transport(self) -> None:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        environment = dict(os.environ)
        environment[MODERN_SPIKE_ENV] = "1"
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "synapse_mcp.transport.modern_spike",
                "--transport",
                "streamable-http",
                "--port",
                str(port),
            ],
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            last_error = None
            for _ in range(100):
                try:
                    async with Client(f"http://127.0.0.1:{port}/mcp") as client:
                        discovered = await client.list_tools()
                        self.assertEqual(client.protocol_version, MODERN_PROTOCOL_REVISION)
                        self.assertEqual([tool.name for tool in discovered.tools], list(MODERN_ACTION_IDS))
                        return
                except Exception as exc:
                    last_error = exc
                    await asyncio.sleep(0.02)
            self.fail(f"Streamable HTTP spike did not become ready: {last_error}")
        finally:
            process.terminate()
            process.wait(timeout=10)


class ModernSpikeFeatureFlagTests(unittest.TestCase):
    def test_feature_flag_and_exact_sdk_pin(self) -> None:
        self.assertEqual(version("mcp"), MODERN_SDK_VERSION)
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, MODERN_SPIKE_ENV):
                build_server()


if __name__ == "__main__":
    unittest.main()
