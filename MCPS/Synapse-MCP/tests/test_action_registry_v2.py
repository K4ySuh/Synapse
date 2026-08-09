import ast
import unittest
from dataclasses import replace
from pathlib import Path

from synapse_mcp.app.actions import (
    ActionRequest,
    ActionRegistry,
    ExecutionContext,
    ExecutionFailure,
    Idempotency,
    LocalWriteDomain,
    REGISTRY,
    Success,
    TrafficDestination,
)


ACTION_IDS = (
    "jobs.status",
    "workspace.summary",
    "workspace.prepare_target_context",
    "headers_cookies.analyze_workspace",
    "cors.execute_test",
    "crawler.crawl",
)
PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "synapse_mcp"


def request_for(action_id: str, arguments: dict) -> ActionRequest:
    descriptor = REGISTRY.get(action_id)
    return ActionRequest(
        input=descriptor.input_model.model_validate(arguments),
        context=ExecutionContext(arguments.get("workspaceId"), "registry-v2-test", 45.0, None),
    )


class ActionRegistryV2Tests(unittest.TestCase):
    def test_every_migrated_output_schema_has_a_typed_required_core(self) -> None:
        for action_id in ACTION_IDS:
            with self.subTest(action=action_id):
                descriptor = REGISTRY.get(action_id)
                contracts = REGISTRY.contract_schema(action_id)
                schema = contracts["outputSchema"]
                self.assertEqual(contracts["actionId"], action_id)
                self.assertEqual(contracts["inputSchema"]["type"], "object")
                self.assertEqual(schema["type"], "object")
                self.assertGreaterEqual(len(schema.get("properties", {})), 3)
                self.assertGreaterEqual(len(schema.get("required", [])), 3)

    def test_invalid_executor_output_is_rejected_for_every_action_family(self) -> None:
        class InvalidExecutor:
            def __init__(self, descriptor):
                self.input_model = descriptor.input_model
                self.output_model = descriptor.output_model

            def __call__(self, _request):
                return Success(payload={"arbitrary": "untyped"})

        minimum_inputs = {
            "jobs.status": {"jobId": "job-fixture"},
            "workspace.summary": {"workspaceId": "fixture"},
            "workspace.prepare_target_context": {"workspaceId": "fixture", "target": "example.test"},
            "headers_cookies.analyze_workspace": {"workspaceId": "fixture", "target": "example.test"},
            "cors.execute_test": {},
            "crawler.crawl": {"target": "https://example.test"},
        }
        for action_id, arguments in minimum_inputs.items():
            with self.subTest(action=action_id):
                descriptor = REGISTRY.get(action_id)
                registry = ActionRegistry()
                registry.register(replace(descriptor, executor=InvalidExecutor(descriptor)))
                outcome = registry.execute(action_id, request_for(action_id, arguments))
                self.assertIsInstance(outcome, ExecutionFailure)
                self.assertEqual(outcome.reason_code, "invalid_output_contract")

    def test_maximum_and_request_effects_are_multidimensional(self) -> None:
        for action_id in ("jobs.status", "workspace.summary", "workspace.prepare_target_context"):
            descriptor = REGISTRY.get(action_id)
            self.assertEqual(descriptor.effects.replay_safety, Idempotency.PURE_READ)
            self.assertEqual(descriptor.effects.traffic, frozenset())
            self.assertEqual(descriptor.effects.local_writes, frozenset())

        header_ingest = REGISTRY.resolve_effects(
            "headers_cookies.analyze_workspace",
            request_for(
                "headers_cookies.analyze_workspace",
                {"workspaceId": "fixture", "target": "example.test", "ingest": True},
            ),
        )
        header_observe = REGISTRY.resolve_effects(
            "headers_cookies.analyze_workspace",
            request_for(
                "headers_cookies.analyze_workspace",
                {"workspaceId": "fixture", "target": "example.test", "ingest": False},
            ),
        )
        self.assertEqual(
            header_ingest.local_writes,
            frozenset({LocalWriteDomain.WORKSPACE, LocalWriteDomain.EVIDENCE}),
        )
        self.assertEqual(header_observe.local_writes, frozenset({LocalWriteDomain.EVIDENCE}))

        cors_direct = REGISTRY.resolve_effects(
            "cors.execute_test",
            request_for("cors.execute_test", {"url": "https://example.test/api"}),
        )
        cors_disabled = REGISTRY.resolve_effects(
            "cors.execute_test",
            request_for(
                "cors.execute_test",
                {"url": "https://example.test/api", "httpBackend": "disabled", "credentialId": "fixture"},
            ),
        )
        self.assertEqual(cors_direct.traffic, frozenset({TrafficDestination.AUTHORIZED_TARGET}))
        self.assertEqual(
            cors_direct.local_writes,
            frozenset({LocalWriteDomain.WORKSPACE, LocalWriteDomain.EVIDENCE}),
        )
        self.assertFalse(cors_direct.remote_state_change)
        self.assertEqual(cors_disabled.traffic, frozenset())
        self.assertTrue(cors_disabled.credential_use)
        self.assertTrue(cors_disabled.secret_use)

        crawler_background = REGISTRY.resolve_effects(
            "crawler.crawl",
            request_for("crawler.crawl", {"target": "https://example.test", "background": True}),
        )
        crawler_foreground = REGISTRY.resolve_effects(
            "crawler.crawl",
            request_for(
                "crawler.crawl",
                {"target": "https://example.test", "background": False, "disableTraffic": True},
            ),
        )
        self.assertEqual(crawler_background.traffic, frozenset({TrafficDestination.AUTHORIZED_TARGET}))
        self.assertEqual(
            crawler_background.local_writes,
            frozenset(
                {LocalWriteDomain.JOBS, LocalWriteDomain.EVIDENCE, LocalWriteDomain.REPORTS_ARTIFACTS}
            ),
        )
        self.assertEqual(crawler_foreground.traffic, frozenset())
        self.assertEqual(
            crawler_foreground.local_writes,
            frozenset(
                {LocalWriteDomain.WORKSPACE, LocalWriteDomain.EVIDENCE, LocalWriteDomain.REPORTS_ARTIFACTS}
            ),
        )

    def test_registered_executor_objects_are_only_called_inside_registry(self) -> None:
        violations = []
        for path in PACKAGE_ROOT.rglob("*.py"):
            if path.name == "registry.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "executor"
                ):
                    violations.append(f"{path.relative_to(PACKAGE_ROOT)}:{node.lineno}")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
