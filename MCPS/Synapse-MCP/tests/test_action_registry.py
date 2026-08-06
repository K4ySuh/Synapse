from __future__ import annotations

from dataclasses import replace
import json
import unittest

from synapse_mcp.app.actions import (
    ActionDescriptor,
    ActionId,
    ActionOutput,
    ActionRegistry,
    ActionRequest,
    Availability,
    CredentialAccess,
    CredentialPolicy,
    CredentialRequirement,
    DeadlineTier,
    Enforcement,
    ExecutionContext,
    Idempotency,
    IdempotencyPolicy,
    InputContractDocument,
    RiskClass,
    ScopePolicy,
    ScopeRequirement,
    SideEffectClass,
    Success,
    TaskPolicy,
    make_input_model,
)


class StubOutput(ActionOutput):
    pass


def _input_model(name: str = "StubInput"):
    return make_input_model(
        name,
        InputContractDocument(
            source=json.dumps({"type": "object", "properties": {}})
        ),
    )


class StubExecutor:
    def __init__(self, input_model, output_model=StubOutput, events=None) -> None:
        self._input_model = input_model
        self._output_model = output_model
        self.events = events

    @property
    def input_model(self):
        return self._input_model

    @property
    def output_model(self):
        return self._output_model

    def __call__(self, request):
        if self.events is not None:
            self.events.append("executor")
        return Success(payload={"ok": True})


def _descriptor(action_id: str = "stub.read") -> ActionDescriptor:
    input_model = _input_model(action_id.replace(".", "_").title())
    return ActionDescriptor(
        id=ActionId.parse(action_id),
        pack=action_id.split(".", 1)[0],
        title="Stub",
        summary="Stub action",
        input_model=input_model,
        output_model=StubOutput,
        side_effect_class=SideEffectClass.READ_ONLY,
        risk_class=RiskClass.NONE,
        scope_policy=ScopePolicy(ScopeRequirement.NOT_APPLICABLE),
        credential_policy=CredentialPolicy(
            CredentialRequirement.NONE,
            CredentialAccess.NONE,
        ),
        idempotency_policy=IdempotencyPolicy(Idempotency.PURE_READ),
        task_policy=TaskPolicy(
            deadline_tier=DeadlineTier.DEFAULT,
            background_capable=False,
            passive_recordable=False,
        ),
        executor=StubExecutor(input_model),
        availability=Availability(available=True),
    )


class ActionRegistryTests(unittest.TestCase):
    def assert_registration_error(self, descriptor, action_id: str) -> None:
        with self.assertRaisesRegex(ValueError, action_id.replace(".", r"\.")):
            ActionRegistry().register(descriptor)

    def test_duplicate_action_id_fails_registration(self) -> None:
        registry = ActionRegistry()
        descriptor = _descriptor()
        registry.register(descriptor)
        self.assert_registration_error_for_registry(registry, descriptor, "stub.read")

    def assert_registration_error_for_registry(self, registry, descriptor, action_id) -> None:
        with self.assertRaisesRegex(ValueError, action_id.replace(".", r"\.")):
            registry.register(descriptor)

    def test_action_ids_are_well_formed_pack_and_local_name(self) -> None:
        registry = ActionRegistry()
        descriptor = _descriptor("cve.session_key.set")
        registry.register(descriptor)
        self.assertEqual(registry.get("cve.session_key.set"), descriptor)

        mismatched = replace(_descriptor("stub.read"), pack="other")
        self.assert_registration_error(mismatched, "stub.read")

    def test_action_models_must_use_application_contract_bases(self) -> None:
        descriptor = _descriptor()
        self.assert_registration_error(replace(descriptor, input_model=object), "stub.read")
        self.assert_registration_error(replace(descriptor, output_model=object), "stub.read")

    def test_executor_must_be_callable_and_match_models_by_identity(self) -> None:
        descriptor = _descriptor()
        self.assert_registration_error(replace(descriptor, executor=object()), "stub.read")

        other_input = _input_model("OtherInput")
        self.assert_registration_error(
            replace(descriptor, executor=StubExecutor(other_input)),
            "stub.read",
        )
        class OtherOutput(ActionOutput):
            pass

        self.assert_registration_error(
            replace(descriptor, executor=StubExecutor(descriptor.input_model, OtherOutput)),
            "stub.read",
        )

    def test_read_only_and_report_build_actions_cannot_require_scope(self) -> None:
        descriptor = _descriptor()
        required_scope = ScopePolicy(ScopeRequirement.REQUIRED)
        self.assert_registration_error(
            replace(descriptor, scope_policy=required_scope),
            "stub.read",
        )
        self.assert_registration_error(
            replace(
                descriptor,
                side_effect_class=SideEffectClass.REPORT_BUILD,
                scope_policy=required_scope,
            ),
            "stub.read",
        )

    def test_active_probe_policy_combination_is_consistent(self) -> None:
        base = _descriptor("stub.probe")
        valid = replace(
            base,
            side_effect_class=SideEffectClass.ACTIVE_PROBE,
            risk_class=RiskClass.MODERATE,
            scope_policy=ScopePolicy(ScopeRequirement.REQUIRED),
            idempotency_policy=IdempotencyPolicy(Idempotency.NON_IDEMPOTENT),
        )
        registry = ActionRegistry()
        registry.register(valid)
        self.assertEqual(registry.get("stub.probe"), valid)

        for broken in (
            replace(valid, risk_class=RiskClass.LOW),
            replace(valid, scope_policy=ScopePolicy(ScopeRequirement.CHECKED_DOWNSTREAM)),
            replace(valid, idempotency_policy=IdempotencyPolicy(Idempotency.PURE_READ)),
        ):
            self.assert_registration_error(broken, "stub.probe")

    def test_phase_one_forbids_executor_policy_enforcement(self) -> None:
        descriptor = _descriptor()
        self.assert_registration_error(
            replace(
                descriptor,
                scope_policy=ScopePolicy(
                    ScopeRequirement.NOT_APPLICABLE,
                    Enforcement.ENFORCED_BY_EXECUTOR,
                ),
            ),
            "stub.read",
        )
        self.assert_registration_error(
            replace(
                descriptor,
                credential_policy=CredentialPolicy(
                    CredentialRequirement.NONE,
                    CredentialAccess.NONE,
                    Enforcement.ENFORCED_BY_EXECUTOR,
                ),
            ),
            "stub.read",
        )

    def test_execute_routes_through_policy_evaluator_before_executor(self) -> None:
        events: list[str] = []

        class SpyEvaluator:
            def evaluate(self, descriptor, request):
                events.append("policy")
                return True

        descriptor = _descriptor()
        descriptor = replace(
            descriptor,
            executor=StubExecutor(descriptor.input_model, events=events),
        )
        registry = ActionRegistry(policy_evaluator=SpyEvaluator())
        registry.register(descriptor)
        request = ActionRequest(
            input=descriptor.input_model(),
            context=ExecutionContext(None, "correlation", 45.0, None),
        )
        outcome = registry.execute(request)
        self.assertIsInstance(outcome, Success)
        self.assertEqual(events, ["policy", "executor"])

        class BlockingEvaluator:
            def evaluate(self, descriptor, request):
                events.append("blocked")
                raise RuntimeError("policy stopped execution")

        blocked_descriptor = _descriptor("stub.blocked")
        blocked_descriptor = replace(
            blocked_descriptor,
            executor=StubExecutor(blocked_descriptor.input_model, events=events),
        )
        blocked_registry = ActionRegistry(policy_evaluator=BlockingEvaluator())
        blocked_registry.register(blocked_descriptor)
        blocked_request = ActionRequest(
            input=blocked_descriptor.input_model(),
            context=ExecutionContext(None, "correlation", 45.0, None),
        )
        with self.assertRaisesRegex(RuntimeError, "policy stopped"):
            blocked_registry.execute(blocked_request)
        self.assertEqual(events[-1], "blocked")

    def test_registry_pack_count_matches_registered_actions(self) -> None:
        registry = ActionRegistry()
        for action_id in ("alpha.one", "alpha.two", "beta.three"):
            registry.register(_descriptor(action_id))
        # deferred until full migration (ADR-0008)
        self.assertEqual(registry.packs(), frozenset({"alpha", "beta"}))
        self.assertEqual(len(registry.descriptors()), 3)


if __name__ == "__main__":
    unittest.main()
