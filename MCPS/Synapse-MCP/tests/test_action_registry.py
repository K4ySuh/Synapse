from __future__ import annotations

from dataclasses import replace
import json
import unittest

from synapse_mcp.app.actions import (
    ActionDescriptor,
    ActionEffects,
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
    LocalWriteDomain,
    RiskClass,
    ScopePolicy,
    ScopeRequirement,
    Success,
    TaskPolicy,
    TrafficDestination,
    UnavailableCapability,
    make_input_model,
)


class StubOutput(ActionOutput):
    ok: bool


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
        effects=ActionEffects(replay_safety=Idempotency.PURE_READ),
        effect_resolver=None,
        risk_class=RiskClass.NONE,
        scope_policy=ScopePolicy(ScopeRequirement.NOT_APPLICABLE),
        credential_policy=CredentialPolicy(
            CredentialRequirement.NONE,
            CredentialAccess.NONE,
        ),
        task_policy=TaskPolicy(
            deadline_tier=DeadlineTier.DEFAULT,
            background_capable=False,
            passive_recordable=False,
        ),
        executor=StubExecutor(input_model),
        availability=Availability(available=True),
        legacy_aliases=(action_id,),
        legacy_serializer="transport",
        implementation_ref="tests.StubExecutor",
        idempotency_policy=IdempotencyPolicy(Idempotency.PURE_READ),
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

    def test_missing_or_duplicate_legacy_alias_fails_registration(self) -> None:
        self.assert_registration_error(replace(_descriptor(), legacy_aliases=()), "stub.read")
        registry = ActionRegistry()
        registry.register(_descriptor("stub.read"))
        self.assert_registration_error_for_registry(
            registry,
            replace(_descriptor("other.read"), legacy_aliases=("stub.read",)),
            "other.read",
        )

    def test_missing_implementation_identity_fails_registration(self) -> None:
        self.assert_registration_error(replace(_descriptor(), implementation_ref=""), "stub.read")

    def test_invalid_legacy_serializer_fails_registration(self) -> None:
        self.assert_registration_error(replace(_descriptor(), legacy_serializer=""), "stub.read")

    def test_approval_declaration_must_match_frozen_confirm_schema(self) -> None:
        self.assert_registration_error(replace(_descriptor(), approval_required=True), "stub.read")

    def test_shared_input_model_routes_unambiguously_by_action_id(self) -> None:
        registry = ActionRegistry()
        first = _descriptor("stub.read")
        second = _descriptor("other.read")
        second = replace(
            second,
            input_model=first.input_model,
            executor=StubExecutor(first.input_model, first.output_model),
        )
        registry.register(first)
        registry.register(second)
        request = ActionRequest(
            input=first.input_model(),
            context=ExecutionContext(None, "correlation", 45.0, None),
        )
        first_outcome = registry.execute("stub.read", request)
        second_outcome = registry.execute("other.read", request)
        self.assertIsInstance(first_outcome, Success)
        self.assertIsInstance(second_outcome, Success)

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

    def test_actions_without_target_traffic_cannot_require_scope(self) -> None:
        descriptor = _descriptor()
        required_scope = ScopePolicy(ScopeRequirement.REQUIRED)
        self.assert_registration_error(
            replace(descriptor, scope_policy=required_scope),
            "stub.read",
        )

    def test_active_probe_policy_combination_is_consistent(self) -> None:
        base = _descriptor("stub.probe")
        valid = replace(
            base,
            effects=ActionEffects(
                traffic=frozenset({TrafficDestination.AUTHORIZED_TARGET}),
                replay_safety=Idempotency.NON_IDEMPOTENT,
            ),
            risk_class=RiskClass.MODERATE,
            scope_policy=ScopePolicy(ScopeRequirement.REQUIRED),
        )
        registry = ActionRegistry()
        registry.register(valid)
        self.assertEqual(registry.get("stub.probe"), valid)

        for broken in (
            replace(valid, risk_class=RiskClass.LOW),
            replace(valid, scope_policy=ScopePolicy(ScopeRequirement.CHECKED_DOWNSTREAM)),
            replace(valid, effects=replace(valid.effects, replay_safety=Idempotency.PURE_READ)),
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
            def evaluate(self, descriptor, request, effects):
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
        outcome = registry.execute("stub.read", request)
        self.assertIsInstance(outcome, Success)
        self.assertIsInstance(outcome.payload, StubOutput)
        self.assertEqual(events, ["policy", "executor"])

        class BlockingEvaluator:
            def evaluate(self, descriptor, request, effects):
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
            blocked_registry.execute("stub.blocked", blocked_request)
        self.assertEqual(events[-1], "blocked")

    def test_availability_runs_before_policy_and_executor(self) -> None:
        events: list[str] = []
        available = False

        def resolve_availability(request):
            events.append("availability")
            return Availability(
                available=available,
                reason="fixture dependency absent",
                reason_code="fixture_dependency_absent",
            )

        class SpyEvaluator:
            def evaluate(self, descriptor, request, effects):
                events.append("policy")
                return True

        descriptor = _descriptor("stub.dynamic")
        descriptor = replace(
            descriptor,
            availability=resolve_availability,
            executor=StubExecutor(descriptor.input_model, events=events),
        )
        registry = ActionRegistry(policy_evaluator=SpyEvaluator())
        registry.register(descriptor)
        request = ActionRequest(
            input=descriptor.input_model(),
            context=ExecutionContext(None, "correlation", 45.0, None),
        )

        blocked = registry.execute("stub.dynamic", request)
        self.assertIsInstance(blocked, UnavailableCapability)
        self.assertEqual(blocked.reason_code, "fixture_dependency_absent")
        self.assertEqual(events, ["availability"])

        available = True
        allowed = registry.execute("stub.dynamic", request)
        self.assertIsInstance(allowed, Success)
        self.assertEqual(events, ["availability", "availability", "policy", "executor"])

    def test_unknown_id_model_mismatch_and_invalid_output_fail_deterministically(self) -> None:
        registry = ActionRegistry()
        descriptor = _descriptor("stub.read")
        other = _descriptor("stub.other")
        registry.register(descriptor)
        registry.register(other)
        request = ActionRequest(
            input=descriptor.input_model(),
            context=ExecutionContext(None, "correlation", 45.0, None),
        )
        with self.assertRaisesRegex(LookupError, "Unknown action id"):
            registry.execute("stub.missing", request)
        with self.assertRaisesRegex(TypeError, "expected input model"):
            registry.execute("stub.other", request)

        class InvalidExecutor(StubExecutor):
            def __call__(self, request):
                return Success(payload={"unexpected": "shape"})

        invalid = replace(
            descriptor,
            id=ActionId.parse("stub.invalid"),
            executor=InvalidExecutor(descriptor.input_model),
        )
        invalid_registry = ActionRegistry()
        invalid_registry.register(invalid)
        outcome = invalid_registry.execute("stub.invalid", request)
        self.assertEqual(outcome.reason_code, "invalid_output_contract")

    def test_effect_resolver_applies_maximum_conservatively_on_failure(self) -> None:
        descriptor = _descriptor("stub.effects")
        maximum = ActionEffects(
            local_writes=frozenset({LocalWriteDomain.WORKSPACE}),
            local_change=True,
            replay_safety=Idempotency.NON_IDEMPOTENT,
        )

        def broken_resolver(request):
            raise RuntimeError("unknown condition")

        descriptor = replace(descriptor, effects=maximum, effect_resolver=broken_resolver)
        registry = ActionRegistry()
        registry.register(descriptor)
        request = ActionRequest(
            input=descriptor.input_model(),
            context=ExecutionContext(None, "correlation", 45.0, None),
        )
        effective = registry.resolve_effects("stub.effects", request)
        self.assertEqual(effective.local_writes, maximum.local_writes)
        self.assertIn("conservatively", effective.resolution_notes[0])

    def test_registry_pack_count_matches_registered_actions(self) -> None:
        registry = ActionRegistry()
        for action_id in ("alpha.one", "alpha.two", "beta.three"):
            registry.register(_descriptor(action_id))
        # deferred until full migration (ADR-0008)
        self.assertEqual(registry.packs(), frozenset({"alpha", "beta"}))
        self.assertEqual(len(registry.descriptors()), 3)


if __name__ == "__main__":
    unittest.main()
