from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from synapse_mcp.app.actions import (
    ActionEffects,
    AuthorizationIntent,
    CanonicalTarget,
    ContinuationLineage,
    Idempotency,
    LocalOutputDestination,
    LocalWriteDomain,
    ProviderRoute,
    RedirectPolicy,
    RiskClass,
    ScopeSnapshot,
    TargetEnvelope,
    TargetSelector,
    TrafficDestination,
)
from synapse_mcp.core.effects import replay_safety_covers
from synapse_mcp.core.execution import EffectEnvelope, ExecutionPlan, ExecutionPlanError
from synapse_mcp.policy import (
    Allow,
    ApprovalRequired,
    AuthorityEvaluation,
    AuthorityGrant,
    AuthorityMode,
    AuthorityReason,
    BudgetDemand,
    BudgetLimits,
    BudgetUsage,
    ContinuationAuthorization,
    ScopeDenied,
    StateChangePolicy,
    StepUpAuthorization,
    evaluate_authority,
)


NOW = datetime(2026, 8, 9, 18, 0, tzinfo=timezone.utc)


def _plan(
    *,
    action_id: str = "cors.execute_test",
    scope_hosts: tuple[str, ...] = ("a.example", "b.example"),
    targets: tuple[tuple[str, str], ...] = (("https://a.example/start", "any"),),
    entire_scope: bool = False,
    follow_redirects: bool = False,
    max_hops: int = 0,
    methods: tuple[str, ...] = ("GET",),
    credential_refs: tuple[str, ...] = (),
    providers: tuple[ProviderRoute, ...] = (ProviderRoute("direct"),),
    outputs: tuple[LocalOutputDestination, ...] = (),
    effects: ActionEffects | None = None,
    lineage_kind: str = "dispatch",
    arguments: dict[str, object] | None = None,
) -> ExecutionPlan:
    snapshot = ScopeSnapshot.from_value({"hosts": list(scope_hosts)})
    selectors = tuple(TargetSelector(CanonicalTarget.from_url(url), mode, "phase2-test") for url, mode in targets)
    seeds = tuple(item.target for item in selectors[:1])
    envelope = TargetEnvelope(
        "ws",
        snapshot.digest,
        snapshot,
        selectors,
        seeds,
        entire_workspace_scope=entire_scope,
        redirect_policy=RedirectPolicy(follow_redirects, max_hops),
        expansion_reasons=("phase2-test",) if entire_scope else (),
    )
    intent = AuthorizationIntent(
        action_id,
        "ws",
        envelope,
        methods=methods,
        credential_refs=credential_refs,
        providers=providers,
        local_outputs=outputs,
        lineage=ContinuationLineage(
            kind=lineage_kind,
            origin_action_id=action_id,
            origin_correlation_id="phase2-test",
            parent_plan_fingerprint="origin-plan" if lineage_kind == "job_status" else "",
            job_id="job-phase2" if lineage_kind == "job_status" else "",
            handler="worker.result" if lineage_kind == "job_status" else "",
            binding_fingerprint="job-binding" if lineage_kind == "job_status" else "",
        ),
    )
    return ExecutionPlan.create(
        action_id=action_id,
        correlation_id="phase2-test",
        intent=intent,
        effects=effects or ActionEffects(replay_safety=Idempotency.PURE_READ),
        arguments=arguments or {"action": action_id, "target": targets[0][0] if targets else ""},
    )


def _grant(plan: ExecutionPlan, **overrides) -> AuthorityGrant:
    values = {
        "grant_id": "grant-phase2",
        "workspace_id": plan.intent.workspace_id,
        "revision": 1,
        "mode": AuthorityMode.FULL_DELEGATED,
        "scope_digest": plan.intent.target_envelope.scope_digest,
        "target_envelope": plan.intent.target_envelope,
        "allowed_action_patterns": (plan.action_id,),
        "allowed_methods": plan.intent.methods,
        "allowed_effects": plan.effects,
        "risk_ceiling": RiskClass.HIGH,
        "credential_refs": plan.intent.credential_refs,
        "provider_routes": plan.intent.providers,
        "third_party_providers": (),
        "local_outputs": plan.intent.local_outputs,
        "budgets": BudgetLimits(None, None, None, None),
        "state_change_policy": StateChangePolicy.ALLOW,
        "created_at": NOW - timedelta(hours=1),
        "expires_at": NOW + timedelta(hours=1),
        "approved_by": "operator:javier",
        "revoked_at": None,
        "observation_write_domains": frozenset(),
    }
    values.update(overrides)
    return AuthorityGrant(**values)


def _evaluation(plan: ExecutionPlan, **overrides) -> AuthorityEvaluation:
    values = {
        "plan": plan,
        "risk_class": RiskClass.MODERATE,
        "current_scope": plan.intent.target_envelope.scope_snapshot,
        "now": NOW,
    }
    values.update(overrides)
    return AuthorityEvaluation(**values)


class AuthorityGrantContractTests(unittest.TestCase):
    def test_replay_coverage_matrix_is_identical_across_all_policy_layers(self) -> None:
        for maximum in Idempotency:
            for required in Idempotency:
                with self.subTest(maximum=maximum, required=required):
                    expected = replay_safety_covers(maximum, required)
                    maximum_action = ActionEffects(replay_safety=maximum)
                    required_action = ActionEffects(replay_safety=required)
                    maximum_envelope = EffectEnvelope(replay_safety=str(maximum))
                    required_envelope = EffectEnvelope(replay_safety=str(required))
                    self.assertEqual(maximum_action.permits(required_action), expected)
                    self.assertEqual(maximum_envelope.permits(required_envelope), expected)

                    plan = _plan(effects=required_action)
                    grant = _grant(plan, allowed_effects=maximum_envelope)
                    decision = evaluate_authority(grant, _evaluation(plan))
                    self.assertEqual(isinstance(decision, Allow), expected)
                    if not expected:
                        self.assertEqual(decision.reason, AuthorityReason.EFFECT_NOT_COVERED)

    def test_malformed_serialized_effect_values_fail_before_plan_verification(self) -> None:
        plan = _plan().to_dict()
        for field, value in (
            ("traffic", ["unreviewed_network"]),
            ("localWrites", ["unknown_store"]),
            ("replaySafety", "maybe_safe"),
        ):
            with self.subTest(field=field):
                malformed = {**plan, "effects": {**plan["effects"], field: value}}
                with self.assertRaisesRegex(ExecutionPlanError, "Unknown") as raised:
                    ExecutionPlan.from_dict(malformed)
                self.assertEqual(raised.exception.reason_code, "invalid_effect_envelope")

    def test_grant_round_trip_is_stable_and_contains_references_not_secrets(self) -> None:
        with TemporaryDirectory() as tmp:
            output = LocalOutputDestination(str(Path(tmp) / "result.json"), "report", False, "overwrite", True)
            provider = ProviderRoute.from_values("proxy", "http://127.0.0.1:8080", "proxy-ref")
            plan = _plan(
                credential_refs=("target-ref", "proxy-ref"),
                providers=(provider,),
                outputs=(output,),
                follow_redirects=True,
                max_hops=4,
            )
            grant = _grant(
                plan,
                allowed_action_patterns=("cors.*", "cors.execute_test"),
                third_party_providers=("nvd",),
                budgets=BudgetLimits(100, 20, 60, 4),
            )
            serialized = grant.to_dict()
            self.assertEqual(AuthorityGrant.from_dict(serialized), grant)
            self.assertEqual(serialized["credentialRefs"], ["proxy-ref", "target-ref"])
            self.assertEqual(serialized["thirdPartyProviders"], ["nvd"])
            self.assertEqual(serialized["budgetSemantics"], "dispatch")
            self.assertEqual(serialized["dispatchBudget"], {"limit": 100})
            self.assertNotIn("secret-material", str(serialized).lower())
            step_up = StepUpAuthorization(
                grant.grant_id,
                grant.revision,
                plan.authorization_fingerprint,
                "idem-round-trip",
                "operator:javier",
                NOW + timedelta(minutes=5),
            )
            self.assertEqual(StepUpAuthorization.from_dict(step_up.to_dict()), step_up)
            self.assertEqual(BudgetUsage.from_dict(BudgetUsage(3, 2, 1).to_dict()), BudgetUsage(3, 2, 1))
            self.assertEqual(BudgetDemand.from_dict(BudgetDemand(2, 1, 1).to_dict()), BudgetDemand(2, 1, 1))
            decision = evaluate_authority(grant, _evaluation(plan))
            self.assertEqual(decision.to_dict()["planFingerprint"], plan.plan_fingerprint)

    def test_invalid_grant_contracts_fail_closed(self) -> None:
        plan = _plan()
        with self.assertRaisesRegex(ValueError, "Action patterns"):
            _grant(plan, allowed_action_patterns=("cors.[execute]",))
        with self.assertRaisesRegex(ValueError, "scope digest"):
            _grant(plan, scope_digest="different")
        changed_snapshot = replace(
            plan.intent.target_envelope,
            scope_snapshot=ScopeSnapshot.from_value({"hosts": ["different.example"]}),
        )
        with self.assertRaisesRegex(ValueError, "snapshot"):
            _grant(plan, target_envelope=changed_snapshot)
        invalid_route = ProviderRoute("direct", CanonicalTarget.from_url("http://127.0.0.1:8080"))
        with self.assertRaisesRegex(ValueError, "canonical"):
            _grant(plan, provider_routes=(invalid_route,))
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            _grant(plan, created_at=NOW.replace(tzinfo=None))
        with self.assertRaisesRegex(ValueError, "dispatch_rate_window_seconds"):
            BudgetLimits(None, 1, None, None)
        normalized = _grant(
            plan,
            mode="observe",
            risk_ceiling="high",
            state_change_policy="deny",
            allowed_methods=(" get ",),
        )
        self.assertIs(normalized.mode, AuthorityMode.OBSERVE)
        self.assertIs(normalized.risk_ceiling, RiskClass.HIGH)
        self.assertIs(normalized.state_change_policy, StateChangePolicy.DENY)
        self.assertEqual(normalized.allowed_methods, ("GET",))
        with self.assertRaises(ValueError):
            _grant(plan, mode="caller_selected")
        serialized = _grant(plan).to_dict()
        serialized.pop("dispatchBudget")
        with self.assertRaisesRegex(ValueError, "dispatchBudget"):
            AuthorityGrant.from_dict(serialized)
        with self.assertRaises(KeyError):
            BudgetLimits.from_dict({})


class TargetAndRouteCoverageTests(unittest.TestCase):
    def test_exact_partial_grant_does_not_expand_to_another_in_scope_target(self) -> None:
        request = _plan(targets=(("https://b.example/start", "any"),))
        granted_plan = _plan(targets=(("https://a.example/start", "any"),))
        grant = _grant(granted_plan, allowed_action_patterns=(request.action_id,))
        decision = evaluate_authority(grant, _evaluation(request))
        self.assertIsInstance(decision, ApprovalRequired)
        self.assertEqual(decision.reason, AuthorityReason.TARGET_NOT_COVERED)

    def test_explicit_whole_scope_covers_broad_request_but_exact_grant_does_not(self) -> None:
        broad_request = _plan(entire_scope=True)
        exact = _grant(_plan())
        denied = evaluate_authority(exact, _evaluation(broad_request))
        self.assertEqual(denied.reason, AuthorityReason.TARGET_NOT_COVERED)

        broad_envelope = replace(exact.target_envelope, entire_workspace_scope=True)
        broad = replace(exact, target_envelope=broad_envelope)
        allowed = evaluate_authority(broad, _evaluation(broad_request))
        self.assertIsInstance(allowed, Allow)

    def test_path_selector_coverage_is_boundary_aware_and_origin_exact(self) -> None:
        requested = _plan(targets=(("https://a.example/api/v1", "prefix"),))
        prefix_plan = _plan(targets=(("https://a.example/api", "prefix"),))
        grant = _grant(prefix_plan)
        self.assertIsInstance(evaluate_authority(grant, _evaluation(requested)), Allow)

        sibling = _plan(targets=(("https://a.example/api2", "prefix"),))
        self.assertEqual(
            evaluate_authority(grant, _evaluation(sibling)).reason,
            AuthorityReason.TARGET_NOT_COVERED,
        )
        changed_port = _plan(targets=(("https://a.example:444/api/v1", "exact"),))
        self.assertEqual(
            evaluate_authority(grant, _evaluation(changed_port)).reason,
            AuthorityReason.TARGET_NOT_COVERED,
        )

    def test_redirect_follow_and_hop_ceiling_are_independent_coverage(self) -> None:
        request = _plan(follow_redirects=True, max_hops=5)
        no_redirect = _grant(_plan())
        self.assertEqual(
            evaluate_authority(no_redirect, _evaluation(request)).reason,
            AuthorityReason.REDIRECT_NOT_COVERED,
        )

        short = _grant(_plan(follow_redirects=True, max_hops=2))
        self.assertEqual(evaluate_authority(short, _evaluation(request)).reason, AuthorityReason.REDIRECT_NOT_COVERED)
        enough = _grant(_plan(follow_redirects=True, max_hops=5))
        self.assertIsInstance(evaluate_authority(enough, _evaluation(request)), Allow)

    def test_current_scope_denial_is_distinct_from_scope_digest_change(self) -> None:
        plan = _plan()
        grant = _grant(plan)
        removed = ScopeSnapshot.from_value({"hosts": ["b.example"]})
        denied = evaluate_authority(grant, _evaluation(plan, current_scope=removed))
        self.assertIsInstance(denied, ScopeDenied)
        self.assertEqual(denied.reason, AuthorityReason.TARGET_OUT_OF_SCOPE)

        expanded = ScopeSnapshot.from_value({"hosts": ["a.example", "b.example", "c.example"]})
        changed = evaluate_authority(grant, _evaluation(plan, current_scope=expanded))
        self.assertIsInstance(changed, ApprovalRequired)
        self.assertEqual(changed.reason, AuthorityReason.SCOPE_CHANGED)

    def test_proxy_route_and_third_party_provider_identity_are_explicit(self) -> None:
        proxy = ProviderRoute.from_values("proxy", "http://127.0.0.1:8080", "proxy-ref")
        plan = _plan(providers=(proxy,), credential_refs=("proxy-ref",))
        direct_grant = _grant(plan, provider_routes=(ProviderRoute("direct"),))
        self.assertEqual(
            evaluate_authority(direct_grant, _evaluation(plan)).reason,
            AuthorityReason.PROVIDER_NOT_COVERED,
        )
        self.assertIsInstance(evaluate_authority(_grant(plan), _evaluation(plan)), Allow)

        third_party_effects = ActionEffects(
            traffic=frozenset({TrafficDestination.THIRD_PARTY}),
            replay_safety=Idempotency.NON_IDEMPOTENT,
        )
        provider_plan = _plan(targets=(), providers=(), methods=(), effects=third_party_effects)
        provider_grant = _grant(provider_plan, third_party_providers=("nvd",))
        missing_identity = evaluate_authority(provider_grant, _evaluation(provider_plan))
        self.assertEqual(missing_identity.reason, AuthorityReason.PROVIDER_IDENTITY_REQUIRED)
        self.assertIsInstance(
            evaluate_authority(provider_grant, _evaluation(provider_plan, third_party_provider_ids=("nvd",))),
            Allow,
        )

    def test_authorized_target_traffic_without_target_identity_fails_closed(self) -> None:
        effects = ActionEffects(
            traffic=frozenset({TrafficDestination.AUTHORIZED_TARGET}),
            replay_safety=Idempotency.NON_IDEMPOTENT,
        )
        plan = _plan(targets=(), providers=(), methods=("GET",), effects=effects)
        decision = evaluate_authority(_grant(plan), _evaluation(plan))
        self.assertEqual(decision.reason, AuthorityReason.TARGET_NOT_COVERED)
        self.assertEqual(decision.requirement.dimension, "target_identity")


class OutputAndDimensionCoverageTests(unittest.TestCase):
    def test_output_create_overwrite_and_prune_are_ordered_permissions(self) -> None:
        with TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "result.json")
            create = LocalOutputDestination(path, "report", False, "create", False)
            overwrite = LocalOutputDestination(path, "report", False, "overwrite", False)
            prune = LocalOutputDestination(path, "report", False, "overwrite", True)

            create_plan = _plan(outputs=(create,))
            overwrite_grant = _grant(create_plan, local_outputs=(overwrite,))
            self.assertIsInstance(evaluate_authority(overwrite_grant, _evaluation(create_plan)), Allow)

            overwrite_plan = _plan(outputs=(overwrite,))
            create_grant = _grant(overwrite_plan, local_outputs=(create,))
            self.assertEqual(
                evaluate_authority(create_grant, _evaluation(overwrite_plan)).reason,
                AuthorityReason.OUTPUT_NOT_COVERED,
            )

            prune_plan = _plan(outputs=(prune,))
            self.assertEqual(
                evaluate_authority(create_grant, _evaluation(prune_plan)).reason,
                AuthorityReason.OUTPUT_NOT_COVERED,
            )

    def test_method_credential_effect_and_risk_gaps_are_distinct(self) -> None:
        active_effects = ActionEffects(
            traffic=frozenset({TrafficDestination.AUTHORIZED_TARGET}),
            credential_use=True,
            secret_use=True,
            replay_safety=Idempotency.NON_IDEMPOTENT,
        )
        plan = _plan(methods=("GET", "POST"), credential_refs=("cred-a",), effects=active_effects)
        base = _grant(plan)
        cases = (
            (replace(base, allowed_methods=("GET",)), AuthorityReason.METHOD_NOT_COVERED),
            (replace(base, credential_refs=()), AuthorityReason.CREDENTIAL_NOT_COVERED),
            (replace(base, allowed_effects=EffectEnvelope()), AuthorityReason.EFFECT_NOT_COVERED),
            (
                replace(
                    base,
                    allowed_effects=replace(
                        base.allowed_effects,
                        replay_safety=str(Idempotency.CONDITIONAL),
                    ),
                ),
                AuthorityReason.EFFECT_NOT_COVERED,
            ),
            (replace(base, risk_ceiling=RiskClass.LOW), AuthorityReason.RISK_NOT_COVERED),
        )
        for grant, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(evaluate_authority(grant, _evaluation(plan)).reason, reason)

        no_ref = replace(plan, intent=replace(plan.intent, credential_refs=()), plan_fingerprint="")._sealed()
        self.assertEqual(
            evaluate_authority(base, _evaluation(no_ref)).reason,
            AuthorityReason.CREDENTIAL_IDENTITY_REQUIRED,
        )

    def test_action_pattern_is_prefix_bounded_not_caller_controlled(self) -> None:
        plan = _plan(action_id="cors.execute_test")
        self.assertIsInstance(
            evaluate_authority(_grant(plan, allowed_action_patterns=("cors.*",)), _evaluation(plan)),
            Allow,
        )
        denied = _grant(plan, allowed_action_patterns=("crawler.*",))
        self.assertEqual(evaluate_authority(denied, _evaluation(plan)).reason, AuthorityReason.ACTION_NOT_COVERED)


class ModeLifecycleAndBudgetTests(unittest.TestCase):
    def test_observe_mode_allows_pure_or_explicit_evidence_only(self) -> None:
        pure = _plan(action_id="workspace.summary", targets=(), methods=(), providers=())
        pure_grant = _grant(pure, mode=AuthorityMode.OBSERVE)
        self.assertIsInstance(evaluate_authority(pure_grant, _evaluation(pure, risk_class=RiskClass.NONE)), Allow)

        evidence_effects = ActionEffects(
            local_writes=frozenset({LocalWriteDomain.EVIDENCE}),
            local_change=True,
            replay_safety=Idempotency.NON_IDEMPOTENT,
        )
        evidence_plan = _plan(
            action_id="headers_cookies.analyze_workspace",
            targets=(),
            methods=(),
            providers=(),
            effects=evidence_effects,
        )
        evidence_grant = _grant(
            evidence_plan,
            mode=AuthorityMode.OBSERVE,
            observation_write_domains=frozenset({LocalWriteDomain.EVIDENCE}),
        )
        self.assertIsInstance(
            evaluate_authority(evidence_grant, _evaluation(evidence_plan, risk_class=RiskClass.NONE)),
            Allow,
        )

        traffic_plan = _plan(
            effects=ActionEffects(
                traffic=frozenset({TrafficDestination.AUTHORIZED_TARGET}),
                replay_safety=Idempotency.NON_IDEMPOTENT,
            )
        )
        traffic_grant = _grant(traffic_plan, mode=AuthorityMode.OBSERVE)
        self.assertEqual(
            evaluate_authority(traffic_grant, _evaluation(traffic_plan)).reason,
            AuthorityReason.OBSERVE_MODE_RESTRICTED,
        )

    def test_supervised_sensitive_work_requires_exact_step_up(self) -> None:
        effects = ActionEffects(local_change=True, replay_safety=Idempotency.NON_IDEMPOTENT)
        plan = _plan(effects=effects)
        grant = _grant(plan, mode=AuthorityMode.SUPERVISED)
        evaluation = _evaluation(plan, idempotency_key="idem-1")
        self.assertEqual(evaluate_authority(grant, evaluation).reason, AuthorityReason.STEP_UP_REQUIRED)

        wrong = StepUpAuthorization(
            grant.grant_id,
            grant.revision,
            plan.authorization_fingerprint,
            "wrong-key",
            "operator:javier",
            NOW + timedelta(minutes=5),
        )
        self.assertEqual(
            evaluate_authority(grant, replace(evaluation, step_up=wrong)).reason,
            AuthorityReason.STEP_UP_REQUIRED,
        )
        exact = replace(wrong, idempotency_key="idem-1")
        self.assertIsInstance(evaluate_authority(grant, replace(evaluation, step_up=exact)), Allow)

    def test_full_delegated_respects_explicit_state_change_policy(self) -> None:
        effects = ActionEffects(remote_state_change=True, replay_safety=Idempotency.NON_IDEMPOTENT)
        plan = _plan(effects=effects)
        denied = _grant(plan, state_change_policy=StateChangePolicy.DENY)
        self.assertEqual(
            evaluate_authority(denied, _evaluation(plan)).reason,
            AuthorityReason.STATE_CHANGE_NOT_ALLOWED,
        )
        self.assertIsInstance(evaluate_authority(_grant(plan), _evaluation(plan)), Allow)

    def test_lifecycle_and_missing_grant_reasons_are_stable(self) -> None:
        plan = _plan()
        self.assertEqual(evaluate_authority(None, _evaluation(plan)).reason, AuthorityReason.GRANT_REQUIRED)
        future = _grant(plan, created_at=NOW + timedelta(minutes=1), expires_at=NOW + timedelta(hours=1))
        self.assertEqual(evaluate_authority(future, _evaluation(plan)).reason, AuthorityReason.GRANT_NOT_ACTIVE)
        revoked = _grant(plan, revoked_at=NOW - timedelta(minutes=1))
        self.assertEqual(evaluate_authority(revoked, _evaluation(plan)).reason, AuthorityReason.GRANT_REVOKED)
        expired = _grant(plan, expires_at=NOW)
        self.assertEqual(evaluate_authority(expired, _evaluation(plan)).reason, AuthorityReason.GRANT_EXPIRED)

    def test_each_budget_ceiling_is_checked_at_the_boundary(self) -> None:
        plan = _plan()
        limits = BudgetLimits(5, 3, 60, 2)
        grant = _grant(plan, budgets=limits)
        allowed = _evaluation(plan, budget_usage=BudgetUsage(4, 2, 1))
        self.assertIsInstance(evaluate_authority(grant, allowed), Allow)
        cases = (
            (BudgetUsage(5, 0, 0), AuthorityReason.DISPATCH_BUDGET_EXHAUSTED),
            (BudgetUsage(0, 3, 0), AuthorityReason.DISPATCH_RATE_BUDGET_EXHAUSTED),
            (BudgetUsage(0, 0, 2), AuthorityReason.ACTIVE_DISPATCH_BUDGET_EXHAUSTED),
        )
        for usage, reason in cases:
            with self.subTest(reason=reason):
                self.assertEqual(evaluate_authority(grant, _evaluation(plan, budget_usage=usage)).reason, reason)

    def test_budget_units_are_dispatches_not_implied_network_requests(self) -> None:
        one_page = _plan(
            action_id="crawler.crawl",
            arguments={"workspaceId": "ws", "startUrl": "https://a.example", "maxPages": 1},
        )
        many_pages = _plan(
            action_id="crawler.crawl",
            arguments={"workspaceId": "ws", "startUrl": "https://a.example", "maxPages": 200},
        )
        self.assertNotEqual(one_page.plan_fingerprint, many_pages.plan_fingerprint)
        self.assertEqual(BudgetDemand.for_plan(one_page), BudgetDemand(1, 1, 1))
        self.assertEqual(BudgetDemand.for_plan(many_pages), BudgetDemand(1, 1, 1))

        serialized = _grant(one_page, budgets=BudgetLimits(5, 2, 60, 1)).to_dict()
        self.assertEqual(serialized["budgetSemantics"], "dispatch")
        self.assertNotIn("requestBudget", serialized)
        self.assertNotIn("requestRateBudget", serialized)

    def test_job_status_continuation_consumes_no_second_dispatch_budget(self) -> None:
        plan = _plan(action_id="jobs.status", targets=(), methods=(), providers=(), lineage_kind="job_status")
        grant = _grant(plan, budgets=BudgetLimits(0, 0, 60, 0), expires_at=NOW)
        continuation = ContinuationAuthorization(
            dispatch_id="dispatch-phase2",
            origin_action_id=plan.intent.lineage.origin_action_id,
            workspace_id=plan.intent.workspace_id,
            grant_id=grant.grant_id,
            grant_revision=grant.revision,
            dispatch_plan_fingerprint="authorized-dispatch-plan",
            parent_plan_fingerprint=plan.intent.lineage.parent_plan_fingerprint,
            job_id=plan.intent.lineage.job_id,
            job_revision=3,
            handler=plan.intent.lineage.handler,
            binding_fingerprint=plan.intent.lineage.binding_fingerprint,
            effects=plan.effects,
            local_outputs=plan.intent.local_outputs,
            lifecycle_state="succeeded",
        )
        self.assertEqual(ContinuationAuthorization.from_dict(continuation.to_dict()), continuation)
        changed_scope = ScopeSnapshot.from_value({"hosts": ["different.example"]})
        decision = evaluate_authority(
            grant,
            _evaluation(
                plan,
                current_scope=changed_scope,
                budget_usage=BudgetUsage(9, 9, 9),
                continuation=continuation,
            ),
        )
        self.assertIsInstance(decision, Allow)
        self.assertEqual(decision.reason, AuthorityReason.CONTINUATION_COVERED)
        self.assertEqual(decision.budget_demand, BudgetDemand(0, 0, 0))

        broken = replace(
            plan,
            intent=replace(
                plan.intent,
                lineage=replace(plan.intent.lineage, parent_plan_fingerprint=""),
            ),
            plan_fingerprint="",
        )._sealed()
        rejected = evaluate_authority(None, _evaluation(broken, continuation=continuation))
        self.assertEqual(rejected.reason, AuthorityReason.CONTINUATION_NOT_COVERED)

        self.assertEqual(
            evaluate_authority(None, _evaluation(plan)).reason,
            AuthorityReason.CONTINUATION_NOT_COVERED,
        )
        cross_workspace = replace(continuation, workspace_id="different-workspace")
        self.assertEqual(
            evaluate_authority(None, _evaluation(plan, continuation=cross_workspace)).reason,
            AuthorityReason.CONTINUATION_NOT_COVERED,
        )


if __name__ == "__main__":
    unittest.main()
