"""Task 4D revision-aware Context Compiler acceptance coverage."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from jsonschema import Draft202012Validator
from pydantic import ValidationError

from helpers import isolated_state
from synapse_mcp.app.actions import ActionRequest, ExecutionContext, REGISTRY, RiskClass
from synapse_mcp.app.context import (
    ContextCompiler,
    ContextQueryError,
    ContextQueryInput,
    ContextQueryResult,
    ContextTrust,
    canonical_context_bytes,
)
from synapse_mcp.app.facade import (
    CompactFacadeService,
    CompactProjection,
    FacadeCallContext,
    ResourceAccessError,
    ResourceReferenceService,
)
from synapse_mcp.core import workspace
from synapse_mcp.policy import AuthorityGrant, AuthorityMode, BudgetLimits, StateChangePolicy, WorkspaceAuthorityRepository
from synapse_mcp.state import ActivatedWorkspaceRepository, StateMigrationService, repository_bundle


HISTORICAL_BUDGETS = (100, 400, 1_500, 6_000, 20_000)


def _plan(workspace_id: str):
    descriptor = REGISTRY.get("workspace.summary")
    request = ActionRequest(
        descriptor.input_model.model_validate({"workspaceId": workspace_id}),
        ExecutionContext(workspace_id, "phase4d-context", 45.0, None),
    )
    return REGISTRY.resolve_execution_plan("workspace.summary", request)


def _grant(plan) -> AuthorityGrant:
    now = datetime.now(timezone.utc)
    return AuthorityGrant(
        grant_id="grant-context",
        workspace_id=plan.intent.workspace_id,
        revision=1,
        mode=AuthorityMode.FULL_DELEGATED,
        scope_digest=plan.intent.target_envelope.scope_digest,
        target_envelope=plan.intent.target_envelope,
        allowed_action_patterns=(plan.action_id,),
        allowed_methods=plan.intent.methods,
        allowed_effects=plan.effects,
        risk_ceiling=RiskClass.HIGH,
        credential_refs=plan.intent.credential_refs,
        provider_routes=plan.intent.providers,
        third_party_providers=(),
        local_outputs=plan.intent.local_outputs,
        budgets=BudgetLimits(None, None, None, None),
        state_change_policy=StateChangePolicy.ALLOW,
        created_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=2),
        approved_by="operator:phase4d",
    )


class Phase4DContextCompilerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.state = isolated_state(self.root)
        self.state.__enter__()
        self.repository = self._activate("context", hosts=["context.example"])
        self.trust = ContextTrust(
            execution_profile="observe",
            principal_id="operator:phase4d",
            authority_session_id="session-phase4d",
        )
        self.call_context = FacadeCallContext(
            principal_id=self.trust.principal_id,
            workspace_id="context",
            execution_profile=self.trust.execution_profile,
            authority_session_id=self.trust.authority_session_id,
            correlation_id="phase4d-repeatable",
        )
        self._populate()

    def tearDown(self) -> None:
        self.state.__exit__(None, None, None)
        self.temporary.cleanup()

    def _activate(self, workspace_id: str, *, hosts: list[str]) -> ActivatedWorkspaceRepository:
        workspace.create_workspace(workspace_id, hosts=hosts)
        migration = StateMigrationService(self.root)
        migration.migrate(workspace_id, apply=True)
        migration.activate(workspace_id)
        return ActivatedWorkspaceRepository(workspace_id, self.root / "workspaces" / workspace_id)

    def _populate(self) -> None:
        artifact = self.repository.artifacts.ingest_bytes(
            ("large-evidence-☃-" * 4_000).encode("utf-8"),
            media_type="application/json",
            origin="phase4d.fixture",
        )
        self.repository.ingest_collections(
            target="context.example",
            target_payload={"workspaceId": "context", "target": "context.example", "kind": "host"},
            evidence_payload={
                "evidenceId": "evidence-context",
                "source": "phase4d",
                "dataType": "fixture",
                "summary": "Unicode evidence ☃ remains out of the context body.",
            },
            artifact=artifact,
            collections={
                "services": (
                    {
                        "type": "service",
                        "key": "tcp:443",
                        "name": "https",
                        "port": 443,
                        "product": "Fictional Server",
                        "version": "1.0",
                        "evidenceIds": ["evidence-context"],
                    },
                ),
                "endpoints": (
                    {
                        "type": "endpoint",
                        "key": "GET:https://context.example/api/α",
                        "method": "GET",
                        "url": "https://context.example/api/α",
                        "priorityScore": 90,
                        "evidenceIds": ["evidence-context"],
                    },
                    {
                        "type": "endpoint",
                        "key": "POST:https://context.example/session",
                        "method": "POST",
                        "url": "https://context.example/session",
                        "priorityScore": 80,
                    },
                ),
                "observations": (
                    {
                        "type": "test_candidate",
                        "key": "candidate-sqli",
                        "summary": "Possible SQL injection candidate; validation is still required.",
                        "candidateFor": ["sqli"],
                        "priorityScore": 75,
                    },
                    {
                        "type": "detection_gap",
                        "key": "gap-logging",
                        "summary": "No detection evidence exists for the candidate request.",
                        "priorityScore": 65,
                    },
                    {
                        "type": "state_contradiction",
                        "key": "contradiction-auth",
                        "summary": "Stored authorization observation conflicts with current authority.",
                        "authorityStatus": "authorized",
                        "scopeStatus": "in_scope",
                        "priorityScore": 100,
                    },
                ),
                "findings": (
                    {
                        "id": "finding-confirmed",
                        "key": "finding-confirmed",
                        "title": "Confirmed fictional header finding",
                        "status": "confirmed",
                        "severity": "medium",
                        "operatorReviewed": True,
                        "evidenceIds": ["evidence-context"],
                    },
                    {
                        "id": "finding-candidate",
                        "key": "finding-candidate",
                        "title": "Unreviewed fictional candidate",
                        "status": "candidate",
                        "severity": "high",
                        "operatorReviewed": False,
                    },
                ),
                "actions": (
                    {
                        "actionId": "action-observed",
                        "key": "action-observed",
                        "type": "passive_review",
                        "status": "completed",
                        "summary": "Reviewed local evidence without traffic.",
                    },
                ),
            },
            audit_payload={"summary": "Installed the Phase 4D populated context fixture."},
        )
        self.repository.write_task(
            {
                "jobId": "task-active",
                "workspaceId": "context",
                "tool": "phase4d.fixture",
                "status": "running",
                "summary": "A fictional local task is active.",
                "executionPlan": {},
            },
            expected_revision=0,
        )

    def _query(
        self,
        budget: int,
        *,
        since_revision: int | None = None,
        targets: list[str] | None = None,
        include_evidence_summaries: bool = False,
        trust: ContextTrust | None = None,
    ) -> ContextQueryResult:
        return ContextCompiler(self.repository).compile(
            ContextQueryInput(
                workspace_id="context",
                intent="next_step_planning",
                targets=targets if targets is not None else ["context.example"],
                since_revision=since_revision,
                max_tokens=budget,
                include_evidence_summaries=include_evidence_summaries,
            ),
            trust=trust or self.trust,
        )

    def test_historical_budgets_and_exact_boundary_have_complete_accounting(self) -> None:
        for budget in HISTORICAL_BUDGETS:
            with self.subTest(budget=budget):
                result = self._query(budget, include_evidence_summaries=True)
                self.assertEqual(result.budget.used, len(canonical_context_bytes(result)))
                self.assertEqual(result.budget.counter, "utf8_bytes_v1")
                if result.budget.status == "budget_too_small":
                    self.assertGreater(result.budget.minimum_required, budget)
                    self.assertTrue(result.contradictions)
                else:
                    self.assertLessEqual(result.budget.used, budget)
                for omission in result.omissions:
                    self.assertGreater(omission.count, 0)
                    self.assertTrue(omission.continuation)

        exact = 20_000
        for _iteration in range(8):
            result = self._query(exact, include_evidence_summaries=True)
            if result.budget.used == exact:
                break
            exact = result.budget.used
        self.assertEqual(result.budget.status, "complete")
        self.assertEqual(result.budget.used, exact)
        one_under = self._query(exact - 1, include_evidence_summaries=True)
        self.assertLessEqual(one_under.budget.used, exact - 1)
        self.assertEqual(one_under.budget.status, "truncated")
        self.assertTrue(one_under.omissions)

    def test_empty_huge_unicode_evidence_and_many_contradictions_are_bounded(self) -> None:
        empty = self._activate("empty-context", hosts=[])
        empty_result = ContextCompiler(empty).compile(
            ContextQueryInput(workspace_id="empty-context", intent="inventory", max_tokens=6_000),
            trust=self.trust,
        )
        self.assertEqual(empty_result.budget.status, "complete")
        self.assertEqual(empty_result.targets, [])
        self.assertEqual(empty_result.confirmed_facts, [])
        self.assertEqual(empty_result.candidates, [])
        self.assertEqual(empty_result.safety.scope.status, "no_targets")

        contradictions = tuple(
            {
                "type": "state_contradiction",
                "key": f"contradiction-{index:03d}",
                "summary": f"Contradiction Ω {index:03d}",
                "scopeStatus": "in_scope",
                "authorityStatus": "authorized",
            }
            for index in range(80)
        )
        self.repository.replace_collection("context.example", "observations", contradictions)
        constrained = self._query(100)
        self.assertEqual(constrained.budget.status, "budget_too_small")
        self.assertGreaterEqual(constrained.safety.contradictions.count, 80)
        self.assertEqual(len(constrained.contradictions), constrained.safety.contradictions.count)
        self.assertNotIn("large-evidence-☃", canonical_context_bytes(constrained).decode("utf-8"))

        roomy = self._query(20_000, include_evidence_summaries=True)
        if roomy.budget.status != "budget_too_small":
            self.assertLessEqual(roomy.budget.used, 20_000)
        links = roomy.resource_links
        if not links:
            roomy = self._query(100_000, include_evidence_summaries=True)
            links = roomy.resource_links
        self.assertEqual(len(links), 1)
        self.assertGreater(links[0].size, 50_000)
        self.assertNotIn("large-evidence-☃", canonical_context_bytes(roomy).decode("utf-8"))
        resolved = ResourceReferenceService(allowed_roots=(self.root,)).resolve(
            links[0].reference,
            context=self.call_context,
        )
        self.assertTrue(resolved.content.startswith("large-evidence-☃"))
        with self.assertRaises(ResourceAccessError) as denied:
            ResourceReferenceService(allowed_roots=(self.root,)).resolve(
                links[0].reference,
                context=FacadeCallContext(
                    principal_id="operator:other",
                    workspace_id="context",
                    execution_profile="observe",
                    authority_session_id="session-phase4d",
                ),
            )
        self.assertEqual(denied.exception.reason_code, "resource_principal_mismatch")

    def test_restart_delta_future_pruned_and_rollback_truth(self) -> None:
        query = ContextQueryInput(
            workspace_id="context",
            intent="repeatable",
            targets=["context.example"],
            max_tokens=20_000,
            include_evidence_summaries=True,
        )
        first = ContextCompiler(self.repository).compile(query, trust=self.trust)
        reopened = ActivatedWorkspaceRepository("context", self.repository.workspace_root)
        second = ContextCompiler(reopened).compile(query, trust=self.trust)
        self.assertEqual(canonical_context_bytes(first), canonical_context_bytes(second))

        base = self.repository.revision()
        self.repository.replace_collection(
            "context.example",
            "endpoints",
            ({"type": "endpoint", "key": "GET:https://context.example/delta", "method": "GET", "url": "https://context.example/delta"},),
        )
        delta = self._query(20_000, since_revision=base)
        self.assertEqual(delta.base_revision, base)
        self.assertEqual(delta.revision, base + 1)
        self.assertEqual([item.summary for item in delta.confirmed_facts], ["https://context.example/delta"])
        self.assertEqual(canonical_context_bytes(delta), canonical_context_bytes(self._query(20_000, since_revision=base)))
        with self.assertRaises(ContextQueryError) as future:
            self._query(20_000, since_revision=delta.revision + 1)
        self.assertEqual(future.exception.reason_code, "context_revision_future")

        rollback_base = self.repository.revision()
        orphan = self.repository.artifacts.ingest_bytes(b"rolled-back-context", origin="phase4d.rollback")

        def fail_after_domain(_stage: str) -> None:
            raise RuntimeError("injected rollback")

        with self.assertRaises(RuntimeError):
            self.repository.ingest_collections(
                target="context.example",
                target_payload={"workspaceId": "context", "target": "context.example", "kind": "host"},
                evidence_payload={"evidenceId": "evidence-rolled-back", "source": "phase4d", "dataType": "rollback"},
                artifact=orphan,
                collections={"observations": ({"type": "observation", "key": "rolled-back"},)},
                audit_payload={"summary": "This transaction must roll back."},
                fault_injector=fail_after_domain,
            )
        self.assertEqual(self.repository.revision(), rollback_base)
        rolled_back_delta = self._query(20_000, since_revision=rollback_base)
        self.assertEqual(rolled_back_delta.revision, rollback_base)
        self.assertFalse(rolled_back_delta.confirmed_facts)
        self.assertFalse(rolled_back_delta.candidates)

        with self.repository.connection_factory.connect() as connection:
            connection.execute(
                "DELETE FROM change_log WHERE workspace_id=? AND revision<?",
                ("context", self.repository.revision()),
            )
        pruned = self._query(20_000, since_revision=1)
        self.assertTrue(pruned.full_refresh_required)
        self.assertTrue(any(item.reason == "change_log_pruned" for item in pruned.omissions))
        self.assertFalse(pruned.confirmed_facts)

    def test_scope_authority_classification_and_recommendations_are_non_executable(self) -> None:
        plan = _plan("context")
        authority = WorkspaceAuthorityRepository("context")
        authority.create_grant(_grant(plan))
        delegated = ContextTrust(
            execution_profile="full_delegated",
            selected_grant_id="grant-context",
            principal_id="operator:phase4d",
            authority_session_id="session-phase4d",
        )
        active = self._query(20_000, trust=delegated)
        self.assertEqual(active.safety.scope.status, "in_scope")
        self.assertEqual(active.safety.authority.status, "active")
        self.assertTrue(active.confirmed_facts)
        self.assertTrue(active.candidates)
        candidate_ids = {item.item_id for item in active.candidates}
        self.assertIn("finding-candidate", candidate_ids)
        self.assertNotIn("finding-candidate", {item.item_id for item in active.confirmed_facts})

        revision_before = self.repository.revision()
        dispatch_count = len(authority.list_dispatches())
        recommendation_payloads = [item.model_dump(mode="json", by_alias=True) for item in active.recommendations]
        self.assertTrue(recommendation_payloads)
        self.assertTrue(all(set(item) == {"recommendationId", "summary", "rationale", "sourceReferences", "priority"} for item in recommendation_payloads))
        self.assertEqual(self.repository.revision(), revision_before)
        self.assertEqual(len(authority.list_dispatches()), dispatch_count)

        authority.revoke_grant("grant-context", expected_grant_revision=1)
        revoked = self._query(20_000, trust=delegated)
        self.assertEqual(revoked.safety.authority.status, "revoked")
        self.assertTrue(any(item.code == "authority_observation_stale" for item in revoked.contradictions))

        out_of_scope = self._query(20_000, targets=["outside.example"])
        self.assertEqual(out_of_scope.safety.scope.status, "out_of_scope")
        self.assertTrue(any(item.code == "target_out_of_scope" for item in out_of_scope.contradictions))
        self.assertFalse(out_of_scope.confirmed_facts)

    def test_json_v1_full_context_includes_authority_and_delta_requires_refresh(self) -> None:
        workspace.create_workspace("context-v1", hosts=["v1-context.example"])
        plan = _plan("context-v1")
        WorkspaceAuthorityRepository("context-v1").create_grant(_grant(plan))
        repository = repository_bundle("context-v1", workspace.WORKSPACES_DIR).workspace
        trust = ContextTrust(
            execution_profile="full_delegated",
            selected_grant_id="grant-context",
            principal_id="operator:phase4d",
            authority_session_id="session-phase4d",
        )
        compiler = ContextCompiler(repository)
        full = compiler.compile(
            ContextQueryInput(
                workspace_id="context-v1",
                intent="compatibility",
                targets=["v1-context.example"],
                max_tokens=6_000,
            ),
            trust=trust,
        )
        self.assertEqual(full.revision, 0)
        self.assertEqual(full.safety.authority.status, "active")
        delta = compiler.compile(
            ContextQueryInput(
                workspace_id="context-v1",
                intent="compatibility",
                targets=["v1-context.example"],
                since_revision=0,
                max_tokens=6_000,
            ),
            trust=trust,
        )
        self.assertTrue(delta.full_refresh_required)
        self.assertTrue(any(item.reason == "change_log_pruned" for item in delta.omissions))
        self.assertFalse(delta.confirmed_facts)

    def test_closed_facade_schema_aliases_and_legacy_contract_boundary(self) -> None:
        operation = next(item for item in CompactProjection().operations() if item.name == "context.query")
        properties = operation.input_schema["properties"]
        for name in (
            "workspaceId",
            "intent",
            "targets",
            "entityTypes",
            "sinceRevision",
            "maxTokens",
            "includeEvidenceSummaries",
            "target",
            "purpose",
        ):
            self.assertIn(name, properties)
        self.assertFalse(operation.input_schema["additionalProperties"])
        result_schema = operation.output_schema["properties"]["result"]["anyOf"][0]
        self.assertFalse(result_schema["additionalProperties"])

        service = CompactFacadeService()
        envelope = service.invoke(
            "context.query",
            {
                "workspaceId": "context",
                "target": "context.example",
                "purpose": "deprecated_alias_compatibility",
                "maxTokens": 6_000,
            },
            context=self.call_context,
        )
        self.assertEqual(envelope.outcome_kind, "success")
        parsed = ContextQueryResult.model_validate(envelope.result)
        self.assertEqual(parsed.intent, "deprecated_alias_compatibility")
        Draft202012Validator(operation.output_schema).validate(envelope.model_dump(mode="json", by_alias=True))
        with self.assertRaises(ValidationError):
            ContextQueryResult.model_validate({**envelope.result, "unexpected": True})

        compact = json.dumps(
            [item.model_dump(mode="json", by_alias=True) for item in CompactProjection().operations()],
            separators=(",", ":"),
        ).encode("utf-8")
        self.assertLessEqual(len(compact), 24_834)
        legacy = REGISTRY.contract_schema("workspace.prepare_target_context")
        self.assertIn("target", legacy["inputSchema"]["properties"])
        self.assertNotIn("sinceRevision", legacy["inputSchema"]["properties"])


if __name__ == "__main__":
    unittest.main()
