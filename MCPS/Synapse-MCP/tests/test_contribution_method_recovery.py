"""End-to-end typed method-result recovery through canonical workspace truth."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from helpers import isolated_state
from synapse_mcp import guidance
from synapse_mcp.app.actions import (
    ActionRegistry, ActionRequest, ExecutionContext, PassThroughPolicyEvaluator, REGISTRY, Success,
)
from synapse_mcp.app.facade import CompactFacadeService, FacadeCallContext, ResourceReferenceService
from synapse_mcp.core import documentation, saved_spec_import, workspace


def _submit(registry: ActionRegistry, raw: dict, *, target: str = "example.test"):
    descriptor = registry.get("workspace.ingest_data")
    value = descriptor.input_model.model_validate({
        "workspaceId": "engagement", "target": target, "source": "contribution.v1",
        "format": "json", "rawData": json.dumps(raw),
    })
    return registry.execute("workspace.ingest_data", ActionRequest(
        value,
        ExecutionContext("engagement", "method-recovery-fixture", 45.0, None,
                         principal_id="consumer:method", execution_profile="observe"),
    ))


def _analysis(request_id: str, subject_id: str, *, conclusion: str, evidence_refs: list[str],
              supporting: list[str], contrary: list[str]) -> dict:
    inconclusive = conclusion == "inconclusive"
    return {
        "schemaVersion": "1.1",
        "requestId": request_id,
        "producer": {"name": "fixture-method", "version": "1.0.0"},
        "evidenceRefs": evidence_refs,
        "entities": {"analyses": [{
            "kind": "candidate",
            "subject": {
                "entityId": subject_id, "url": "https://example.test/items",
                "method": "GET", "parameter": "id", "location": "query",
            },
            "candidateClass": "sqli", "knowledgeState": "reported" if inconclusive else "inferred",
            "confidence": "low" if inconclusive else "medium",
            "reason": "Contrary response makes this inconclusive." if inconclusive else "Parameter shape warrants validation.",
            "supportingEvidenceIds": supporting,
            "contraryEvidenceIds": contrary,
            "methodRef": {"id": "web.sqli.triage", "digest": "sha256:" + ("b" if inconclusive else "a") * 64},
            "modelLabel": "fixture-model",
            "inconclusive": inconclusive,
        }]},
    }


def _method_analysis(
    request_id: str,
    subject_id: str,
    evidence_id: str,
    *,
    candidate_class: str,
    method_id: str,
    method_digest: str,
    reason: str,
    url: str = "https://example.test/items",
) -> dict:
    return {
        "schemaVersion": "1.1",
        "requestId": request_id,
        "producer": {"name": "transition-fixture", "version": "1.0.0"},
        "evidenceRefs": [evidence_id],
        "entities": {"analyses": [{
            "kind": "candidate",
            "subject": {
                "entityId": subject_id,
                "url": url,
                "method": "GET",
            },
            "candidateClass": candidate_class,
            "knowledgeState": "inferred",
            "confidence": "medium",
            "reason": reason,
            "supportingEvidenceIds": [evidence_id],
            "methodRef": {"id": method_id, "digest": f"sha256:{method_digest}"},
        }]},
    }


class ContributionMethodRecoveryTests(unittest.TestCase):
    def test_saved_method_result_survives_optional_package_removal(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                workspace.create_workspace("engagement", hosts=["example.test"])
                registry = ActionRegistry(PassThroughPolicyEvaluator())
                registry.register(REGISTRY.get("workspace.ingest_data"))
                registry.freeze()
                surface = _submit(registry, {
                    "schemaVersion": "1.0",
                    "requestId": "package-removal-surface",
                    "producer": {"name": "package-removal-fixture", "version": "1.0.0"},
                    "entities": {"endpoints": [{
                        "url": "https://example.test/items",
                        "method": "GET",
                    }]},
                })
                self.assertIsInstance(surface, Success)
                receipt = surface.payload.model_dump(mode="json")
                package = next(
                    item for item in guidance.build_guidance_snapshot().packages
                    if item["id"] == "synapse-web-access-control"
                )
                analysis = _submit(registry, _method_analysis(
                    "package-removal-analysis",
                    receipt["canonicalRecordIds"]["endpoints"][0],
                    receipt["evidenceIds"][0],
                    candidate_class="access_control",
                    method_id=package["id"],
                    method_digest=package["sha256"],
                    reason="Saved ownership evidence requires a second actor comparison.",
                ))
                self.assertIsInstance(analysis, Success)

                retained_packages = tuple(
                    item for item in guidance.GUIDANCE_PACKAGES
                    if item.id != "synapse-web-access-control"
                )
                with patch.object(guidance, "GUIDANCE_PACKAGES", retained_packages):
                    self.assertNotIn(
                        "synapse-web-access-control",
                        {item["id"] for item in guidance.build_guidance_snapshot().packages},
                    )
                    context = CompactFacadeService(
                        resources=ResourceReferenceService(state_path=root / "rollback-resources.json")
                    ).invoke(
                        "context.query",
                        {"workspaceId": "engagement", "targets": ["example.test"], "maxTokens": 30_000},
                        context=FacadeCallContext(
                            principal_id="consumer:package-rollback",
                            workspace_id="engagement",
                            authority_session_id="session:package-rollback",
                            execution_profile="observe",
                        ),
                    )
                self.assertEqual(context.outcome_kind, "success")
                recovered = next(
                    item for item in context.result["candidates"]
                    if item.get("attributes", {}).get("sourceAttribution", {}).get("methodRef", {}).get("id")
                    == "synapse-web-access-control"
                )
                self.assertEqual(
                    recovered["attributes"]["sourceAttribution"]["methodRef"]["digest"],
                    f"sha256:{package['sha256']}",
                )
                self.assertIn("second actor comparison", recovered["attributes"]["reason"])

    def test_web_cve_web_method_refs_recover_after_process_restart(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                workspace.create_workspace("engagement", hosts=["example.test"])
                registry = ActionRegistry(PassThroughPolicyEvaluator())
                registry.register(REGISTRY.get("workspace.ingest_data"))
                registry.freeze()

                surface = _submit(registry, {
                    "schemaVersion": "1.0",
                    "requestId": "transition-surface",
                    "producer": {"name": "transition-fixture", "version": "1.0.0"},
                    "entities": {"endpoints": [{
                        "url": "https://example.test/items",
                        "method": "GET",
                        "source": "saved-transition-fixture",
                    }]},
                })
                cve_surface = _submit(registry, {
                    "schemaVersion": "1.0",
                    "requestId": "transition-component-evidence",
                    "producer": {"name": "transition-fixture", "version": "1.0.0"},
                    "entities": {"endpoints": [{
                        "url": "https://example.test/component",
                        "method": "GET",
                        "source": "saved-transition-fixture",
                    }]},
                })
                self.assertIsInstance(surface, Success)
                self.assertIsInstance(cve_surface, Success)
                surface_receipt = surface.payload.model_dump(mode="json")
                cve_surface_receipt = cve_surface.payload.model_dump(mode="json")
                subject_id = surface_receipt["canonicalRecordIds"]["endpoints"][0]
                cve_subject_id = cve_surface_receipt["canonicalRecordIds"]["endpoints"][0]
                evidence_id = surface_receipt["evidenceIds"][0]
                cve_evidence_id = cve_surface_receipt["evidenceIds"][0]
                digests = {
                    package["id"]: package["sha256"]
                    for package in guidance.build_guidance_snapshot().packages
                }

                web_first = _submit(registry, _method_analysis(
                    "transition-web-first",
                    subject_id,
                    evidence_id,
                    candidate_class="configuration",
                    method_id="synapse-web-configuration",
                    method_digest=digests["synapse-web-configuration"],
                    reason="Saved version evidence requires an applicability check.",
                ))
                cve = _submit(registry, _method_analysis(
                    "transition-cve",
                    cve_subject_id,
                    cve_evidence_id,
                    candidate_class="cve_applicability",
                    method_id="synapse-cve-intelligence",
                    method_digest=digests["synapse-cve-intelligence"],
                    reason="The affected feature is absent from the saved deployment evidence.",
                    url="https://example.test/component",
                ))
                web_return = _submit(registry, _method_analysis(
                    "transition-web-return",
                    subject_id,
                    evidence_id,
                    candidate_class="configuration",
                    method_id="synapse-web-configuration",
                    method_digest=digests["synapse-web-configuration"],
                    reason="CVE applicability is unsupported; continue the Web configuration question.",
                ))
                for result in (web_first, cve, web_return):
                    self.assertIsInstance(result, Success)
                first_receipt = web_first.payload.model_dump(mode="json")
                cve_receipt = cve.payload.model_dump(mode="json")
                return_receipt = web_return.payload.model_dump(mode="json")
                self.assertEqual(
                    first_receipt["canonicalRecordIds"]["observations"],
                    return_receipt["canonicalRecordIds"]["observations"],
                )
                self.assertLess(first_receipt["committedRevision"], cve_receipt["committedRevision"])
                self.assertLess(cve_receipt["committedRevision"], return_receipt["committedRevision"])

                fresh_code = """
import json
from pathlib import Path
from synapse_mcp.app.facade import CompactFacadeService, FacadeCallContext, ResourceReferenceService
root = Path(__import__('os').environ['SYNAPSE_ROOT'])
context = CompactFacadeService(resources=ResourceReferenceService(state_path=root / 'transition-resources.json')).invoke(
    'context.query', {'workspaceId': 'engagement', 'targets': ['example.test'], 'maxTokens': 30000},
    context=FacadeCallContext(principal_id='consumer:transition-fresh', workspace_id='engagement',
                              authority_session_id='transition-fresh', execution_profile='observe'))
assert context.outcome_kind == 'success', context.outcome_kind
by_method = {
    item['attributes']['sourceAttribution']['methodRef']['id']: item
    for item in context.result['candidates']
    if 'methodRef' in item.get('attributes', {}).get('sourceAttribution', {})
}
print(json.dumps({'byMethod': by_method, 'workItems': context.result['workItems']}))
"""
                environment = os.environ.copy()
                environment.update({
                    "SYNAPSE_ROOT": str(root),
                    "SYNAPSE_DATA_DIR": str(root),
                    "SYNAPSE_REPORTS_DIR": str(root / "reports"),
                    "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                })
                fresh = subprocess.run(
                    [sys.executable, "-c", fresh_code],
                    cwd=root,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(fresh.returncode, 0, fresh.stderr)
                recovered = json.loads(fresh.stdout)
                self.assertEqual(recovered["workItems"], [])
                web = recovered["byMethod"]["synapse-web-configuration"]
                recovered_cve = recovered["byMethod"]["synapse-cve-intelligence"]
                self.assertEqual(
                    web["attributes"]["sourceAttribution"]["methodRef"]["digest"],
                    f"sha256:{digests['synapse-web-configuration']}",
                )
                self.assertIn("continue the Web configuration question", web["attributes"]["reason"])
                self.assertEqual(
                    recovered_cve["attributes"]["sourceAttribution"]["methodRef"]["digest"],
                    f"sha256:{digests['synapse-cve-intelligence']}",
                )
                self.assertEqual(web["attributes"]["subjectEntityId"], subject_id)
                self.assertEqual(recovered_cve["attributes"]["subjectEntityId"], cve_subject_id)

    def test_candidate_contrary_inconclusive_retry_and_process_restart(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with isolated_state(root, store_version="sqlite-v2"):
                workspace.create_workspace("engagement", hosts=["example.test", "other.example.test"])
                registry = ActionRegistry(PassThroughPolicyEvaluator())
                registry.register(REGISTRY.get("workspace.ingest_data"))
                registry.freeze()

                surface = _submit(registry, {
                    "schemaVersion": "1.0", "requestId": "surface",
                    "producer": {"name": "fixture", "version": "1.0"},
                    "entities": {"endpoints": [{"url": "https://example.test/items", "method": "GET"}]},
                })
                contrary = _submit(registry, {
                    "schemaVersion": "1.0", "requestId": "contrary-evidence",
                    "producer": {"name": "fixture", "version": "1.0"},
                    "entities": {"observations": [{"type": "response_note", "value": "No diagnostic signal"}]},
                })
                self.assertIsInstance(surface, Success)
                self.assertIsInstance(contrary, Success)
                surface_receipt = surface.payload.model_dump(mode="json")
                contrary_receipt = contrary.payload.model_dump(mode="json")
                subject_id = surface_receipt["canonicalRecordIds"]["endpoints"][0]
                supporting_id = surface_receipt["evidenceIds"][0]
                contrary_id = contrary_receipt["evidenceIds"][0]
                imported = json.loads(saved_spec_import.import_spec({
                    "workspaceId": "engagement", "target": "example.test", "ingest": True,
                    "rawData": json.dumps({
                        "openapi": "3.0.0", "info": {"title": "Fictional API", "version": "1"},
                        "paths": {"/documented": {"get": {"responses": {"200": {"description": "ok"}}}}},
                    }),
                }))
                self.assertEqual(imported["endpointCount"], 1)

                proposed = _analysis(
                    "proposed", subject_id, conclusion="proposed",
                    evidence_refs=[supporting_id], supporting=[supporting_id], contrary=[],
                )
                first = _submit(registry, proposed)
                self.assertIsInstance(first, Success)
                first_receipt = first.payload.model_dump(mode="json")
                candidate_row_id = first_receipt["canonicalRecordIds"]["observations"][0]
                candidate = next(
                    item for item in workspace._activated_repository("engagement").collection("example.test", "observations")
                    if item.get("type") == "test_candidate"
                )
                candidate_id = candidate["candidateId"]
                decision = workspace.record_candidate_validation(
                    "engagement", "example.test", {"candidateId": candidate_id},
                    "inconclusive", vuln_class="sqli", reviewer="operator:fixture",
                )
                self.assertEqual(decision["observation"]["candidateDetails"]["sqli"]["validationStatus"], "inconclusive")

                update = _analysis(
                    "inconclusive", subject_id, conclusion="inconclusive",
                    evidence_refs=[supporting_id, contrary_id], supporting=[supporting_id], contrary=[contrary_id],
                )
                update["entities"]["analyses"].append({
                    "kind": "coverage_gap",
                    "subject": {"entityId": subject_id, "url": "https://example.test/items", "method": "GET"},
                    "knowledgeState": "reported", "confidence": "low",
                    "reason": "A second response profile is not covered.", "inconclusive": True,
                    "contraryEvidenceIds": [contrary_id],
                })
                second = _submit(registry, update)
                self.assertIsInstance(second, Success)
                receipt = second.payload.model_dump(mode="json")
                self.assertEqual(receipt["schemaVersion"], "1.1")
                self.assertEqual(receipt["insertedCounts"]["observations"], 1)
                self.assertEqual(receipt["updatedCounts"]["observations"], 1)
                self.assertGreater(receipt["committedRevision"], first_receipt["committedRevision"])
                self.assertIn(candidate_row_id, receipt["canonicalRecordIds"]["observations"])
                self.assertEqual(len(receipt["canonicalRecordIds"]["observations"]), 2)
                repository = workspace._activated_repository("engagement")
                observations = repository.collection("example.test", "observations")
                candidate = next(item for item in observations if item.get("candidateId") == candidate_id)
                gap = next(item for item in observations if item.get("type") == "analysis_coverage_gap")
                self.assertEqual(candidate["analysisConclusion"], "inconclusive")
                self.assertEqual(candidate["reason"], "[sqli] Contrary response makes this inconclusive.")
                self.assertEqual(candidate["candidateDetails"]["sqli"]["validationStatus"], "inconclusive")
                self.assertEqual(candidate["methodRef"]["digest"], "sha256:" + "b" * 64)
                self.assertEqual(candidate["subjectEntityId"], subject_id)
                self.assertTrue({supporting_id, first_receipt["evidenceIds"][0], receipt["evidenceIds"][0]}.issubset(candidate["evidenceIds"]))
                self.assertEqual(candidate["contraryEvidenceIds"], [contrary_id])
                self.assertEqual(gap["analysisConclusion"], "inconclusive")

                replay = _submit(registry, update)
                self.assertIsInstance(replay, Success)
                self.assertEqual(replay.payload.model_dump(mode="json"), receipt)
                changed_payload = json.loads(json.dumps(update))
                changed_payload["entities"]["analyses"][0]["reason"] = "Conflicting retry"
                self.assertIn("contribution_request_conflict", _submit(registry, changed_payload).message)

                other = _submit(registry, {
                    "schemaVersion": "1.0", "requestId": "other-subject",
                    "producer": {"name": "fixture", "version": "1.0"},
                    "entities": {"endpoints": [{"url": "https://other.example.test/items", "method": "GET"}]},
                }, target="other.example.test")
                self.assertIsInstance(other, Success)
                other_id = other.payload.model_dump(mode="json")["canonicalRecordIds"]["endpoints"][0]
                cross_target = _analysis(
                    "cross-target", other_id, conclusion="proposed",
                    evidence_refs=[supporting_id], supporting=[supporting_id], contrary=[],
                )
                self.assertIn("contribution_subject_ref_invalid", _submit(registry, cross_target).message)
                mismatch = _analysis(
                    "mismatch", subject_id, conclusion="proposed",
                    evidence_refs=[supporting_id], supporting=[supporting_id], contrary=[],
                )
                mismatch["entities"]["analyses"][0]["subject"]["url"] = "https://example.test/different"
                self.assertIn("contribution_subject_ref_mismatch", _submit(registry, mismatch).message)
                self.assertEqual(repository.revision(), other.payload.model_dump(mode="json")["committedRevision"])

                report = documentation.build_report_context({
                    "workspaceId": "engagement", "target": "example.test", "redactionMode": "internal",
                })["report"]
                self.assertEqual(report["findings"], [])
                pending = report["targets"][0]["pendingObservations"]
                report_candidate = next(item for item in pending if item.get("candidateId") == candidate_id)
                report_gap = next(item for item in pending if item.get("type") == "analysis_coverage_gap")
                self.assertEqual(report_candidate["knowledgeState"], "reported")
                self.assertEqual(report_candidate["analysisConclusion"], "inconclusive")
                self.assertEqual(report_candidate["methodRef"]["id"], "web.sqli.triage")
                self.assertEqual(report_gap["knowledgeState"], "reported")

                fresh_code = """
import json
from pathlib import Path
from synapse_mcp.app.facade import CompactFacadeService, FacadeCallContext, ResourceReferenceService
from synapse_mcp.core import documentation
root = Path(__import__('os').environ['SYNAPSE_ROOT'])
context = CompactFacadeService(resources=ResourceReferenceService(state_path=root / 'fresh-resources.json')).invoke(
    'context.query', {'workspaceId': 'engagement', 'targets': ['example.test'], 'maxTokens': 30000},
    context=FacadeCallContext(principal_id='consumer:fresh', workspace_id='engagement',
                              authority_session_id='fresh-session', execution_profile='observe'))
assert context.outcome_kind == 'success', context.outcome_kind
candidate = next(item for item in context.result['candidates'] if item['kind'] == 'test_candidate')
gap = next(item for item in context.result['coverageGaps'] if item['kind'] == 'analysis_coverage_gap')
documented = next(item for item in context.result['confirmedFacts']
                  if item.get('attributes', {}).get('url') == 'https://example.test/documented')
report = documentation.build_report_context({'workspaceId': 'engagement', 'target': 'example.test',
                                             'redactionMode': 'internal'})['report']
pending = report['targets'][0]['pendingObservations']
print(json.dumps({'candidate': candidate, 'gap': gap, 'documented': documented, 'reportCandidate':
    next(item for item in pending if item.get('type') == 'test_candidate')}))
"""
                environment = os.environ.copy()
                environment.update({
                    "SYNAPSE_ROOT": str(root), "SYNAPSE_DATA_DIR": str(root),
                    "SYNAPSE_REPORTS_DIR": str(root / "reports"),
                    "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
                })
                fresh = subprocess.run(
                    [sys.executable, "-c", fresh_code], cwd=root, env=environment,
                    capture_output=True, text=True, timeout=20, check=False,
                )
                self.assertEqual(fresh.returncode, 0, fresh.stderr)
                recovered = json.loads(fresh.stdout)
                self.assertEqual(recovered["candidate"]["attributes"]["knowledgeState"], "reported")
                self.assertEqual(recovered["candidate"]["attributes"]["analysisConclusion"], "inconclusive")
                self.assertEqual(recovered["candidate"]["attributes"]["subjectEntityId"], subject_id)
                self.assertEqual(recovered["candidate"]["attributes"]["contraryEvidenceReferences"], [contrary_id])
                self.assertEqual(recovered["gap"]["attributes"]["analysisConclusion"], "inconclusive")
                self.assertEqual(recovered["documented"]["attributes"]["knowledgeState"], "documented")
                self.assertEqual(recovered["reportCandidate"]["methodRef"]["digest"], "sha256:" + "b" * 64)

                suppressed = workspace.set_entity_reportable(
                    "engagement", "example.test", "observations", {"candidateId": candidate_id},
                    False, reason="Operator withheld this candidate from reports.", reviewer="operator:fixture",
                )
                self.assertEqual(suppressed["matched"], 1)
                post_review = _analysis(
                    "post-review", subject_id, conclusion="inconclusive",
                    evidence_refs=[supporting_id, contrary_id], supporting=[supporting_id], contrary=[contrary_id],
                )
                post_review["entities"]["analyses"][0]["reason"] = "A later method run remains inconclusive."
                self.assertIsInstance(_submit(registry, post_review), Success)
                candidate = next(
                    item for item in repository.collection("example.test", "observations")
                    if item.get("candidateId") == candidate_id
                )
                self.assertFalse(candidate["isReportable"])
                self.assertEqual(candidate["candidateDetails"]["sqli"]["validationStatus"], "inconclusive")


if __name__ == "__main__":
    unittest.main()
