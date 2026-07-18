import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from urllib.parse import urlsplit

import httpx

from helpers import isolated_state
from http_stub import stub_httpx
from synapse_mcp.adapters.web import access_control
from synapse_mcp.core import credentials, scope, workspace
from synapse_mcp.core.http import compare_http_responses
from synapse_mcp.core.http.models import HttpResponse
from synapse_mcp.transport import stdio_server


class AccessControlAdapterTests(unittest.TestCase):
    def test_access_control_reads_canonical_target_model(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["example.com"])
                canonical_dir = workspace.target_model_dir("engagement", "example.com", "access-control")
                workspace._write_json(canonical_dir / "objects.json", [{"objectId": "canonical_user", "objectType": "user"}])

                items = access_control.read_access_control_items("engagement", "example.com", "objects")

                self.assertEqual(items[0]["objectId"], "canonical_user")

    def test_access_control_requires_privileged_semantics_for_api_collections(self) -> None:
        surfaces = access_control.extract_object_surfaces(
            {
                "endpoints": [
                    {
                        "url": "GET https://example.com/api/Users",
                        "method": "GET",
                        "statusCodes": [200],
                        "contentTypes": ["application/json"],
                    },
                    {
                        "url": "https://example.com/rest/basket/1",
                        "method": "GET",
                        "statusCodes": [200],
                        "contentTypes": ["application/json"],
                    },
                    {
                        "url": "https://example.com/assets/public/images/uploads/default.svg",
                        "method": "GET",
                        "statusCodes": [200],
                        "contentTypes": ["image/svg+xml"],
                    },
                ],
                "parameters": [],
                "observations": [],
            }
        )
        objects = [item for item in surfaces if item["isReportable"]]
        classifications = [item for item in surfaces if not item["isReportable"]]

        object_keys = {(item["endpointPattern"], item["objectType"], item["testClass"]) for item in objects}
        self.assertNotIn(("/api/Users", "user", "BFLA"), object_keys)
        self.assertTrue(any(item["endpointPattern"] == "/api/Users" and item["classification"] == "public_or_unqualified_collection" for item in classifications))
        self.assertIn(("/rest/basket/{basket_id}", "basket", "BOLA"), object_keys)
        self.assertFalse(any("default.svg" in item["url"] for item in surfaces))

    def test_access_control_suppresses_framework_public_and_dependency_404_surfaces(self) -> None:
        comment_url = "https://example.com/comment"
        dependency_url = "https://example.com/api/users/"
        protected_url = "https://example.com/api/orders/123"
        entities = {
            "endpoints": [
                {
                    "type": "endpoint",
                    "url": comment_url,
                    "method": "POST",
                    "statusCodes": [200],
                    "contentTypes": ["text/html"],
                    "source": "crawler",
                    "observed": True,
                },
                {
                    "type": "endpoint",
                    "url": dependency_url,
                    "method": "GET",
                    "statusCodes": [404],
                    "contentTypes": ["application/json"],
                    "source": "js_intelligence",
                    "sourceAsset": "https://example.com/vendor/ui-router-1.0.10.js",
                    "derived": True,
                    "inferred": True,
                },
                {
                    "type": "endpoint",
                    "url": protected_url,
                    "method": "GET",
                    "statusCodes": [200],
                    "contentTypes": ["application/json"],
                    "cookieNames": ["SESSIONID"],
                    "source": "js_intelligence",
                    "sourceAsset": "https://example.com/assets/app.js",
                    "derived": True,
                    "observedRequests": [{"method": "GET", "status": 200}],
                },
            ],
            "parameters": [
                {"type": "parameter", "name": name, "url": comment_url, "method": "POST", "location": "form", "valuePreview": value}
                for name, value in (
                    ("form_build_id", "form-abc"),
                    ("form_id", "comment_form"),
                    ("comment_post_ID", "42"),
                    ("category_id", "7"),
                    ("newsletter_id", "4"),
                    ("contract_type", "public"),
                    ("procedure_filter", "open"),
                )
            ],
            "observations": [
                {
                    "type": "access_control_object_candidate",
                    "objectId": "legacy_dependency_object",
                    "value": "/api/users",
                    "url": dependency_url,
                    "method": "GET",
                    "priority": "high",
                    "priorityScore": 85,
                    "isReportable": True,
                },
                {
                    "type": "access_control_test_candidate",
                    "matrixId": "legacy_dependency_matrix",
                    "value": "/api/users",
                    "method": "GET",
                    "priority": "high",
                    "priorityScore": 85,
                    "isReportable": True,
                },
            ],
        }

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["example.com"])
                workspace.ingest_data(
                    "engagement",
                    "example.com",
                    "adapter_result",
                    "passive_analysis",
                    "json",
                    json.dumps({"entities": entities}),
                )

                identified = json.loads(access_control.identify_objects({"workspaceId": "engagement", "target": "example.com"}))
                self.assertEqual(identified["objectCount"], 1)
                self.assertEqual(identified["objects"][0]["endpointPattern"], "/api/orders/{order_id}")
                self.assertEqual(identified["objects"][0]["objectType"], "order")
                self.assertEqual(identified["objects"][0]["sourceQuality"], "first_party")
                self.assertTrue(identified["objects"][0]["isReportable"])

                classifications = identified["classifications"]
                classified_names = {item["identifierName"] for item in classifications}
                self.assertTrue({"form_build_id", "form_id", "comment_post_id", "category_id", "newsletter_id", "contract_type", "procedure_filter"}.issubset(classified_names))
                dependency = next(item for item in classifications if item["url"] == dependency_url)
                self.assertEqual(dependency["reachability"], "refuted_not_found")
                self.assertEqual(dependency["sourceQuality"], "dependency")
                self.assertIn("observed_consistent_404_410", dependency["suppressionReasons"])
                self.assertEqual(access_control.endpoint_reachability({"statusCodes": [404, 200]}), "observed_reachable")

                matrix = json.loads(
                    access_control.build_test_matrix(
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "contexts": [
                                {"contextId": "owner", "role": "user", "authState": "authenticated", "credentialId": "owner-cred"},
                                {"contextId": "peer", "role": "user", "authState": "authenticated", "credentialId": "peer-cred"},
                            ],
                        }
                    )
                )
                self.assertEqual(matrix["matrixCount"], 1)
                self.assertEqual(matrix["matrix"][0]["endpointPattern"], "/api/orders/{order_id}")
                stored_objects = access_control.read_access_control_items("engagement", "example.com", "objects")
                self.assertEqual([item["endpointPattern"] for item in stored_objects], ["/api/orders/{order_id}"])
                stored_observations = workspace._load_target_entities("engagement", "example.com")["observations"]
                legacy = [item for item in stored_observations if str(item.get("matrixId") or item.get("objectId", "")).startswith("legacy_dependency")]
                self.assertEqual(len(legacy), 2)
                self.assertTrue(all(item["isReportable"] is False and item["analysisEligible"] is False for item in legacy))

    def test_access_control_identifies_objects_records_contexts_and_builds_matrix(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                raw = json.dumps(
                    {
                        "hosts": [
                            {
                                "host": "example.com",
                                "urls": [
                                    {
                                        "url": "https://example.com/api/users/123",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                        "contentTypes": ["application/json"],
                                        "cookieNames": ["SESSIONID"],
                                    },
                                    {
                                        "url": "https://example.com/api/accounts?account_id=456",
                                        "methods": ["GET"],
                                        "statusCodes": [200],
                                        "contentTypes": ["application/json"],
                                        "cookieNames": ["SESSIONID"],
                                    },
                                    {
                                        "url": "https://example.com/api/tenants?tenant_id=789",
                                        "methods": ["PATCH"],
                                        "statusCodes": [200],
                                        "contentTypes": ["application/json"],
                                        "cookieNames": ["SESSIONID"],
                                        "stateChanging": True,
                                    },
                                    {
                                        "url": "https://example.com/admin/users/delete?user_id=123",
                                        "methods": ["POST"],
                                        "statusCodes": [200],
                                        "contentTypes": ["application/json"],
                                        "bodyParameters": ["user_id", "role"],
                                        "cookieNames": ["SESSIONID"],
                                        "stateChanging": True,
                                    },
                                ],
                            }
                        ],
                        "summary": {"hostCount": 1},
                    }
                )
                workspace.ingest_data("engagement", "example.com", "sitemap", "tool_output", "json", raw)

                caps = json.loads(stdio_server.call_tool("access_control.capabilities", {}))
                self.assertEqual(caps["name"], "access_control")
                self.assertTrue(caps["sendsTraffic"])
                self.assertTrue(caps["requiresConfirmation"])

                objects = json.loads(access_control.identify_objects({"workspaceId": "engagement", "target": "example.com"}))
                self.assertGreaterEqual(objects["objectCount"], 3)
                object_types = {item["objectType"] for item in objects["objects"]}
                self.assertIn("user", object_types)
                self.assertIn("account", object_types)
                self.assertTrue(all("identifierValue" not in item for item in objects["objects"]))

                access_dir = workspace.target_path("engagement", "example.com") / "models" / "access-control"
                self.assertTrue((access_dir / "objects.json").exists())

                access_control.record_context(
                    {
                        "workspaceId": "engagement",
                        "target": "example.com",
                        "contextId": "user_a",
                        "label": "User A",
                        "role": "user",
                        "credentialId": "cred-user-a",
                        "ownedObjectTypes": ["user", "account"],
                    }
                )
                access_control.record_context(
                    {
                        "workspaceId": "engagement",
                        "target": "example.com",
                        "contextId": "admin",
                        "label": "Admin",
                        "role": "admin",
                        "credentialId": "cred-admin",
                    }
                )

                matrix = json.loads(access_control.build_test_matrix({"workspaceId": "engagement", "target": "example.com"}))
                self.assertGreaterEqual(matrix["matrixCount"], 2)
                classes = {item["testClass"] for item in matrix["matrix"]}
                self.assertIn("BOLA", classes)
                self.assertIn("BOPLA", classes)
                self.assertIn("BFLA", classes)
                self.assertTrue((access_dir / "contexts.json").exists())
                self.assertTrue((access_dir / "matrix.json").exists())

                plan = json.loads(access_control.plan_tests({"matrixEntry": matrix["matrix"][0]}))
                self.assertTrue(plan["requiresConfirmation"])
                self.assertEqual(plan["comparisonHelper"], "synapse_mcp.core.http.compare.compare_http_responses")

                context = workspace.prepare_target_context("engagement", "example.com")
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("access_control_object_candidate", observation_types)
                self.assertIn("access_control_test_candidate", observation_types)

    def test_access_control_matrix_prefers_authenticated_peers_for_bola(self) -> None:
        objects = [
            {
                "objectId": "obj_order",
                "objectType": "order",
                "method": "GET",
                "endpointPattern": "/rest/order-history/{orderId}",
                "identifierName": "orderId",
                "location": "path",
                "testClass": "BOLA",
                "priority": "high",
            }
        ]
        contexts = [
            {"contextId": "anon", "label": "Anonymous", "role": "anonymous", "authState": "anonymous"},
            {"contextId": "tester1", "label": "Tester 1", "role": "user", "authState": "authenticated", "credentialId": "cred-1"},
            {"contextId": "tester3", "label": "Tester 3", "role": "user", "authState": "authenticated", "credentialId": "cred-3"},
        ]

        matrix = access_control.create_matrix(objects, contexts)

        self.assertEqual(matrix[0]["requiredContexts"], ["tester1", "tester3"])

    def test_access_control_matrix_preserves_available_contexts_and_emits_gaps(self) -> None:
        objects = [
            {
                "objectId": "obj_order",
                "objectType": "order",
                "method": "GET",
                "endpointPattern": "/api/orders/{order_id}",
                "identifierName": "order_id",
                "identifierValueShape": "numeric",
                "location": "path",
                "testClass": "BOLA",
                "priority": "high",
            }
        ]
        anonymous_matrix, anonymous_gaps = access_control.create_matrix_plan(
            objects,
            [{"contextId": "rtbit-anonymous", "role": "anonymous", "authState": "anonymous"}],
        )
        self.assertEqual(len(anonymous_matrix), 1)
        self.assertEqual(anonymous_matrix[0]["testClass"], "ANONYMOUS_BASELINE")
        self.assertEqual(anonymous_matrix[0]["requiredContexts"], ["rtbit-anonymous"])
        self.assertEqual(len(anonymous_gaps), 1)
        self.assertEqual(anonymous_gaps[0]["missingContextRoles"], ["two_authenticated_peers"])

        one_matrix, one_gaps = access_control.create_matrix_plan(
            objects,
            [{"contextId": "only-user", "role": "user", "authState": "authenticated", "credentialId": "cred-only"}],
        )
        self.assertEqual(one_matrix, [])
        self.assertEqual(one_gaps[0]["availableContextIds"], ["only-user"])

        peer_matrix, peer_gaps = access_control.create_matrix_plan(
            objects,
            [
                {"contextId": "alice", "role": "user", "authState": "authenticated", "credentialId": "cred-alice"},
                {"contextId": "bob", "role": "user", "authState": "authenticated", "credentialId": "cred-bob"},
            ],
        )
        self.assertEqual(peer_gaps, [])
        self.assertEqual(peer_matrix[0]["requiredContexts"], ["alice", "bob"])
        serialized = json.dumps(anonymous_matrix + anonymous_gaps + one_matrix + one_gaps + peer_matrix)
        self.assertNotIn("user_a", serialized)
        self.assertNotIn("user_b", serialized)
        self.assertNotIn("standard_user", serialized)

    def test_access_control_build_matrix_persists_anonymous_baseline_and_blocked_gap(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["example.com"])
                access_control.replace_access_control_items(
                    "engagement",
                    "example.com",
                    "objects",
                    [
                        {
                            "objectId": "obj_order",
                            "objectType": "order",
                            "method": "GET",
                            "endpointPattern": "/api/orders/{order_id}",
                            "identifierName": "order_id",
                            "identifierValueShape": "numeric",
                            "location": "path",
                            "testClass": "BOLA",
                            "priority": "high",
                            "isReportable": True,
                        }
                    ],
                    "objectId",
                )
                result = json.loads(
                    access_control.build_test_matrix(
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "refreshObjects": False,
                            "contexts": [{"contextId": "rtbit-anonymous", "role": "anonymous", "authState": "anonymous"}],
                            "ingest": True,
                        }
                    )
                )

                self.assertEqual(result["matrixCount"], 1)
                self.assertEqual(result["matrix"][0]["requiredContexts"], ["rtbit-anonymous"])
                self.assertEqual(result["matrix"][0]["testClass"], "ANONYMOUS_BASELINE")
                self.assertEqual(result["coverageGapCount"], 1)
                self.assertTrue(result["coverageGaps"][0]["blocked"])
                self.assertEqual(result["coverageGaps"][0]["availableContextIds"], ["rtbit-anonymous"])
                self.assertTrue((workspace.target_model_dir("engagement", "example.com", "access-control") / "coverage-gaps.json").exists())

                with self.assertRaisesRegex(Exception, "Blocked access-control coverage gaps are not executable"):
                    access_control.execute_matrix_test(
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "matrixEntry": result["coverageGaps"][0],
                            "confirm": True,
                        }
                    )
                with self.assertRaisesRegex(Exception, "missing matrix-required context IDs"):
                    access_control.resolve_replay_contexts(
                        {"contexts": [{"contextId": "different-anonymous", "role": "anonymous"}]},
                        "engagement",
                        "example.com",
                        result["matrix"][0],
                    )

    def test_access_control_execute_matrix_test_replays_contexts_with_approval(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            cookie = request.headers.get("cookie", "")
            if "USERA=1" in cookie or "USERB=1" in cookie:
                return httpx.Response(200, json={"user_id": 123, "email": "owner@example.com", "role": "user"})
            return httpx.Response(403, text='{"error":"denied"}', headers={"content-type": "application/json"})

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                base = "http://app.acme-demo.test"
                target = f"{base}/api/users/123"
                scope.save_scope([base], "test", "Example Client")
                credentials.save_credential({"id": "user-a", "type": "cookie", "scopes": ["app.acme-demo.test"], "secret": "USERA=1"})
                credentials.save_credential({"id": "user-b", "type": "cookie", "scopes": ["app.acme-demo.test"], "secret": "USERB=1"})

                args = {
                    "workspaceId": "engagement",
                    "target": "app.acme-demo.test",
                    "matrixEntry": {
                        "matrixId": "acm_test",
                        "endpointPattern": "/api/users/{user_id}",
                        "method": "GET",
                        "objectType": "user",
                        "testClass": "BOLA",
                    },
                    "requestUrl": target,
                    "contexts": [
                        {"contextId": "user_a", "credentialId": "user-a", "expectedAccess": True},
                        {"contextId": "user_b", "credentialId": "user-b", "expectedAccess": False},
                    ],
                }
                with self.assertRaisesRegex(Exception, "confirm=true"):
                    access_control.execute_matrix_test({**args, "confirm": False})

                with stub_httpx(handler):
                    result = json.loads(
                        access_control.execute_matrix_test(
                            {
                                **args,
                                "confirm": True,
                                "approvalReason": "unit test approved cross-context BOLA replay",
                                "riskTier": "medium",
                            }
                        )
                    )

                self.assertEqual(result["replay"]["assessment"], "possible_broken_access_control")
                self.assertEqual(result["replay"]["comparisons"][0]["signalsPossibleBrokenAccessControl"], True)
                self.assertTrue((workspace.target_path("engagement", "app.acme-demo.test") / "models" / "access-control" / "replays.json").exists())
                serialized = json.dumps(result)
                self.assertNotIn("USERA=1", serialized)
                self.assertNotIn("USERB=1", serialized)
                self.assertNotIn("owner@example.com", serialized)
                allowed_exchange = Path(result["replay"]["replays"][0]["exchangeEvidence"]["rawPath"])
                self.assertTrue(allowed_exchange.exists())
                allowed_raw = allowed_exchange.read_text(encoding="utf-8")
                self.assertIn('"Cookie": "<redacted>"', allowed_raw)
                self.assertNotIn("USERA=1", allowed_raw)
                self.assertIn("owner@example.com", allowed_raw)
                context = workspace.prepare_target_context("engagement", "app.acme-demo.test")
                observation_types = {item["type"] for item in context["observations"]}
                self.assertIn("possible_broken_access_control", observation_types)
                self.assertGreaterEqual(len(context["recentActions"]), 1)

    def test_access_control_replay_records_under_request_host(self) -> None:
        def fake_send(_request, *, policy):
            return HttpResponse(status=200, headers={"content-type": "application/json"}, body='{"ok":true}')

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["app.example.com", "api.example.com"])
                with patch.object(access_control.http_client, "send", side_effect=fake_send):
                    result = json.loads(
                        access_control.execute_matrix_test(
                            {
                                "workspaceId": "engagement",
                                "target": "app.example.com",
                                "matrixEntry": {
                                    "matrixId": "acm_cross_host",
                                    "endpointPattern": "/api/users/{user_id}",
                                    "method": "GET",
                                "objectType": "user",
                                    "testClass": "ANONYMOUS_BASELINE",
                                },
                                "requestUrl": "https://api.example.com/api/users/123",
                                "contexts": [{"contextId": "anonymous", "role": "anonymous", "expectedAccess": False}],
                                "confirm": True,
                                "approvalReason": "unit test approved cross-host attribution check",
                                "riskTier": "low",
                            }
                        )
                    )

                self.assertEqual(result["replay"]["host"], "api.example.com")
                self.assertEqual(result["replay"]["modelHost"], "app.example.com")
                self.assertEqual(result["action"]["action"]["modelHost"], "app.example.com")
                self.assertTrue((workspace.target_path("engagement", "api.example.com") / "models" / "access-control" / "replays.json").exists())
                self.assertFalse((workspace.target_path("engagement", "app.example.com") / "models" / "access-control" / "replays.json").exists())

    def test_access_control_post_replay_ids_include_body_identity(self) -> None:
        def fake_send(_request, *, policy):
            return HttpResponse(status=200, headers={"content-type": "application/json"}, body='{"ok":true,"data":{"id":1}}')

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["example.com"])
                scope.save_scope(["https://example.com"], "test", "Example Client")
                credentials.save_credential({"id": "high-cred", "type": "cookie", "scopes": ["example.com"], "secret": "HIGH=1"})
                credentials.save_credential({"id": "normal-cred", "type": "cookie", "scopes": ["example.com"], "secret": "NORMAL=1"})
                base_args = {
                    "workspaceId": "engagement",
                    "target": "example.com",
                    "matrixEntry": {
                        "endpointPattern": "/api/Sicas",
                        "method": "POST",
                        "objectType": "rpc",
                        "testClass": "BFLA",
                    },
                    "requestUrl": "https://example.com/api/Sicas",
                    "allowStateChanging": True,
                    "contexts": [
                        {"contextId": "high", "role": "admin", "credentialId": "high-cred", "expectedAccess": True},
                        {"contextId": "normal", "role": "user", "credentialId": "normal-cred", "expectedAccess": False},
                    ],
                    "confirm": True,
                    "approvalReason": "unit test approved POST replay identity check",
                    "riskTier": "medium",
                }
                with patch.object(access_control.http_client, "send", side_effect=fake_send):
                    first = json.loads(access_control.execute_matrix_test({**base_args, "jsonBody": {"rpc": "OFE"}}))
                    second = json.loads(access_control.execute_matrix_test({**base_args, "jsonBody": {"rpc": "CONSULTAR", "action": "consulta"}}))

                self.assertNotEqual(first["replay"]["replayId"], second["replay"]["replayId"])
                self.assertNotEqual(first["replay"]["requestFingerprint"], second["replay"]["requestFingerprint"])
                replays = access_control.read_access_control_items("engagement", "example.com", "replays")
                self.assertEqual(len(replays), 2)
                self.assertEqual({item["requestFingerprint"] for item in replays}, {first["replay"]["requestFingerprint"], second["replay"]["requestFingerprint"]})

    def test_access_control_replay_downgrades_identical_error_shaped_json(self) -> None:
        def fake_send(_request, *, policy):
            return HttpResponse(
                status=200,
                headers={"content-type": "application/json"},
                body='{"CAM_ERR":"missing field","message":"missing required field"}',
            )

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["example.com"])
                scope.save_scope(["https://example.com"], "test", "Example Client")
                credentials.save_credential({"id": "high-cred", "type": "cookie", "scopes": ["example.com"], "secret": "HIGH=1"})
                credentials.save_credential({"id": "normal-cred", "type": "cookie", "scopes": ["example.com"], "secret": "NORMAL=1"})
                with patch.object(access_control.http_client, "send", side_effect=fake_send):
                    result = json.loads(
                        access_control.execute_matrix_test(
                            {
                                "workspaceId": "engagement",
                                "target": "example.com",
                                "matrixEntry": {
                                    "matrixId": "acm_error_shape",
                                    "endpointPattern": "/api/Sicas",
                                    "method": "GET",
                                    "objectType": "rpc",
                                    "testClass": "BFLA",
                                },
                                "requestUrl": "https://example.com/api/Sicas",
                                "contexts": [
                                    {"contextId": "high", "role": "admin", "credentialId": "high-cred", "expectedAccess": True},
                                    {"contextId": "normal", "role": "user", "credentialId": "normal-cred", "expectedAccess": False},
                                ],
                                "confirm": True,
                                "approvalReason": "unit test approved error-shaped response check",
                                "riskTier": "low",
                            }
                        )
                    )

                comparison = result["replay"]["comparisons"][0]
                self.assertEqual(result["replay"]["assessment"], "inconclusive")
                self.assertNotIn("downgradeReason", comparison)
                self.assertTrue(comparison["comparison"]["bodyIdentical"])
                self.assertEqual(comparison["comparison"]["sensitiveMarkersA"], [])
                self.assertFalse(comparison["signalsPossibleBrokenAccessControl"])
                self.assertTrue(comparison["responseSemantics"]["errorShapedJson"])
                self.assertFalse(comparison["responseSemantics"]["dataBearingJson"])
                context = workspace.prepare_target_context("engagement", "example.com")
                observation_types = {item["type"] for item in context["observations"]}
                self.assertNotIn("possible_broken_access_control", observation_types)

    def test_access_control_replay_clamps_request_timeout_to_remaining_budget(self) -> None:
        seen_timeouts: list[float] = []

        def fake_send(_request, *, policy):
            seen_timeouts.append(policy.timeout_seconds)
            return HttpResponse(status=200, headers={"content-type": "application/json"}, body='{"ok":true}')

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["example.com"])
                with patch.object(access_control.http_client, "send", side_effect=fake_send):
                    result = json.loads(
                        access_control.execute_matrix_test(
                            {
                                "workspaceId": "engagement",
                                "target": "example.com",
                                "matrixEntry": {
                                    "matrixId": "acm_budget",
                                    "endpointPattern": "/api/users/{user_id}",
                                    "method": "GET",
                                    "objectType": "user",
                                    "testClass": "ANONYMOUS_BASELINE",
                                },
                                "requestUrl": "https://example.com/api/users/123",
                                "contexts": [{"contextId": "anonymous", "role": "anonymous", "expectedAccess": False}],
                                "confirm": True,
                                "approvalReason": "unit test approved budget clamp",
                                "riskTier": "low",
                                "requestTimeout": 60,
                                "totalBudgetSeconds": 0.5,
                            }
                        )
                    )

                self.assertEqual(result["replay"]["budgetSeconds"], 0.5)
                self.assertEqual(len(seen_timeouts), 1)
                self.assertLessEqual(seen_timeouts[0], 0.5)

    def test_access_control_replay_without_valid_credentials_fails_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                base = "http://127.0.0.1:9"
                scope.save_scope([base], "test", "Example Client")
                with self.assertRaisesRegex(Exception, "separate context explicitly marked anonymous"):
                    access_control.execute_matrix_test(
                        {
                            "workspaceId": "engagement",
                            "target": "127.0.0.1",
                            "matrixEntry": {
                                "matrixId": "acm_anon",
                                "endpointPattern": "/api/users/{user_id}",
                                "method": "GET",
                                "objectType": "user",
                                "testClass": "BOLA",
                            },
                            "requestUrl": f"{base}/api/users/123",
                            "contexts": [
                                {"contextId": "missing", "expectedAccess": True},
                                {"contextId": "invalid", "credentialId": "does-not-exist", "expectedAccess": False},
                            ],
                            "confirm": True,
                            "approvalReason": "unit test strict default",
                            "riskTier": "low",
                        }
                    )

    def test_access_control_replay_never_downgrades_missing_credentials_to_anonymous(self) -> None:
        seen_cookies: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_cookies.append(request.headers.get("cookie", ""))
            return httpx.Response(200, text='{"public":true}', headers={"content-type": "application/json"})

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                base = "http://app.acme-demo.test"
                target = f"{base}/api/users/123"
                scope.save_scope([base], "test", "Example Client")

                with stub_httpx(handler), self.assertRaisesRegex(Exception, "never downgraded|separate context explicitly marked anonymous"):
                    access_control.execute_matrix_test(
                        {
                            "workspaceId": "engagement",
                            "target": "app.acme-demo.test",
                            "matrixEntry": {
                                "matrixId": "acm_anon",
                                "endpointPattern": "/api/users/{user_id}",
                                "method": "GET",
                                "objectType": "user",
                                "testClass": "BOLA",
                            },
                            "requestUrl": target,
                            "allowAnonymousContexts": True,
                            "contexts": [
                                {"contextId": "missing", "expectedAccess": True},
                                {"contextId": "invalid", "credentialId": "does-not-exist", "expectedAccess": False},
                            ],
                            "confirm": True,
                            "approvalReason": "unit test verifies anonymous downgrade is forbidden",
                            "riskTier": "low",
                        }
                    )

                self.assertEqual(seen_cookies, [])

    def test_access_control_explicit_anonymous_baseline_replays_without_credentials(self) -> None:
        seen_cookies: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_cookies.append(request.headers.get("cookie", ""))
            return httpx.Response(403, text='{"error":"denied"}', headers={"content-type": "application/json"})

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                base = "http://app.acme-demo.test"
                target = f"{base}/api/users/123"
                scope.save_scope([base], "test", "Example Client")
                with stub_httpx(handler):
                    result = json.loads(
                        access_control.execute_matrix_test(
                            {
                                "workspaceId": "engagement",
                                "target": "app.acme-demo.test",
                                "matrixEntry": {
                                    "matrixId": "acm_anonymous_baseline",
                                    "endpointPattern": "/api/users/{user_id}",
                                    "method": "GET",
                                    "objectType": "user",
                                    "testClass": "ANONYMOUS_BASELINE",
                                    "requiredContexts": ["rtbit-anonymous"],
                                },
                                "requestUrl": target,
                                "contexts": [{"contextId": "rtbit-anonymous", "role": "anonymous", "authState": "anonymous"}],
                                "confirm": True,
                                "approvalReason": "unit test approved explicit anonymous baseline",
                                "riskTier": "low",
                            }
                        )
                    )

                self.assertEqual(seen_cookies, [""])
                contexts = result["replay"]["contexts"]
                self.assertEqual([item["authState"] for item in contexts], ["anonymous"])
                self.assertTrue(all(item["allowAnonymous"] for item in contexts))
                self.assertEqual([item["credentialId"] for item in contexts], [""])
                self.assertIn("explicitly", contexts[0]["anonymousReason"])
                self.assertTrue(all("Cookie" not in replay["requestHeaders"] for replay in result["replay"]["replays"]))

    def test_resolve_replay_contexts_requires_credentials_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                with self.assertRaisesRegex(Exception, "no credentialId"):
                    access_control.resolve_replay_contexts(
                        {"contexts": [{"contextId": "user_b", "expectedAccess": True}]},
                        "engagement",
                        "127.0.0.1",
                        {"requiredContexts": []},
                    )

    def test_resolve_replay_contexts_allows_explicit_anonymous(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                contexts = access_control.resolve_replay_contexts(
                    {"contexts": [{"contextId": "anon", "role": "anonymous"}]},
                    "engagement",
                    "127.0.0.1",
                    {"requiredContexts": []},
                )
                self.assertTrue(contexts[0]["allowAnonymous"])
                self.assertEqual(contexts[0]["authState"], "anonymous")

    def test_resolve_replay_contexts_global_anonymous_flag_cannot_downgrade_role(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                with self.assertRaisesRegex(Exception, "separate context explicitly marked anonymous"):
                    access_control.resolve_replay_contexts(
                        {"contexts": [{"contextId": "missing", "expectedAccess": True}], "allowAnonymousContexts": True},
                        "engagement",
                        "127.0.0.1",
                        {"requiredContexts": []},
                    )

    def test_prepare_replay_context_auth_invalid_credential_never_downgrades(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                with self.assertRaisesRegex(Exception, "could not be resolved"):
                    access_control.prepare_replay_context_auth(
                        {"contextId": "user_b", "credentialId": "does-not-exist"},
                        "http://127.0.0.1/api/users/123",
                    )
                with self.assertRaisesRegex(Exception, "never downgraded"):
                    access_control.prepare_replay_context_auth(
                        {"contextId": "user_b", "credentialId": "does-not-exist"},
                        "http://127.0.0.1/api/users/123",
                        allow_anonymous=True,
                    )

    def test_build_replay_request_blocks_secret_bearing_headers(self) -> None:
        for header in ("X-Api-Key", "X-Auth-Token", "X-Session-Id", "X-CSRF-Token"):
            with self.assertRaisesRegex(Exception, "secret-bearing headers"):
                access_control.build_replay_request(
                    "http://127.0.0.1/api/users/123",
                    "GET",
                    "",
                    extra_headers={header: "value"},
                )
        # Benign headers are allowed through.
        built = access_control.build_replay_request(
            "http://127.0.0.1/api/users/123",
            "GET",
            "",
            extra_headers={"Accept": "application/json", "Origin": "http://127.0.0.1"},
        )
        self.assertEqual(built["headers"]["Accept"], "application/json")
        self.assertTrue(built["headers"]["User-Agent"].startswith("Synapse-MCP/"))

    def test_is_success_response_treats_only_2xx_as_success(self) -> None:
        for status in (200, 201, 204, 299):
            self.assertTrue(access_control.is_success_response({"status": status}), status)
        for status in (301, 302, 303, 304, 307, 308, 401, 403, 404, 500):
            self.assertFalse(access_control.is_success_response({"status": status}), status)
        self.assertFalse(access_control.is_success_response({"status": None}))
        self.assertFalse(access_control.is_success_response({}))

    def test_access_control_replay_redirect_to_login_is_not_access_granted(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            path = urlsplit(str(request.url)).path
            if path.startswith("/login"):
                return httpx.Response(200, text="login page", headers={"content-type": "text/html"})
            if "USERA=1" in request.headers.get("cookie", ""):
                return httpx.Response(200, headers={"content-type": "application/json"})
            return httpx.Response(302, headers={"location": "/login"})

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                base = "http://app.acme-demo.test"
                target = f"{base}/api/users/123"
                scope.save_scope([base], "test", "Example Client")
                credentials.save_credential({"id": "user-a", "type": "cookie", "scopes": ["app.acme-demo.test"], "secret": "USERA=1"})
                credentials.save_credential({"id": "user-b", "type": "cookie", "scopes": ["app.acme-demo.test"], "secret": "USERB=1"})

                with stub_httpx(handler):
                    result = json.loads(
                        access_control.execute_matrix_test(
                            {
                                "workspaceId": "engagement",
                                "target": "app.acme-demo.test",
                                "matrixEntry": {
                                    "matrixId": "acm_redirect",
                                    "endpointPattern": "/api/users/{user_id}",
                                    "method": "GET",
                                    "objectType": "user",
                                    "testClass": "BOLA",
                                },
                                "requestUrl": target,
                                "contexts": [
                                    {"contextId": "user_a", "credentialId": "user-a", "expectedAccess": True},
                                    {"contextId": "user_b", "credentialId": "user-b", "expectedAccess": False},
                                ],
                                "confirm": True,
                                "approvalReason": "unit test approved redirect-denial replay",
                                "riskTier": "low",
                            }
                        )
                    )

                # Both responses have identical empty bodies, so only the
                # status classification separates granted from denied here.
                denied_replay = result["replay"]["replays"][1]
                self.assertEqual(denied_replay["response"]["status"], 302)
                self.assertEqual(result["replay"]["assessment"], "inconclusive")
                self.assertFalse(result["replay"]["comparisons"][0]["signalsPossibleBrokenAccessControl"])

    def test_resolve_replay_contexts_baseline_is_identity_derived_not_positional(self) -> None:
        # Contract 3.5: the allowed/denied baseline must come from identity, never from array
        # position. Two authenticated peers on an object-level (BOLA) test have no asserted
        # ownership differential, so neither is fabricated as the "allowed" baseline.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                bola = access_control.resolve_replay_contexts(
                    {
                        "contexts": [
                            {"contextId": "tester1", "role": "user", "authState": "authenticated", "credentialId": "c1"},
                            {"contextId": "tester3", "role": "user", "authState": "authenticated", "credentialId": "c3"},
                        ]
                    },
                    "engagement",
                    "127.0.0.1",
                    {"testClass": "BOLA", "requiredContexts": []},
                )
                self.assertEqual([item["expectedAccess"] for item in bola], [None, None])

                # Function-level (BFLA) access is privilege-derived: the privileged role is the
                # allowed baseline, the non-privileged role is expected to be denied.
                bfla = access_control.resolve_replay_contexts(
                    {
                        "contexts": [
                            {"contextId": "admin", "role": "admin", "authState": "authenticated", "credentialId": "ca"},
                            {"contextId": "normal", "role": "user", "authState": "authenticated", "credentialId": "cn"},
                        ]
                    },
                    "engagement",
                    "127.0.0.1",
                    {"testClass": "BFLA", "requiredContexts": []},
                )
                self.assertEqual({item["contextId"]: item["expectedAccess"] for item in bfla}, {"admin": True, "normal": False})

    def test_bfla_without_privileged_context_is_blocked_before_traffic(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["https://example.com"], "test", "Example Client")
                credentials.save_credential({"id": "normal-cred", "type": "cookie", "scopes": ["example.com"], "secret": "NORMAL=1"})
                send = patch.object(
                    access_control.http_client,
                    "send",
                    return_value=HttpResponse(status=200, headers={"content-type": "application/json"}, body='{"ok":true}'),
                )
                with send as mocked_send, self.assertRaisesRegex(Exception, "no privileged authenticated context"):
                    access_control.execute_matrix_test(
                        {
                            "workspaceId": "engagement",
                            "target": "example.com",
                            "matrixEntry": {
                                "matrixId": "acm_bfla_unassessable",
                                "endpointPattern": "/admin",
                                "method": "GET",
                                "objectType": "function",
                                "testClass": "BFLA",
                            },
                            "requestUrl": "https://example.com/admin",
                            "contexts": [
                                {"contextId": "normal", "role": "user", "authState": "authenticated", "credentialId": "normal-cred"},
                                {"contextId": "anon", "role": "anonymous", "authState": "anonymous"},
                            ],
                            "confirm": True,
                            "approvalReason": "unit test verifies incomplete BFLA is blocked",
                            "riskTier": "low",
                        }
                    )
                mocked_send.assert_not_called()

    def test_compare_reports_body_identity(self) -> None:
        identical = compare_http_responses({"status": 200, "body": '{"a":1}'}, {"status": 200, "body": '{"a":1}'})
        different = compare_http_responses({"status": 200, "body": '{"a":1}'}, {"status": 200, "body": '{"a":2}'})

        self.assertTrue(identical["bodyIdentical"])
        self.assertFalse(different["bodyIdentical"])

    def test_self_scoped_distinct_values_not_flagged(self) -> None:
        authed_a = {
            "context": {"contextId": "tester1", "role": "user", "authState": "authenticated", "credentialId": "c1"},
            "response": {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"user": {"email": "tester1@dotmail.test", "id": 21}}),
            },
        }
        authed_b = {
            "context": {"contextId": "tester2", "role": "user", "authState": "authenticated", "credentialId": "c2"},
            "response": {
                "status": 200,
                "headers": {"content-type": "application/json"},
                "body": json.dumps({"user": {"email": "tester2@dotmail.test", "id": 22}}),
            },
        }
        matrix = {"testClass": "BOLA"}
        comparison = compare_http_responses(authed_a["response"], authed_b["response"])

        self.assertFalse(comparison["bodyIdentical"])
        self.assertEqual(comparison["sensitiveMarkersA"], comparison["sensitiveMarkersB"])
        self.assertTrue(access_control.responses_carry_distinct_identity(comparison))
        self.assertEqual(access_control.peer_access_signal(authed_a, authed_b, comparison, matrix), "")

    def test_shared_sensitive_object_flagged(self) -> None:
        body = json.dumps({"status": "success", "data": {"id": 1, "email": "admin@juice-sh.op", "role": "admin"}})
        authed_a = {
            "context": {"contextId": "tester1", "role": "user", "authState": "authenticated", "credentialId": "c1"},
            "response": {"status": 200, "headers": {"content-type": "application/json"}, "body": body},
        }
        authed_b = {
            "context": {"contextId": "tester2", "role": "user", "authState": "authenticated", "credentialId": "c2"},
            "response": {"status": 200, "headers": {"content-type": "application/json"}, "body": body},
        }
        comparison = compare_http_responses(authed_a["response"], authed_b["response"])

        self.assertTrue(comparison["bodyIdentical"])
        self.assertIn("email", comparison["sensitiveMarkersA"])
        self.assertFalse(access_control.responses_carry_distinct_identity(comparison))
        self.assertTrue(access_control.peer_access_signal(authed_a, authed_b, comparison, {"testClass": "BOLA"}))

    def test_identical_nonsensitive_body_not_flagged(self) -> None:
        body = json.dumps({"status": "success", "data": []})
        authed_a = {
            "context": {"contextId": "tester1", "role": "user", "authState": "authenticated", "credentialId": "c1"},
            "response": {"status": 200, "headers": {"content-type": "application/json"}, "body": body},
        }
        authed_b = {
            "context": {"contextId": "tester2", "role": "user", "authState": "authenticated", "credentialId": "c2"},
            "response": {"status": 200, "headers": {"content-type": "application/json"}, "body": body},
        }
        comparison = compare_http_responses(authed_a["response"], authed_b["response"])

        self.assertTrue(comparison["bodyIdentical"])
        self.assertEqual(comparison["sensitiveMarkersA"], [])
        self.assertTrue(access_control.responses_carry_distinct_identity(comparison))
        self.assertEqual(access_control.peer_access_signal(authed_a, authed_b, comparison, {"testClass": "BOLA"}), "")

    def test_apply_json_substitutions_uses_explicit_recursion_semantics(self) -> None:
        self.assertEqual(
            access_control.apply_json_substitutions({"data": {"user_id": 123}}, {"user_id": 456}),
            {"data": {"user_id": 456}},
        )
        self.assertEqual(
            access_control.apply_json_substitutions({"user_id": 123, "data": {"owner_id": 999}}, {"user_id": 456}),
            {"user_id": 456, "data": {"owner_id": 999}},
        )
        self.assertEqual(
            access_control.apply_json_substitutions([{"user_id": 1}, 2], {"user_id": 456}),
            [{"user_id": 456}, 2],
        )
        # A replacement value is inserted verbatim; it is not re-substituted.
        self.assertEqual(
            access_control.apply_json_substitutions(
                {"profile": {"anything": 1}},
                {"profile": {"user_id": 111}, "user_id": 456},
            ),
            {"profile": {"user_id": 111}},
        )

    def test_response_compare_uses_metadata_similarity_and_json_key_overlap(self) -> None:
        result = compare_http_responses(
            {
                "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"id": 1, "name": "Alice"}),
            },
            {
                "status": 200,
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"id": 2, "name": "Bob", "email": "bob@example.com", "role": "admin"}),
            },
        )

        self.assertFalse(result["statusDelta"])
        self.assertEqual(result["contentTypeDelta"], False)
        self.assertLess(result["jsonKeyOverlap"], 1)
        self.assertIn("email", result["sensitiveMarkersB"])
        self.assertTrue(any("additional JSON key" in item for item in result["interestingDifferences"]))



if __name__ == "__main__":
    unittest.main()
