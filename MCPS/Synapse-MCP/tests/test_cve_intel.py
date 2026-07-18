import json
import os
import subprocess
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch
from urllib import parse

from helpers import isolated_state
from synapse_mcp.adapters.web import cve_intel
from synapse_mcp.core import scope, workspace
from synapse_mcp.core.adapters import default_registry
from synapse_mcp.core.errors import McpError
from synapse_mcp.core.http.models import HttpResponse
from synapse_mcp.transport import stdio_server


def seed_component(version_precision: str = "exact") -> None:
    workspace.create_workspace("engagement", organization="Example", hosts=["app.example.com"])
    workspace.ingest_data(
        "engagement",
        "app.example.com",
        "adapter_result",
        "adapter_result",
        "json",
        json.dumps(
            {
                "entities": {
                    "observations": [
                        {
                            "type": "technology_component",
                            "value": "Apache httpd 2.4.49",
                            "name": "Apache httpd",
                            "version": "2.4.49",
                            "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                            "versionPrecision": version_precision,
                            "confidence": "high",
                        }
                    ]
                }
            }
        ),
    )


def nvd_record() -> dict[str, object]:
    return {
        "cveId": "CVE-2021-41773",
        "cvss": 7.5,
        "severity": "high",
        "summary": "Apache path traversal.",
        "references": [{"source": "nvd", "url": "https://nvd.example/CVE-2021-41773", "tags": []}],
        "exploitReferences": [],
        "publishedDate": "2021-10-05T00:00:00.000",
        "component": "Apache httpd",
        "version": "2.4.49",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "versionPrecision": "exact",
        "source": "nvd",
        "discoverySources": ["nvd"],
    }


def seed_named_component(name: str, *, version: str = "", cpe: str = "", precision: str = "unknown", source: str = "") -> None:
    workspace.create_workspace("engagement", organization="Example", hosts=["app.example.com"])
    workspace.ingest_data(
        "engagement",
        "app.example.com",
        "adapter_result",
        "adapter_result",
        "json",
        json.dumps(
            {
                "entities": {
                    "observations": [
                        {
                            "type": "technology_component",
                            "value": f"{name} {version}".strip(),
                            "name": name,
                            "version": version,
                            "cpe": cpe,
                            "versionPrecision": precision,
                            "source": source,
                            "confidence": "high",
                        }
                    ]
                }
            }
        ),
    )


def seed_target_components(target: str, components: list[dict[str, str]]) -> None:
    workspace.ensure_workspace("engagement", organization="Example")
    workspace.add_target("engagement", target)
    workspace.ingest_data(
        "engagement",
        target,
        "adapter_result",
        "adapter_result",
        "json",
        json.dumps(
            {
                "entities": {
                    "observations": [
                        {
                            "type": "technology_component",
                            "value": f"{component['name']} {component['version']}",
                            "name": component["name"],
                            "version": component["version"],
                            "cpe": component["cpe"],
                            "versionPrecision": "exact",
                            "confidence": "high",
                        }
                        for component in components
                    ]
                }
            }
        ),
    )


def add_deployment_context(target: str, value: str) -> None:
    workspace.ingest_data(
        "engagement",
        target,
        "adapter_result",
        "adapter_result",
        "json",
        json.dumps(
            {
                "entities": {
                    "observations": [
                        {
                            "type": "deployment_context",
                            "value": value,
                            "reason": f"Observed deployment context: {value}",
                            "confidence": "high",
                        }
                    ]
                }
            }
        ),
    )


def nvd_config(product: str, *, vendor: str = "vendor", cpe_version: str = "*", **bounds: str) -> list[dict[str, object]]:
    match: dict[str, object] = {"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:{product}:{cpe_version}:*:*:*:*:*:*:*"}
    match.update(bounds)
    return [{"nodes": [{"cpeMatch": [match]}]}]


def nvd_item(
    cve_id: str,
    configurations: list[dict[str, object]],
    *,
    base_score: float = 7.5,
    references: list[dict[str, object]] | None = None,
    cwe: str = "CWE-89",
    attack_vector: str = "NETWORK",
) -> dict[str, object]:
    cvss_data: dict[str, object] = {"baseScore": base_score, "baseSeverity": "HIGH", "attackVector": attack_vector}
    weaknesses = [{"description": [{"lang": "en", "value": cwe}]}] if cwe else []
    return {
        "cve": {
            "id": cve_id,
            "published": "2021-10-05T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "desc"}],
            "metrics": {"cvssMetricV31": [{"cvssData": cvss_data}]},
            "weaknesses": weaknesses,
            "references": references or [],
            "configurations": configurations,
        }
    }


def nvd_payload(cve_id: str, configurations: list[dict[str, object]], **kwargs: object) -> dict[str, object]:
    return {"vulnerabilities": [nvd_item(cve_id, configurations, **kwargs)]}


class FakeSession:
    def __init__(self, response: HttpResponse):
        self.response = response
        self.requests = []

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def send(self, request):
        self.requests.append(request)
        return self.response


class CveIntelTests(unittest.TestCase):
    def setUp(self) -> None:
        cve_intel._ENDPOINT_OVERRIDES.clear()
        cve_intel._SESSION_KEYS.clear()
        cve_intel._LAST_SOURCE_STATUS.clear()
        cve_intel._LAST_FETCH_CONTEXT.clear()

    def test_correlate_requires_confirm(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                with patch.object(cve_intel, "_discover_nvd", return_value=[]) as discover:
                    with self.assertRaisesRegex(McpError, "confirm=true"):
                        cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd"]})
                discover.assert_not_called()

    def test_correlate_merges_discovery_and_enrichment(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                with patch.object(cve_intel, "_discover_nvd", return_value=[nvd_record()]), patch.object(
                    cve_intel,
                    "_enrich_cisa_kev",
                    return_value={"CVE-2021-41773": {"knownExploited": True, "source": "cisa_kev"}},
                ), patch.object(
                    cve_intel,
                    "_enrich_poc_github_index",
                    return_value={
                        "CVE-2021-41773": {
                            "pocReferences": [
                                {"source": "poc_github_index", "url": "https://github.example/poc-one", "stars": 10},
                                {"source": "poc_github_index", "url": "https://github.example/poc-two", "stars": 3},
                            ],
                            "source": "poc_github_index",
                        }
                    },
                ):
                    first = json.loads(
                        cve_intel.correlate(
                            {
                                "workspaceId": "engagement",
                                "target": "app.example.com",
                                "sources": ["nvd", "cisa_kev", "poc_github_index"],
                                "confirm": True,
                            }
                        )
                    )
                    cve_intel.correlate(
                        {
                            "workspaceId": "engagement",
                            "target": "app.example.com",
                            "sources": ["nvd", "cisa_kev", "poc_github_index"],
                            "confirm": True,
                        }
                    )

                self.assertEqual(first["candidateCount"], 1)
                candidate = first["candidates"][0]
                self.assertEqual(candidate["confidence"], "high")
                self.assertTrue(candidate["knownExploited"])
                self.assertEqual(candidate["exploitMaturity"], "in_the_wild")
                self.assertEqual(candidate["priority"], "critical")
                self.assertEqual(candidate["pocCount"], 2)
                observations = workspace._load_target_entities("engagement", "app.example.com")["observations"]
                cve_candidates = [item for item in observations if item.get("type") == "cve_candidate"]
                self.assertEqual(len(cve_candidates), 1)
                self.assertEqual(cve_candidates[0]["candidateId"], "cve_CVE-2021-41773_apache-httpd_2.4.49")

    def test_discover_nvd_parses_2_0_reference_list_exploit_tags(self) -> None:
        # Exercises the real _discover_nvd/_references_from_nvd path (not stubbed) against the
        # NVD 2.0 schema, where cve.references is a list (not the 1.0 references.referenceData
        # dict). An Exploit-tagged reference must surface and drive exploitMaturity.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                nvd_response = {
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2021-41773",
                                "published": "2021-10-05T00:00:00.000",
                                "descriptions": [{"lang": "en", "value": "Apache path traversal."}],
                                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH", "attackVector": "NETWORK"}}]},
                                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
                                "configurations": nvd_config("http_server", vendor="apache", cpe_version="2.4.49"),
                                "references": [
                                    {"url": "https://exploit.example/poc", "tags": ["Exploit"]},
                                    {"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]},
                                ],
                            }
                        }
                    ]
                }
                with patch.object(cve_intel, "_fetch_nvd", return_value=nvd_response), patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate(
                            {
                                "workspaceId": "engagement",
                                "target": "app.example.com",
                                "sources": ["nvd", "cisa_kev", "poc_github_index"],
                                "confirm": True,
                            }
                        )
                    )
                candidate = result["candidates"][0]
                self.assertEqual(candidate["cvssScore"], 7.5)
                exploit_urls = [ref.get("url") for ref in candidate["exploitReferences"]]
                self.assertIn("https://exploit.example/poc", exploit_urls)
                self.assertNotIn("https://vendor.example/advisory", exploit_urls)
                self.assertEqual(candidate["exploitMaturity"], "exploit_referenced")

    def test_out_of_range_version_is_dropped(self) -> None:
        # Apache httpd 2.4.49 detected; a CVE that only affects < 2.4.0 must be filtered out.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                payload = nvd_payload("CVE-2000-1234", nvd_config("http_server", vendor="apache", versionEndExcluding="2.4.0"))
                with patch.object(cve_intel, "_fetch_nvd", return_value=payload), patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True})
                    )
                self.assertEqual(result["candidateCount"], 0)
                self.assertEqual(result["filtered"]["notAffected"], 1)

    def test_in_range_version_is_kept_high_confidence(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                payload = nvd_payload(
                    "CVE-2021-41773",
                    nvd_config("http_server", vendor="apache", versionStartIncluding="2.4.0", versionEndExcluding="2.4.50"),
                )
                with patch.object(cve_intel, "_fetch_nvd", return_value=payload), patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True})
                    )
                self.assertEqual(result["candidateCount"], 1)
                self.assertEqual(result["candidates"][0]["confidence"], "high")
                self.assertEqual(result["candidates"][0]["versionPrecision"], "exact")

    def test_product_mismatch_is_dropped(self) -> None:
        # Keyword search surfaces a CVE whose only affected product is a different package.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                payload = nvd_payload("CVE-2022-9999", nvd_config("some_plugin", vendor="thirdparty"))
                with patch.object(cve_intel, "_fetch_nvd", return_value=payload), patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True})
                    )
                self.assertEqual(result["candidateCount"], 0)
                self.assertEqual(result["filtered"]["productMismatch"], 1)

    def test_version_unknown_skips_nvd_by_default_and_emits_gap(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_named_component("Drupal")
                with patch.object(cve_intel, "_fetch_nvd") as fetch_nvd:
                    result = json.loads(
                        cve_intel.correlate(
                            {
                                "workspaceId": "engagement",
                                "target": "app.example.com",
                                "sources": ["nvd", "cisa_kev", "poc_github_index"],
                                "confirm": True,
                            }
                        )
                    )

                fetch_nvd.assert_not_called()
                self.assertEqual(result["candidateCount"], 0)
                self.assertEqual(result["filtered"]["versionUnknownSkipped"], 1)
                self.assertEqual(result["gaps"][0]["type"], "cve_version_precision_gap")
                self.assertEqual(result["gaps"][0]["component"], "Drupal")

    def test_version_unknown_opt_in_keeps_only_corroborated_candidates(self) -> None:
        # A broad version-unknown lookup is explicit. Even then, a high CVSS score does not
        # establish applicability; KEV/PoC/exploit corroboration is required.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_named_component("Drupal")
                payload = {
                    "vulnerabilities": [
                        nvd_item("CVE-2014-1111", nvd_config("drupal", vendor="drupal"), base_score=4.0),  # low sev, no corroboration -> suppressed
                        nvd_item("CVE-2019-2222", nvd_config("drupal", vendor="drupal"), base_score=9.8),  # high sev alone -> suppressed
                        nvd_item("CVE-2018-7600", nvd_config("drupal", vendor="drupal"), base_score=3.0),  # low sev but KEV -> kept
                    ]
                }
                with patch.object(cve_intel, "_fetch_nvd", return_value=payload), patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={"CVE-2018-7600": {"knownExploited": True, "source": "cisa_kev"}}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate(
                            {
                                "workspaceId": "engagement",
                                "target": "app.example.com",
                                "sources": ["nvd", "cisa_kev", "poc_github_index"],
                                "includeVersionUnknown": True,
                                "confirm": True,
                            }
                        )
                    )
                kept = {candidate["cveId"] for candidate in result["candidates"]}
                self.assertEqual(kept, {"CVE-2018-7600"})
                self.assertEqual(result["filtered"]["unconfirmedSuppressed"], 2)
                self.assertTrue(all(candidate["webExploitable"] for candidate in result["candidates"]))

    def test_correlation_caps_and_sorts_candidate_output(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                records = []
                for index, score in enumerate((4.0, 9.8, 7.5, 5.0, 8.2), start=1):
                    record = dict(nvd_record())
                    record["cveId"] = f"CVE-2026-{index:04d}"
                    record["cvss"] = score
                    record["applicability"] = "affected"
                    records.append(record)
                with patch.object(cve_intel, "_discover_nvd", return_value=records):
                    result = json.loads(
                        cve_intel.correlate(
                            {
                                "workspaceId": "engagement",
                                "target": "app.example.com",
                                "sources": ["nvd"],
                                "maxCandidates": 2,
                                "confirm": True,
                            }
                        )
                    )

                self.assertEqual(result["candidateCount"], 2)
                self.assertEqual(result["filtered"]["candidateLimitSuppressed"], 3)
                self.assertEqual(
                    [candidate["cveId"] for candidate in result["candidates"]],
                    ["CVE-2026-0002", "CVE-2026-0005"],
                )

    def test_correlation_reconciles_successful_snapshots_without_losing_history(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                first_record = {**nvd_record(), "applicability": "affected"}
                second_record = {
                    **nvd_record(),
                    "cveId": "CVE-2026-9999",
                    "applicability": "affected",
                }
                args = {
                    "workspaceId": "engagement",
                    "target": "app.example.com",
                    "sources": ["nvd"],
                    "confirm": True,
                }

                with patch.object(cve_intel, "_discover_nvd", return_value=[first_record, second_record]):
                    first = json.loads(cve_intel.correlate(args))
                self.assertEqual(first["candidateCount"], 2)

                with patch.object(cve_intel, "_discover_nvd", side_effect=RuntimeError("provider unavailable")):
                    failed_refresh = json.loads(cve_intel.correlate(args))
                self.assertEqual(failed_refresh["reconciliation"]["retiredCount"], 0)
                self.assertEqual(failed_refresh["reconciliation"]["protectedCount"], 2)

                with patch.object(cve_intel, "_discover_nvd", return_value=[first_record]):
                    reduced = json.loads(cve_intel.correlate(args))
                self.assertEqual(reduced["reconciliation"]["retiredCount"], 1)
                observations = workspace._load_target_entities("engagement", "app.example.com")["observations"]
                stale = next(item for item in observations if item.get("value") == "CVE-2026-9999")
                self.assertTrue(stale["stale"])
                self.assertTrue(stale["retired"])
                self.assertFalse(stale["isReportable"])
                self.assertFalse(stale["analysisEligible"])
                context = workspace.prepare_target_context("engagement", "app.example.com")
                self.assertFalse(any(item.get("value") == "CVE-2026-9999" for item in context["candidateFindings"]))
                self.assertGreaterEqual(context["observationInventory"]["suppressed"], 1)

                with patch.object(cve_intel, "_discover_nvd", return_value=[first_record, second_record]):
                    restored = json.loads(cve_intel.correlate(args))
                self.assertEqual(restored["reconciliation"]["revivedCount"], 1)
                observations = workspace._load_target_entities("engagement", "app.example.com")["observations"]
                revived = next(item for item in observations if item.get("value") == "CVE-2026-9999")
                self.assertFalse(revived["stale"])
                self.assertFalse(revived["retired"])
                self.assertTrue(revived["isReportable"])
                self.assertTrue(revived["analysisEligible"])

    def test_provider_cache_rate_limit_pause_and_resume_are_shared_across_targets(self) -> None:
        components = [
            {
                "name": "Apache httpd",
                "version": "2.4.49",
                "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
            },
            {
                "name": "nginx",
                "version": "1.20.0",
                "cpe": "cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*",
            },
            {
                "name": "Drupal",
                "version": "10.0.0",
                "cpe": "cpe:2.3:a:drupal:drupal:10.0.0:*:*:*:*:*:*:*",
            },
        ]
        provider_records = {
            "http_server": ("apache", "2.4.49", "CVE-2021-41773"),
            "nginx": ("nginx", "1.20.0", "CVE-2022-10001"),
            "drupal": ("drupal", "10.0.0", "CVE-2023-10002"),
        }

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_target_components("app.example.com", components[:2])
                calls: dict[str, int] = {}

                def fake_provider(request, *, policy):
                    del policy
                    query = parse.parse_qs(parse.urlsplit(request.url).query)
                    cpe = query.get("cpeName", [""])[0]
                    fields = cpe.split(":")
                    product = fields[4] if len(fields) > 5 else ""
                    calls[product] = calls.get(product, 0) + 1
                    if product == "drupal" and calls[product] == 1:
                        return HttpResponse(status=429, headers={"Retry-After": "0.03"}, body="small provider window")
                    vendor, version, cve_id = provider_records[product]
                    return HttpResponse(
                        status=200,
                        headers={},
                        body=json.dumps(nvd_payload(cve_id, nvd_config(product, vendor=vendor, cpe_version=version))),
                    )

                args = {
                    "workspaceId": "engagement",
                    "target": "app.example.com",
                    "sources": ["nvd"],
                    "confirm": True,
                    "providerRateLimitCapacity": 100,
                    "providerRateLimitWindowSeconds": 1,
                    "providerMaxAttempts": 1,
                    "providerMaxWaitSeconds": 1,
                    "providerBackoffBaseSeconds": 0.01,
                    "providerBackoffJitterSeconds": 0,
                }
                with patch.object(cve_intel.http_client, "send", side_effect=fake_provider):
                    initial = json.loads(cve_intel.correlate(args))
                    self.assertEqual(initial["candidateCount"], 2)
                    self.assertEqual(initial["sourceStatus"]["nvd"]["networkRequestCount"], 2)

                    seed_target_components("app.example.com", components)
                    paused = json.loads(cve_intel.correlate(args))
                    paused_status = paused["sourceStatus"]["nvd"]
                    self.assertEqual(paused_status["status"], "rate_limited")
                    self.assertGreaterEqual(paused_status["cacheHitCount"], 1)
                    self.assertEqual(paused_status["networkRequestCount"], 1)
                    self.assertEqual(paused_status["attempt"], 1)
                    self.assertEqual(paused_status["maxAttempts"], 1)
                    self.assertGreaterEqual(paused_status["retryAfterSeconds"], 0.03)
                    self.assertGreaterEqual(paused_status["remainingDelaySeconds"], 0.03)
                    self.assertEqual(paused["reconciliation"]["retiredCount"], 0)
                    self.assertEqual(paused["reconciliation"]["protectedCount"], 2)
                    stored = workspace._load_target_entities("engagement", "app.example.com")["observations"]
                    self.assertTrue(all(not item.get("retired") for item in stored if item.get("type") == "cve_candidate"))

                    resumed_at = time.monotonic()
                    resumed = json.loads(cve_intel.correlate(args))
                    self.assertGreaterEqual(time.monotonic() - resumed_at, 0.02)
                    self.assertEqual(resumed["sourceStatus"]["nvd"]["status"], "ok")
                    self.assertEqual(resumed["sourceStatus"]["nvd"]["cacheHitCount"], 2)
                    self.assertEqual(resumed["sourceStatus"]["nvd"]["networkRequestCount"], 1)
                    self.assertEqual(resumed["candidateCount"], 3)

                    seed_target_components("mirror.example.com", components)
                    mirror = json.loads(cve_intel.correlate({**args, "target": "mirror.example.com"}))
                    self.assertEqual(mirror["candidateCount"], 3)
                    self.assertEqual(mirror["sourceStatus"]["nvd"]["cacheHitCount"], 3)
                    self.assertEqual(mirror["sourceStatus"]["nvd"]["networkRequestCount"], 0)

                self.assertEqual(calls, {"http_server": 1, "nginx": 1, "drupal": 2})
                cache_files = list((Path(tmp) / "cache" / "cve-intelligence" / "responses" / "nvd").glob("*.json"))
                self.assertEqual(len(cache_files), 3)
                mirror_evidence = list(workspace.target_path("engagement", "mirror.example.com").glob("evidence/*cve_nvd_raw.json"))
                self.assertEqual(len(mirror_evidence), 3)

    def test_candidates_retain_exact_per_query_source_results(self) -> None:
        components = [
            {
                "name": "PHP",
                "version": "8.1.0",
                "cpe": "cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*",
            },
            {
                "name": "jQuery",
                "version": "3.6.0",
                "cpe": "cpe:2.3:a:jquery:jquery:3.6.0:*:*:*:*:*:*:*",
            },
            {
                "name": "jQuery UI",
                "version": "1.13.0",
                "cpe": "cpe:2.3:a:jquery:jquery_ui:1.13.0:*:*:*:*:*:*:*",
            },
        ]
        provider_records = {
            "php": ("php", "8.1.0", "CVE-2024-10001"),
            "jquery": ("jquery", "3.6.0", "CVE-2024-10002"),
            "jquery_ui": ("jquery", "1.13.0", "CVE-2024-10003"),
        }

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_target_components("app.example.com", components)

                def fake_provider(request, *, policy):
                    del policy
                    query = parse.parse_qs(parse.urlsplit(request.url).query)
                    cpe = query["cpeName"][0]
                    fields = cpe.split(":")
                    product = fields[4]
                    vendor, version, cve_id = provider_records[product]
                    return HttpResponse(
                        status=200,
                        headers={},
                        body=json.dumps(nvd_payload(cve_id, nvd_config(product, vendor=vendor, cpe_version=version), cwe="CWE-79")),
                    )

                with patch.object(cve_intel.http_client, "send", side_effect=fake_provider):
                    result = json.loads(
                        cve_intel.correlate(
                            {
                                "workspaceId": "engagement",
                                "target": "app.example.com",
                                "sources": ["nvd"],
                                "confirm": True,
                                "providerRateLimitCapacity": 100,
                                "providerRateLimitWindowSeconds": 1,
                            }
                        )
                    )

                self.assertEqual(result["candidateCount"], 3)
                self.assertEqual(len(result["sourceResults"]), 3)
                aggregate_url = result["sourceStatus"]["nvd"]["url"]
                candidate_urls = []
                for candidate in result["candidates"]:
                    self.assertNotIn("sourceStatus", candidate)
                    self.assertEqual(len(candidate["sourceResults"]), 1)
                    source_result = candidate["sourceResults"][0]
                    candidate_urls.append(source_result["url"])
                    self.assertEqual(source_result["source"], "nvd")
                    self.assertEqual(source_result["httpStatus"], 200)
                    self.assertEqual(source_result["query"]["cpeName"], candidate["cpe"])
                    self.assertEqual(parse.parse_qs(parse.urlsplit(source_result["url"]).query)["cpeName"][0], candidate["cpe"])
                    self.assertIn(source_result["sourceResultId"], candidate["sourceResultIds"])
                    self.assertIn(source_result["evidenceId"], candidate["evidenceIds"])
                    evidence_meta = workspace._read_json(
                        workspace.target_path("engagement", "app.example.com") / "evidence" / f"{source_result['evidenceId']}.json",
                        {},
                    )
                    self.assertEqual(evidence_meta["metadata"]["queryHash"], source_result["queryHash"])
                    self.assertEqual(evidence_meta["metadata"]["query"]["cpeName"], candidate["cpe"])
                self.assertEqual(len(set(candidate_urls)), 3)
                self.assertTrue(any(url != aggregate_url for url in candidate_urls))

    def test_php_cve_prerequisites_refute_satisfy_or_gap_by_deployment(self) -> None:
        php_component = {
            "name": "PHP",
            "version": "8.1.0",
            "cpe": "cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*",
        }
        configuration = [
            {
                "nodes": [
                    {
                        "operator": "AND",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*",
                            },
                        ],
                    }
                ]
            }
        ]
        payload = nvd_payload("CVE-2024-4577", configuration, cwe="CWE-78")
        payload["vulnerabilities"][0]["cve"]["descriptions"] = [
            {
                "lang": "en",
                "value": "PHP-CGI on Windows with Apache is affected when an affected Best-Fit code page controls request decoding.",
            }
        ]

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                contexts = {
                    "linux.example.com": "Red Hat Enterprise Linux; Apache; PHP-CGI; Best-Fit code page 950",
                    "windows.example.com": "Microsoft Windows Server 2022; Apache; PHP-CGI; Best-Fit code page 950",
                    "unknown.example.com": "PHP 8.1.0",
                }
                for target, context in contexts.items():
                    seed_target_components(target, [php_component])
                    if target != "unknown.example.com":
                        add_deployment_context(target, context)

                results = {}
                with patch.object(cve_intel, "_fetch_nvd", return_value=payload):
                    for target in contexts:
                        results[target] = json.loads(
                            cve_intel.correlate(
                                {
                                    "workspaceId": "engagement",
                                    "target": target,
                                    "sources": ["nvd"],
                                    "confirm": True,
                                }
                            )
                        )

                linux = results["linux.example.com"]
                self.assertEqual(linux["candidateCount"], 0)
                self.assertEqual(linux["refutedCandidateCount"], 1)
                linux_candidate = linux["refutedCandidates"][0]
                self.assertEqual(linux_candidate["versionApplicability"], "affected")
                self.assertEqual(linux_candidate["versionConfidence"], "high")
                self.assertEqual(linux_candidate["deploymentDisposition"], "contradicted")
                self.assertEqual(linux_candidate["validationStatus"], "refuted")
                self.assertFalse(linux_candidate["isReportable"])
                self.assertFalse(linux_candidate["testable"])
                self.assertFalse(linux_candidate["webExploitable"])
                stored_linux = workspace._load_target_entities("engagement", "linux.example.com")["observations"]
                stored_refuted = next(item for item in stored_linux if item.get("type") == "cve_candidate")
                self.assertFalse(stored_refuted["isReportable"])
                self.assertEqual(stored_refuted["validationStatus"], "refuted")

                windows_candidate = results["windows.example.com"]["candidates"][0]
                self.assertEqual(windows_candidate["deploymentDisposition"], "satisfied")
                self.assertEqual(windows_candidate["confidence"], "high")
                self.assertTrue(windows_candidate["testable"])
                self.assertTrue(windows_candidate["directReplayEligible"])
                self.assertTrue(windows_candidate["prerequisiteEvaluation"]["reachableCodePathIdentified"])

                unknown = results["unknown.example.com"]
                unknown_candidate = unknown["candidates"][0]
                self.assertEqual(unknown_candidate["versionConfidence"], "high")
                self.assertEqual(unknown_candidate["deploymentDisposition"], "unknown")
                self.assertEqual(unknown_candidate["confidence"], "low")
                self.assertFalse(unknown_candidate["testable"])
                self.assertTrue(any(gap.get("type") == "cve_prerequisite_gap" for gap in unknown["gaps"]))

                plans = [
                    json.loads(cve_intel.plan_tests({"candidate": candidate, "workspaceId": "engagement", "target": f"https://{target}/"}))
                    for target, candidate in (
                        ("linux.example.com", linux_candidate),
                        ("windows.example.com", windows_candidate),
                        ("unknown.example.com", unknown_candidate),
                    )
                ]
                self.assertTrue(all(plan["controllingFacts"] for plan in plans))
                self.assertFalse(plans[0]["directReplayEligible"])
                self.assertTrue(plans[1]["directReplayEligible"])
                self.assertFalse(plans[2]["directReplayEligible"])
                self.assertTrue(all({fact["status"] for fact in plan["controllingFacts"]} for plan in plans))
                with self.assertRaisesRegex(McpError, "deployment prerequisites"):
                    cve_intel.prepare_replay({"candidate": unknown_candidate, "target": "https://unknown.example.com/"})

                add_deployment_context(
                    "unknown.example.com",
                    "Microsoft Windows Server 2022; Apache; PHP-CGI; Best-Fit code page 950",
                )
                with patch.object(cve_intel, "_fetch_nvd", return_value=payload):
                    resolved = json.loads(
                        cve_intel.correlate(
                            {
                                "workspaceId": "engagement",
                                "target": "unknown.example.com",
                                "sources": ["nvd"],
                                "confirm": True,
                            }
                        )
                    )
                self.assertEqual(resolved["candidates"][0]["deploymentDisposition"], "satisfied")
                stored_resolved = workspace._load_target_entities("engagement", "unknown.example.com")["observations"]
                resolved_candidate = next(item for item in stored_resolved if item.get("type") == "cve_candidate")
                self.assertTrue(resolved_candidate["isReportable"])
                self.assertTrue(resolved_candidate["testable"])
                self.assertEqual(resolved_candidate["validationStatus"], "proposed")

    def test_major_only_version_matches_range_and_refutes_ancient(self) -> None:
        # Drupal detected as major "10". A 10.x-range CVE is affected; an ancient <4.7 CVE and a
        # 7.x CVE are refuted (not_affected), even though the version is only a bare major.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_named_component("Drupal", version="10", cpe="cpe:2.3:a:drupal:drupal:10:*:*:*:*:*:*:*", precision="exact")
                payload = {
                    "vulnerabilities": [
                        nvd_item("CVE-2023-1010", nvd_config("drupal", vendor="drupal", versionStartIncluding="10.0.0", versionEndExcluding="10.1.5")),
                        nvd_item("CVE-2005-1921", nvd_config("drupal", vendor="drupal", versionEndExcluding="4.7.0")),
                        nvd_item("CVE-2018-7600", nvd_config("drupal", vendor="drupal", versionStartIncluding="7.0", versionEndExcluding="8.0")),
                    ]
                }
                with patch.object(cve_intel, "_fetch_nvd", return_value=payload), patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True})
                    )
                kept = {c["cveId"] for c in result["candidates"]}
                self.assertEqual(kept, {"CVE-2023-1010"})
                self.assertEqual(result["candidates"][0]["confidence"], "high")
                self.assertEqual(result["filtered"]["notAffected"], 2)

    def test_versionless_component_collapsed_when_versioned_present(self) -> None:
        # Two Drupal components (bare "Drupal" and "Drupal 10"): the version-less one is dropped
        # so its keyword lookup cannot resurrect out-of-version CVEs.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "observations": [
                                    {"type": "technology_component", "name": "Drupal", "version": "", "cpe": "cpe:2.3:a:drupal:drupal:*:*:*:*:*:*:*:*", "versionPrecision": "unknown"},
                                    {"type": "technology_component", "name": "Drupal", "version": "10", "cpe": "cpe:2.3:a:drupal:drupal:10:*:*:*:*:*:*:*", "versionPrecision": "exact"},
                                ]
                            }
                        }
                    ),
                )
                components = cve_intel._technology_components(workspace._load_target_entities("engagement", "app.example.com"))
                self.assertEqual([(c["name"], c["version"]) for c in components], [("Drupal", "10")])

    def test_non_web_cve_is_dropped(self) -> None:
        # A DoS-class / non-web CWE on the right product+version is still dropped.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                payload = nvd_payload(
                    "CVE-2020-3333",
                    nvd_config("http_server", vendor="apache", versionStartIncluding="2.4.0", versionEndExcluding="2.4.50"),
                    cwe="CWE-400",
                )
                with patch.object(cve_intel, "_fetch_nvd", return_value=payload), patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True})
                    )
                self.assertEqual(result["candidateCount"], 0)
                self.assertEqual(result["filtered"]["nonWeb"], 1)

    def test_local_attack_vector_is_dropped(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                payload = nvd_payload(
                    "CVE-2020-4444",
                    nvd_config("http_server", vendor="apache", versionStartIncluding="2.4.0", versionEndExcluding="2.4.50"),
                    cwe="CWE-89",
                    attack_vector="LOCAL",
                )
                with patch.object(cve_intel, "_fetch_nvd", return_value=payload), patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True})
                    )
                self.assertEqual(result["candidateCount"], 0)
                self.assertEqual(result["filtered"]["nonWeb"], 1)

    def test_infra_only_component_without_http_surface_is_unreachable(self) -> None:
        # A component seen only via an nmap service banner, with no crawled HTTP surface,
        # is not a web-pentest target and yields no CVE lookups.
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_named_component("OpenSSH", version="8.2", source="service_metadata")
                with patch.object(cve_intel, "_fetch_nvd") as fetch, patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True})
                    )
                fetch.assert_not_called()
                self.assertEqual(result["candidateCount"], 0)
                self.assertEqual(result["filtered"]["unreachable"], 1)

    def test_high_value_class_tag_and_priority(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                payload = nvd_payload(
                    "CVE-2021-41773",
                    nvd_config("http_server", vendor="apache", versionStartIncluding="2.4.0", versionEndExcluding="2.4.50"),
                    cwe="CWE-78",
                )
                with patch.object(cve_intel, "_fetch_nvd", return_value=payload), patch.object(
                    cve_intel, "_enrich_cisa_kev", return_value={}
                ), patch.object(cve_intel, "_enrich_poc_github_index", return_value={}):
                    result = json.loads(
                        cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True})
                    )
                candidate = result["candidates"][0]
                self.assertEqual(candidate["vulnClass"], "OS Command Injection")
                self.assertIn("CWE-78", candidate["cwes"])
                self.assertIn("high-value-class", candidate["tags"])

    def test_public_poc_bumps_priority_without_kev(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                record = {**nvd_record(), "cvss": 5.0, "severity": "medium"}
                with patch.object(cve_intel, "_discover_nvd", return_value=[record]), patch.object(cve_intel, "_enrich_cisa_kev", return_value={}), patch.object(
                    cve_intel,
                    "_enrich_poc_github_index",
                    return_value={"CVE-2021-41773": {"pocReferences": [{"source": "poc_github_index", "url": "https://github.example/poc"}], "source": "poc_github_index"}},
                ):
                    result = json.loads(cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True}))

                candidate = result["candidates"][0]
                self.assertEqual(candidate["exploitMaturity"], "public_poc")
                self.assertEqual(candidate["priority"], "high")
                self.assertIn("public-poc", candidate["tags"])

    def test_correlate_degrades_per_source(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                with patch.object(cve_intel, "_discover_nvd", return_value=[nvd_record()]), patch.object(cve_intel, "_enrich_cisa_kev", return_value={}), patch.object(
                    cve_intel, "_enrich_poc_github_index", side_effect=RuntimeError("rate limited")
                ):
                    result = json.loads(cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "cisa_kev", "poc_github_index"], "confirm": True}))

                self.assertEqual(result["sourceStatus"]["poc_github_index"]["status"], "error")
                self.assertTrue(result["cveDataAvailable"])
                self.assertEqual(result["candidateCount"], 1)

    def test_github_search_skipped_without_token(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                with patch.object(cve_intel, "_discover_nvd", return_value=[nvd_record()]):
                    result = json.loads(cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "github_search"], "confirm": True}))
                self.assertEqual(result["sourceStatus"]["github_search"]["status"], "skipped: no token")

    def test_searchsploit_skipped_when_absent(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                with patch.object(cve_intel, "_discover_nvd", return_value=[nvd_record()]), patch.object(cve_intel.shutil, "which", return_value=None):
                    result = json.loads(cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "searchsploit"], "confirm": True}))
                self.assertEqual(result["sourceStatus"]["searchsploit"]["status"], "skipped: searchsploit not installed")

    def test_source_endpoint_resolution_precedence(self) -> None:
        cve_intel._ENDPOINT_OVERRIDES.clear()
        with patch.dict(cve_intel.os.environ, {"SYNAPSE_CVE_NVD_URL": "https://env.example/nvd"}, clear=False):
            self.assertEqual(cve_intel._resolve_source_config("nvd")["resolvedFrom"], "env")
            cve_intel.set_source_endpoint({"source": "nvd", "url": "https://override.example/nvd", "confirm": True})
            resolved = cve_intel._resolve_source_config("nvd")
            self.assertEqual(resolved["url"], "https://override.example/nvd")
            self.assertEqual(resolved["resolvedFrom"], "override")
            cve_intel.reset_source_endpoint({"source": "nvd", "confirm": True})
            resolved = cve_intel._resolve_source_config("nvd")
            self.assertEqual(resolved["url"], "https://env.example/nvd")
            self.assertEqual(resolved["resolvedFrom"], "env")

    def test_source_endpoint_override_validates_transport_and_executable_kind(self) -> None:
        with self.assertRaisesRegex(McpError, "absolute http"):
            cve_intel.set_source_endpoint(
                {"source": "nvd", "url": "/tmp/local-feed.json", "confirm": True}
            )
        with self.assertRaisesRegex(McpError, "searchsploit executable"):
            cve_intel.set_source_endpoint(
                {"source": "searchsploit", "url": "/bin/echo", "confirm": True}
            )

        result = json.loads(
            cve_intel.set_source_endpoint(
                {
                    "source": "searchsploit",
                    "url": "/opt/exploitdb/searchsploit",
                    "confirm": True,
                }
            )
        )
        self.assertEqual(result["url"], "/opt/exploitdb/searchsploit")

    def test_source_status_reports_url_and_http_status_on_failure(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                seed_component()
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps({"entities": {"observations": [{"type": "possible_cve", "value": "CVE-2024-0001"}]}}),
                )
                with patch.object(cve_intel, "_fetch_nvd", return_value={"httpStatus": 404, "detail": "path moved"}):
                    result = json.loads(cve_intel.correlate({"workspaceId": "engagement", "target": "app.example.com", "sources": ["nvd", "shodan"], "confirm": True}))

                self.assertEqual(result["sourceStatus"]["nvd"]["status"], "error")
                self.assertEqual(result["sourceStatus"]["nvd"]["httpStatus"], 404)
                self.assertIn("url", result["sourceStatus"]["nvd"])
                self.assertEqual(result["candidateCount"], 1)

    def test_cve_sources_tool_reflects_override(self) -> None:
        cve_intel.set_source_endpoint({"source": "nvd", "url": "https://override.example/nvd", "confirm": True})
        result = json.loads(cve_intel.sources({}))
        self.assertEqual(result["sources"]["nvd"]["url"], "https://override.example/nvd")
        self.assertEqual(result["sources"]["nvd"]["resolvedFrom"], "override")

    def test_poc_endpoint_template_is_exact_and_invalid_configuration_sends_no_traffic(self) -> None:
        self.assertTrue(cve_intel._STARTUP_SOURCE_VALIDATION["poc_github_index"]["valid"])
        expected = {
            "CVE-1999-0001": "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/1999/CVE-1999-0001.json",
            "CVE-2024-4577": "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2024/CVE-2024-4577.json",
            "CVE-2031-12345": "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/2031/CVE-2031-12345.json",
        }
        with patch.object(cve_intel, "_fetch_json_source", return_value={}) as fetch:
            for cve_id in expected:
                cve_intel._fetch_poc_github_index(cve_id, {})
        self.assertEqual([call.args[2] for call in fetch.call_args_list], list(expected.values()))

        with patch.object(cve_intel, "_fetch_json_source") as fetch:
            with self.assertRaisesRegex(cve_intel.SourceFetchError, "strict CVE identifier"):
                cve_intel._fetch_poc_github_index("CVE-24-4577", {})
        fetch.assert_not_called()

        malformed = "https://raw.githubusercontent.example/master/{year/{cveId}.json}"
        with patch.dict(os.environ, {"SYNAPSE_CVE_POC_GITHUB_URL": malformed}):
            status = json.loads(cve_intel.sources({"sources": ["poc_github_index"]}))["sources"]["poc_github_index"]
            self.assertTrue(status["configuredEnabled"])
            self.assertFalse(status["enabled"])
            self.assertEqual(status["configuration"]["status"], "configuration_error")
            with TemporaryDirectory() as tmp:
                with isolated_state(Path(tmp)):
                    seed_component()
                    with patch.object(cve_intel, "_fetch_json_source") as fetch:
                        result = json.loads(
                            cve_intel.correlate(
                                {
                                    "workspaceId": "engagement",
                                    "target": "app.example.com",
                                    "sources": ["poc_github_index"],
                                    "confirm": True,
                                }
                            )
                        )
                    fetch.assert_not_called()
                    self.assertEqual(result["sourceStatus"]["poc_github_index"]["status"], "configuration_error")
            with self.assertRaisesRegex(McpError, "PoC endpoint template"):
                cve_intel.set_source_endpoint(
                    {"source": "poc_github_index", "url": malformed, "confirm": True}
                )

        env_path = Path(__file__).resolve().parents[3] / "config" / "synapse.env"
        shell = subprocess.run(
            [
                "sh",
                "-c",
                'unset SYNAPSE_CVE_POC_GITHUB_URL; . "$1"; printf "%s" "$SYNAPSE_CVE_POC_GITHUB_URL"',
                "sh",
                str(env_path),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertEqual(shell.stdout, expected["CVE-2024-4577"].replace("2024/CVE-2024-4577.json", "{year}/{cveId}.json"))

    def test_cve_adapter_is_registered(self) -> None:
        names = {entry["name"] for entry in default_registry.list()}
        self.assertIn("cve", names)

    def test_plan_and_prepare_replay_send_no_traffic(self) -> None:
        candidate = {
            "candidateId": "cve_CVE-2021-41773_apache-httpd_2.4.49",
            "cveId": "CVE-2021-41773",
            "component": "Apache httpd",
            "version": "2.4.49",
            "exploitMaturity": "public_poc",
            "knownExploited": False,
            "pocReferences": [{"source": "poc_github_index", "url": "https://github.example/poc"}],
            "nucleiTemplate": "cves/2021/CVE-2021-41773.yaml",
        }
        with patch.object(cve_intel.http_client, "session") as session:
            plan = json.loads(cve_intel.plan_tests({"candidate": candidate, "workspaceId": "engagement", "target": "https://app.example.com/"}))
            replay = json.loads(cve_intel.prepare_replay({"candidate": candidate, "target": "https://app.example.com/"}))
        session.assert_not_called()
        self.assertEqual(plan["exploitMaturity"], "public_poc")
        self.assertIn("poc_github_index", plan["pocReferencesBySource"])
        self.assertEqual(plan["nucleiTemplate"], "cves/2021/CVE-2021-41773.yaml")
        self.assertTrue(any("Do not fetch" in item for item in plan["guardrails"]))
        self.assertEqual(replay["request"]["method"], "GET")
        self.assertIn("pocReferences", replay)

    def test_execute_test_requires_confirm_and_scope(self) -> None:
        candidate = {"candidateId": "cve_CVE-2021-41773_apache-httpd_2.4.49", "cveId": "CVE-2021-41773", "component": "Apache httpd", "version": "2.4.49"}
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["app.example.com"], "test")
                with patch.object(cve_intel.http_client, "session") as session:
                    with self.assertRaisesRegex(McpError, "confirm=true"):
                        cve_intel.execute_test({"workspaceId": "engagement", "target": "https://app.example.com/", "candidate": candidate})
                    with self.assertRaisesRegex(McpError, "not in authorized scope"):
                        cve_intel.execute_test({"workspaceId": "engagement", "target": "https://other.example.com/", "candidate": candidate, "confirm": True})
                session.assert_not_called()

    def test_execute_test_records_evidence_and_action(self) -> None:
        candidate = {"candidateId": "cve_CVE-2021-41773_apache-httpd_2.4.49", "cveId": "CVE-2021-41773", "component": "Apache httpd", "version": "2.4.49"}
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["example.com"], "test")
                workspace.create_workspace("engagement", organization="Example", hosts=["example.com"])
                fake_session = FakeSession(HttpResponse(status=200, headers={"Server": "Apache/2.4.49"}, body="Apache httpd 2.4.49"))
                with patch.object(cve_intel.http_client, "session", return_value=fake_session):
                    result = json.loads(cve_intel.execute_test({"workspaceId": "engagement", "target": "https://example.com/", "candidate": candidate, "confirm": True}))

                self.assertEqual(result["test"]["assessment"], "possible_cve")
                self.assertTrue(result["test"]["exchangeEvidence"]["evidenceId"].startswith("ev_"))
                actions = workspace._load_target_entities("engagement", "example.com")["actions"]
                self.assertTrue(any(action.get("tool") == "cve.execute_test" for action in actions))
                self.assertEqual(len(fake_session.requests), 1)

    def test_cve_dispatch_tools_are_reachable(self) -> None:
        result = json.loads(stdio_server.call_tool("cve.session_key.status", {}))
        self.assertIn("providers", result)
