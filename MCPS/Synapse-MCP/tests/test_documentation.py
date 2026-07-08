import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from helpers import assert_shared_html_shell, isolated_state
from synapse_mcp.adapters.web import js_intel
from synapse_mcp.core import credentials, scope, workspace
from synapse_mcp.core.documentation.builder import is_active_action
from synapse_mcp.core.documentation.assets import banner_data_uri, report_css
from synapse_mcp.core.documentation import layers
from synapse_mcp.core.documentation.layer_renderer import _summary_value, render_layer_report, render_workspace_report
from synapse_mcp.transport import stdio_server


class DocumentationTests(unittest.TestCase):
    def test_render_returns_path_not_content_by_default(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["app.example.com"])

                report = json.loads(
                    stdio_server.call_tool(
                        "documentation.render_workspace_report",
                        {"workspaceId": "engagement", "layers": ["perimeter"], "outputPath": "reports/workspace.html"},
                    )
                )

                self.assertEqual(report["format"], "html")
                self.assertTrue(Path(report["path"]).exists())
                self.assertIn("summary", report)
                self.assertNotIn("content", report)

    def test_redaction_mode_toggles_workspace_report_body_class(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["app.example.com"])

                def render(mode: str) -> str:
                    return json.loads(
                        stdio_server.call_tool(
                            "documentation.render_workspace_report",
                            {"workspaceId": "engagement", "layers": ["perimeter"], "redactionMode": mode, "returnContent": True, "outputPath": "reports/r.html"},
                        )
                    )["content"]

                operator_html = render("internal")
                high_level_html = render("high_level")

                # internal renders the full operator view ...
                self.assertIn('<body class="operator single-target">', operator_html)
                self.assertNotIn('<body class="high-level single-target">', operator_html)
                # ... while high_level switches the body class, which the stylesheet uses to
                # hide operator-only blocks and apply the high-level (Dossier) styling.
                self.assertIn('<body class="high-level single-target">', high_level_html)
                self.assertNotIn('<body class="operator single-target">', high_level_html)
                self.assertIn("body.high-level .operator-only{display:none", high_level_html)

    def test_layer_renderer_renders_coverage_gaps_once_per_document(self) -> None:
        layer_context = {
            "workspaceId": "engagement",
            "layer": "perimeter",
            "title": "Synthetic Layer",
            "generatedAt": "2026-06-12T00:00:00Z",
            "summary": {"targetCount": 1, "endpointCount": 2},
            "targets": [
                {
                    "target": "app.example.com",
                    "summary": {"targetCount": 1, "endpointCount": 2},
                    "gaps": ["Shared coverage gap", "Target-only gap"],
                    "sections": [],
                }
            ],
            "gaps": ["Shared coverage gap", "Layer-only gap"],
            "recommendedNextSteps": [],
            "sections": [],
        }
        workspace_context = {
            "workspaceId": "engagement",
            "title": "Synthetic Workspace",
            "generatedAt": "2026-06-12T00:00:00Z",
            "summary": {"layerCount": 1},
            "layers": [layer_context],
            "gaps": ["Shared coverage gap", "Layer-only gap", "Workspace-only gap"],
            "recommendedNextSteps": [],
        }

        for rendered in (
            render_layer_report(layer_context, "html"),
            render_layer_report(layer_context, "markdown"),
            render_workspace_report(workspace_context, "html"),
            render_workspace_report(workspace_context, "markdown"),
        ):
            self.assertEqual(rendered.count("Shared coverage gap"), 1)
            self.assertEqual(rendered.count("Layer-only gap"), 1)

        self.assertEqual(render_workspace_report(workspace_context, "html").count("Workspace-only gap"), 1)
        self.assertEqual(render_workspace_report(workspace_context, "markdown").count("Workspace-only gap"), 1)
        self.assertEqual(render_layer_report(layer_context, "html").count("Endpoint Count"), 1)

    def test_summary_values_render_structured_data_readably(self) -> None:
        self.assertEqual(_summary_value([{"name": "nginx"}, {"name": "Apache"}]), "nginx, Apache")
        self.assertEqual(_summary_value([{"target": "app.example.com", "ports": [443]}]), "app.example.com")
        self.assertEqual(_summary_value([{"ports": [443]}]), "1 records")
        self.assertEqual(_summary_value({"counts": {"targets": 1}, "targets": [{"target": "app.example.com"}]}), "2 fields")
        for value in (
            _summary_value([{"ports": [443]}]),
            _summary_value({"counts": {"targets": 1}, "targets": [{"target": "app.example.com"}]}),
        ):
            self.assertNotIn("{'", value)

    def test_auth_layer_filters_credential_metadata_to_report_targets(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                scope.save_scope(["app.example.com", "other.example.net"], "test", "Example Client")
                workspace.create_workspace("engagement", hosts=["app.example.com"])
                credentials.save_credential({"id": "app-cookie", "type": "cookie", "secret": "SESSION=app", "scopes": ["app.example.com"]})
                credentials.save_credential({"id": "other-cookie", "type": "cookie", "secret": "SESSION=other", "scopes": ["other.example.net"]})

                context = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_layer_report_context",
                        {"workspaceId": "engagement", "target": "app.example.com", "layer": "auth", "refresh": True},
                    )
                )

                sections = {section["sectionId"]: section for section in context["layerReport"]["sections"]}
                credential_ids = {row[0] for row in sections["credential_metadata"]["rows"]}
                self.assertEqual(credential_ids, {"app-cookie"})

    def test_web_vulnerability_layer_groups_passive_candidates(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "passive_analysis",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "observations": [
                                    {
                                        "type": "xss_candidate",
                                        "value": "GET https://app.example.com/search?q=alpha",
                                        "url": "https://app.example.com/search?q=alpha",
                                        "method": "GET",
                                        "parameter": "q",
                                        "priority": "medium",
                                        "priorityScore": 70,
                                        "reason": "Search parameter may be reflected.",
                                    },
                                    {
                                        "type": "sqli_candidate",
                                        "value": "GET https://app.example.com/rest/products/search?q=1",
                                        "url": "https://app.example.com/rest/products/search?q=1",
                                        "method": "GET",
                                        "parameter": "q",
                                        "priority": "medium",
                                        "priorityScore": 70,
                                        "reason": "Search parameter may reach database queries.",
                                    },
                                    {
                                        "type": "xss_candidate",
                                        "value": "GET https://twitter.com/intent/tweet?text=hello",
                                        "url": "https://twitter.com/intent/tweet?text=hello",
                                        "method": "GET",
                                        "parameter": "text",
                                        "priority": "medium",
                                        "priorityScore": 70,
                                        "reason": "External endpoint should not appear in target-owned web vulnerability report.",
                                    },
                                ]
                            }
                        }
                    ),
                )

                context = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_layer_report_context",
                        {"workspaceId": "engagement", "target": "app.example.com", "layer": "web_vulnerabilities"},
                    )
                )

                report = context["layerReport"]
                self.assertEqual(report["summary"]["candidateCount"], 2)
                self.assertEqual(report["summary"]["moduleCounts"], {"xss": 1, "sqli": 1})
                self.assertNotIn("twitter.com", json.dumps(report))
                candidate_section = next(section for section in report["sections"] if section["sectionId"] == "web_vulnerability_candidates")
                self.assertEqual({group["category"] for group in candidate_section["metadata"]["groups"]}, {"xss", "sqli"})

    def test_web_vulnerability_layer_justifies_findings_and_high_confidence_candidates(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                from synapse_mcp.core.adapters import surface_candidate

                candidate = surface_candidate(
                    vuln_class="ssrf", url="https://app.example.com/fetch?target=1", method="GET",
                    parameter="target", location="query", reason="URL-fetch parameter reaches internal metadata service.",
                    priority="high", priority_score=85,
                )
                ingestion = workspace.ingest_data(
                    "engagement", "app.example.com", "adapter_result", "passive_analysis", "json",
                    json.dumps({"entities": {
                        "observations": [candidate],
                        "findings": [{
                            "type": "finding", "title": "Reflected XSS in search", "status": "confirmed",
                            "severity": "high", "description": "The q parameter is reflected without encoding.",
                            "impact": "Session theft via crafted link.", "affectedAssets": ["app.example.com"],
                        }],
                    }}),
                )
                evidence_id = ingestion["evidenceId"]
                # Confirm the ssrf class so the candidate is high-confidence.
                workspace.record_candidate_validation(
                    "engagement", "app.example.com", {"candidateId": candidate["candidateId"]}, "confirmed", vuln_class="ssrf",
                )

                context = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_layer_report_context",
                        {"workspaceId": "engagement", "target": "app.example.com", "layer": "web_vulnerabilities", "redactionMode": "internal"},
                    )
                )
                report = context["layerReport"]
                sections = {section["sectionId"]: section for section in report["sections"]}

                findings_section = sections["reviewed_findings"]
                self.assertIn("Why", findings_section["headers"])
                self.assertIn("Local Path", findings_section["headers"])
                finding_row = findings_section["rows"][0]
                self.assertIn("reflected without encoding", " ".join(str(cell) for cell in finding_row))
                self.assertIn("Session theft", " ".join(str(cell) for cell in finding_row))
                self.assertIn(evidence_id, str(finding_row[6]))  # Evidence column carries the id
                self.assertNotEqual(str(finding_row[7]), "not linked")  # Local Path resolved to the evidence file

                high_conf = sections["confirmed_high_confidence_candidates"]
                self.assertTrue(high_conf["rows"])
                hc_row = " ".join(str(cell) for cell in high_conf["rows"][0])
                self.assertIn("ssrf:confirmed", hc_row)
                self.assertIn("metadata service", hc_row)

                # Operator HTML shows the evidence file path; high-level marks it operator-only (CSS-hidden).
                operator_html = render_layer_report(report, "html")
                self.assertIn("operator-only", operator_html)

    def test_web_vulnerability_layer_drops_static_asset_phantom_candidates(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "passive_analysis",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "observations": [
                                    {
                                        "type": "ssti_candidate",
                                        "value": "GET https://app.example.com/profile",
                                        "url": "https://app.example.com/profile",
                                        "method": "GET",
                                        "priority": "medium",
                                    },
                                    {
                                        "type": "ssti_candidate",
                                        "value": "GET https://app.example.com/2fa/chunk-ABCD.js",
                                        "url": "https://app.example.com/2fa/chunk-ABCD.js",
                                        "method": "GET",
                                        "priority": "medium",
                                    },
                                ]
                            }
                        }
                    ),
                )

                context = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_layer_report_context",
                        {"workspaceId": "engagement", "target": "app.example.com", "layer": "web_vulnerabilities"},
                    )
                )
                report = context["layerReport"]
                # The phantom .js candidate is dropped; the real /profile candidate remains.
                self.assertEqual(report["summary"]["candidateCount"], 1)
                self.assertNotIn("chunk-ABCD.js", json.dumps(report))
                self.assertIn("/profile", json.dumps(report))

    def test_cve_layer_ranks_kev_and_marks_exploit_refs_operator_only(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "passive_analysis",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "observations": [
                                    {
                                        "type": "cve_candidate",
                                        "candidateId": "cve_CVE-2024-0002_nginx_1.22.1",
                                        "value": "CVE-2024-0002",
                                        "cveId": "CVE-2024-0002",
                                        "component": "nginx",
                                        "version": "1.22.1",
                                        "priority": "medium",
                                        "priorityScore": 50,
                                        "confidence": "high",
                                        "cvssScore": 5.0,
                                        "exploitMaturity": "none",
                                        "knownExploited": False,
                                        "pocReferences": [],
                                        "pocCount": 0,
                                        "testable": True,
                                        "reason": "Exact nginx version maps to an NVD CVE.",
                                    },
                                    {
                                        "type": "cve_candidate",
                                        "candidateId": "cve_CVE-2021-41773_apache-httpd_2.4.49",
                                        "value": "CVE-2021-41773",
                                        "cveId": "CVE-2021-41773",
                                        "component": "Apache httpd",
                                        "version": "2.4.49",
                                        "priority": "critical",
                                        "priorityScore": 95,
                                        "confidence": "high",
                                        "cvssScore": 7.5,
                                        "exploitMaturity": "in_the_wild",
                                        "knownExploited": True,
                                        "pocReferences": [{"source": "poc_github_index", "url": "https://github.example/apache-poc", "stars": 20}],
                                        "pocCount": 1,
                                        "testable": True,
                                        "reason": "KEV-listed Apache path traversal candidate.",
                                    },
                                ],
                                "findings": [
                                    {
                                        "type": "finding",
                                        "title": "CVE-2021-41773 confirmed on Apache httpd",
                                        "status": "confirmed",
                                        "severity": "critical",
                                        "confidence": "high",
                                        "cveId": "CVE-2021-41773",
                                        "component": "Apache httpd",
                                    }
                                ],
                            }
                        }
                    ),
                )

                operator = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_layer_report_context",
                        {"workspaceId": "engagement", "target": "app.example.com", "layer": "cve", "redactionMode": "internal"},
                    )
                )["layerReport"]
                safe = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_layer_report_context",
                        {"workspaceId": "engagement", "target": "app.example.com", "layer": "cve", "redactionMode": "high_level"},
                    )
                )["layerReport"]

                operator_candidates = next(section for section in operator["sections"] if section["sectionId"] == "suggested_cves")
                safe_candidates = next(section for section in safe["sections"] if section["sectionId"] == "suggested_cves")
                self.assertEqual(operator_candidates["rows"][0][4], "CVE-2021-41773")
                self.assertIn("Exploit Reference", operator_candidates["headers"])
                self.assertIn("https://github.example/apache-poc", json.dumps(operator_candidates))
                # Reports are internal operator artifacts, so the high-level view hides the
                # exploit-reference column via presentation-only CSS (operator-only class): the
                # data stays in the report source in both views and is never stripped.
                self.assertEqual(safe_candidates["rows"][0][4], "CVE-2021-41773")
                self.assertIn("Exploit Reference", safe_candidates["headers"])
                self.assertIn("https://github.example/apache-poc", json.dumps(safe))
                self.assertIn("in_the_wild", json.dumps(safe))
                from synapse_mcp.core.documentation import layer_renderer

                self.assertTrue(layer_renderer._is_operator_only_header("Exploit Reference"))
                findings = next(section for section in operator["sections"] if section["sectionId"] == "confirmed_cve_findings")
                self.assertEqual(findings["rows"][0][2], "CVE-2021-41773")

    def test_report_candidate_counts_single_source(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Client", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "passive_analysis",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "observations": [
                                    {
                                        "type": "xss_candidate",
                                        "value": "GET https://app.example.com/search?q=1",
                                        "url": "https://app.example.com/search?q=1",
                                        "method": "GET",
                                        "parameter": "q",
                                        "priority": "medium",
                                    },
                                    {
                                        "type": "sqli_candidate",
                                        "value": "GET https://app.example.com/api/items?id=1",
                                        "url": "https://app.example.com/api/items?id=1",
                                        "method": "GET",
                                        "parameter": "id",
                                        "priority": "high",
                                    },
                                    {
                                        "type": "access_control_object_candidate",
                                        "value": "GET https://app.example.com/api/users/1",
                                        "url": "https://app.example.com/api/users/1",
                                        "method": "GET",
                                        "priority": "high",
                                    },
                                ]
                            }
                        }
                    ),
                )

                context = layers.build_workspace_report_context(
                    {"workspaceId": "engagement", "layers": ["perimeter", "web_vulnerabilities", "access_control"], "refresh": True}
                )["workspaceReport"]
                by_layer = {item["layer"]: item for item in context["layers"]}
                app_total = by_layer["perimeter"]["summary"]["candidateCount"]
                web_summary = by_layer["web_vulnerabilities"]["summary"]

                self.assertEqual(app_total, 2)
                self.assertEqual(web_summary["candidateCount"], app_total)
                self.assertEqual(sum(web_summary["moduleCounts"].values()), app_total)
                self.assertEqual(by_layer["access_control"]["summary"]["accessControlReviewItems"], 1)

                rendered = json.loads(
                    stdio_server.call_tool(
                        "documentation.render_workspace_report",
                        {
                            "workspaceId": "engagement",
                            "layers": ["perimeter", "web_vulnerabilities", "access_control"],
                            "refresh": True,
                            "returnContent": True,
                        },
                    )
                )
                self.assertIn("Access Control Review Items", rendered["content"])

    def test_perimeter_layer_summary_uses_scalar_counts(self) -> None:
        payload = {
            "workspaceId": "engagement",
            "summary": {
                "generatedAt": "2026-06-12T00:00:00Z",
                "targets": [{"target": "app.example.com", "ports": [443]}],
                "technologyMatrix": [{"name": "nginx", "hosts": ["app.example.com"]}],
                "counts": {
                    "targets": 1,
                    "webApplications": 1,
                    "technologyComponents": 1,
                    "loginPortals": 1,
                    "findingCandidates": 1,
                },
            },
            "targets": [
                {
                    "target": "app.example.com",
                    "asset": {"serviceCount": 1, "endpointCount": 3},
                    "webApplications": [{}],
                    "technologyComponents": [{}],
                    "loginPortals": [{}],
                    "protectedResources": [],
                    "findingCandidates": [{}],
                    "siteMap": {"endpointCount": 3, "tree": {}},
                }
            ],
        }
        with patch.object(layers.perimeter, "build_summary", return_value=payload):
            context = layers._perimeter_layer({"workspaceId": "engagement"})

        self.assertEqual(context["summary"]["targetCount"], 1)
        self.assertEqual(context["summary"]["endpointCount"], 3)
        self.assertNotIn("targets", context["summary"])
        html = render_layer_report(context, "html")
        markdown = render_layer_report(context, "markdown")
        self.assertNotIn("{'", html)
        self.assertNotIn("{'", markdown)
        self.assertIn("Target Count", html)
        self.assertIn("Target Count", markdown)

    def test_report_css_uses_bounded_soft_layout_and_wraps_callouts(self) -> None:
        css = report_css()
        # Reports keep the v2-style wide-but-bounded content measure.
        self.assertIn("--maxw:1680px", css)
        self.assertNotIn("--maxw:1080px", css)
        # Brand palette: a dark navy field with a single blue structural accent, and a
        # flat token-driven background floor (panels mix into the field, no glow rules).
        self.assertIn("--accent:", css)
        self.assertIn("transparent 60%),var(--bg)", css)
        self.assertNotIn(".risk-panel:before", css)
        self.assertIn("grid-template-columns:minmax(210px,260px) minmax(0,1fr)", css)
        self.assertIn(".report-toc a:hover,.report-toc a.active", css)
        self.assertIn("@media(max-width:1100px)", css)
        # Tables rely on CSS layout and wrapping instead of generated col widths.
        self.assertIn("table-layout:fixed", css)
        self.assertIn("min-width:0", css)
        self.assertIn("white-space:normal", css)
        # Long unbreakable strings (URLs) in callouts must wrap instead of overflowing the column.
        self.assertIn(".finding h4{", css)
        self.assertIn(".finding p{", css)
        finding_heading = css.split(".finding h4{", 1)[1].split("}", 1)[0]
        finding_body = css.split(".finding p{", 1)[1].split("}", 1)[0]
        self.assertIn("overflow-wrap:anywhere", finding_heading)
        self.assertIn("overflow-wrap:anywhere", finding_body)
        # The dead candidate-callout modifier is gone now that candidates render as grouped tables.
        self.assertNotIn(".finding.candidate-observation", css)
        self.assertIn(".candidate-group-title", css)

    def test_workspace_html_single_target_uses_curated_visible_report(self) -> None:
        web_layer = {
            "workspaceId": "engagement",
            "layer": "web_vulnerabilities",
            "title": "Web Vulnerability Candidate Report",
            "generatedAt": "2026-06-21T00:00:00Z",
            "summary": {"targetCount": 1, "candidateCount": 1, "findingCount": 1, "moduleCounts": {"xss": 1}},
            "targets": [
                {
                    "target": "app.example.com",
                    "summary": {"candidateCount": 1},
                    "gaps": [],
                    "sections": [
                        {
                            "sectionId": "raw_target_detail",
                            "title": "Raw Target Detail",
                            "headers": ["Host", "Value"],
                            "rows": [["app.example.com", "kept for operator detail"]],
                        }
                    ],
                }
            ],
            "sections": [
                {
                    "sectionId": "web_vulnerability_candidates",
                    "title": "High-Value Candidate Surface",
                    "kind": "candidate_groups",
                    "headers": ["Host", "Module", "Top Surface", "Parameter", "Priority", "Count", "Evidence", "Reason"],
                    "rows": [["app.example.com", "xss", "POST /profile", "name", "high", 1, "ev1", "reflection reason"]],
                    "metadata": {
                        "groups": [
                            {
                                "category": "xss",
                                "count": 1,
                                "headers": ["Host", "Top Surface", "Parameter", "Priority", "Count", "Evidence", "Reason"],
                                "rows": [["app.example.com", "POST /profile", "name", "high", 1, "ev1", "reflection reason"]],
                            }
                        ]
                    },
                },
                {
                    "sectionId": "reviewed_findings",
                    "title": "Workspace Findings",
                    "kind": "table",
                    "headers": ["Host", "Severity", "Title", "Status", "Affected Assets", "Evidence"],
                    "rows": [["app.example.com", "high", "Confirmed issue", "confirmed", "https://app.example.com/api/Users", "ev1"]],
                },
            ],
            "gaps": [],
            "recommendedNextSteps": [],
        }
        workspace_context = {
            "workspaceId": "engagement",
            "title": "Synthetic Workspace",
            "generatedAt": "2026-06-21T00:00:00Z",
            "summary": {"layerCount": 1, "targetCount": 1},
            "layers": [web_layer],
            "gaps": [],
            "recommendedNextSteps": [],
        }

        rendered = render_workspace_report(workspace_context, "html")

        self.assertIn('class="operator single-target"', rendered)
        self.assertNotIn("<h3>app.example.com</h3>", rendered)
        self.assertIn("<p>/api/Users</p>", rendered)
        self.assertNotIn("<p>https://app.example.com/api/Users</p>", rendered)
        # The workspace report opens on Risk Posture / Confirmed Findings, not a redundant
        # top "Summary" stat block (that duplicated the risk posture). The per-layer Summary
        # in single-layer reports is unaffected.
        self.assertNotIn('<section class="layer" id="summary">', rendered)
        self.assertNotIn(">Internal Summary<", rendered)
        self.assertIn('<details class="operator-detail operator-only">', rendered)
        # High-level is a standalone executive summary; the operator console (finding cards
        # and the per-layer technical stack) is operator-only and CSS-hidden in that view.
        self.assertIn('<section class="exec-summary high-level-only">', rendered)
        self.assertIn(">Executive Summary<", rendered)
        self.assertIn(">Key Findings<", rendered)
        self.assertIn(">Areas Requiring Attention<", rendered)
        self.assertIn('class="report-strip finding-strip operator-only"', rendered)
        self.assertIn('<div class="wrap operator-only"><div class="layout">', rendered)
        brief = rendered.split('<section class="block layer-brief">', 1)[1].split("<details", 1)[0]
        self.assertIn(">Family<", brief)
        self.assertNotIn(">Host<", brief)
        self.assertNotIn(">Evidence<", brief)
        self.assertNotIn(">Reason<", brief)

    def test_report_banner_uses_optimized_jpeg_and_small_html(self) -> None:
        data_uri = banner_data_uri()
        self.assertTrue(data_uri.startswith("data:image/jpeg;base64,"))
        self.assertIn("body.high-level .operator-only", report_css())
        self.assertIn("@media print", report_css())
        # Operator opted into the design-template display face; system-ui stays as fallback.
        self.assertIn("--display:'Oxanium'", report_css())
        self.assertIn("system-ui", report_css())
        self.assertNotIn('"Chakra Petch"', report_css())
        self.assertNotIn('"Inter"', report_css())
        layer_context = {
            "workspaceId": "engagement",
            "layer": "perimeter",
            "title": "Small Layer",
            "generatedAt": "2026-06-12T00:00:00Z",
            "summary": {"targetCount": 1},
            "targets": [],
            "gaps": [],
            "recommendedNextSteps": [],
            "sections": [],
        }
        rendered = render_layer_report(layer_context, "html")
        self.assertLess(len(rendered.encode("utf-8")), 400_000)
        self.assertIn("agentic operations layer", rendered)
        self.assertIn("mode-badge", rendered)
        self.assertIn("setMode", rendered)
        # Operator opted into design-template fonts; they load with a system fallback.
        self.assertIn("fonts.googleapis.com", rendered)
        self.assertIn("fonts.gstatic.com", rendered)
        self.assertIn('<link rel="preconnect"', rendered)

    def test_js_asset_local_path_is_workspace_relative(self) -> None:
        from synapse_mcp.core.documentation.layers import _short_local_path

        abs_path = "/home/op/AI/Synapse/DATA/workspaces/ws1/targets/example.com/outputs/js-intelligence/assets/abc.js"
        short = _short_local_path(abs_path)
        self.assertEqual(short, "workspaces/ws1/targets/example.com/outputs/js-intelligence/assets/abc.js")
        self.assertNotIn("/home/op", short)
        self.assertEqual(_short_local_path("/tmp/x/y.js"), "y.js")
        self.assertEqual(_short_local_path(""), "")

    def test_layer_html_includes_decorative_report_elements(self) -> None:
        sections = [
            {
                "sectionId": f"section_{index}",
                "title": f"Section {index}",
                "headers": ["Severity", "Priority", "URL"],
                "rows": [["high", "medium", f"https://app.example.com/{index}"]],
            }
            for index in range(1, 4)
        ]
        context = {
            "workspaceId": "engagement",
            "layer": "perimeter",
            "title": "Decorated Layer",
            "generatedAt": "2026-06-12T00:00:00Z",
            "summary": {"targetCount": 1, "layers": ["perimeter"]},
            "targets": [],
            "gaps": [],
            "recommendedNextSteps": [],
            "sections": sections,
        }
        rendered = render_layer_report(context, "html")
        self.assertIn('class="stat-card"', rendered)
        self.assertIn('class="stat-value">1</span>', rendered)
        self.assertIn('<ul class="summary-list">', rendered)
        self.assertIn('class="report-toc"', rendered)
        self.assertIn("synapseSetActiveToc", rendered)
        self.assertIn("workspace engagement", rendered)
        self.assertIn("2026-06-12T00:00:00Z", rendered)
        self.assertIn('class="badge badge-high">high</span>', rendered)
        self.assertIn('class="badge badge-medium">medium</span>', rendered)
        self.assertIn("Operator Report", rendered)
        self.assertIn("High-Level", rendered)
        self.assertIn("aria-pressed", rendered)
        self.assertIn("body.high-level", rendered)
        self.assertIn("body.operator", rendered)
        self.assertIn("synapse-report-footer", rendered)

    def test_report_tables_exclude_confidence_but_workspace_keeps_it(self) -> None:
        payload = {
            "workspaceId": "engagement",
            "summary": {
                "generatedAt": "2026-06-12T00:00:00Z",
                "targets": [{"target": "app.example.com", "ports": [443]}],
                "technologyMatrix": [{"name": "nginx", "version": "1.25", "confidence": "high", "source": "response_header", "hosts": ["app.example.com"]}],
                "counts": {"targets": 1, "webApplications": 1, "technologyComponents": 1, "loginPortals": 1, "findingCandidates": 0},
            },
            "targets": [
                {
                    "target": "app.example.com",
                    "asset": {"serviceCount": 0, "endpointCount": 1},
                    "webApplications": [{"baseUrl": "https://app.example.com/", "appFamily": "spa", "routeCount": 3, "authRequired": True, "confidence": "low"}],
                    "technologyComponents": [{}],
                    "loginPortals": [{"representativeUrl": "https://app.example.com/login", "provider": "Form", "method": "POST", "confidence": "medium"}],
                    "protectedResources": [],
                    "findingCandidates": [],
                    # Agent-facing observation retains confidence; only report tables drop the column.
                    "perimeterObservations": [{"type": "technology", "value": "nginx", "confidence": "high"}],
                    "siteMap": {"endpointCount": 1, "tree": {}},
                }
            ],
        }
        with patch.object(layers.perimeter, "build_summary", return_value=payload):
            context = layers._perimeter_layer({"workspaceId": "engagement"})

        for section in context["sections"]:
            self.assertNotIn("Confidence", section.get("headers", []))
        html = render_layer_report(context, "html")
        markdown = render_layer_report(context, "markdown")
        self.assertNotIn(">Confidence<", html)
        self.assertNotIn("| Confidence |", markdown)
        # Workspace/agent-facing data is never weakened to satisfy a report concern.
        self.assertIn('"confidence": "high"', json.dumps(context))

    def test_perimeter_candidates_render_grouped_by_category(self) -> None:
        payload = {
            "workspaceId": "engagement",
            "summary": {
                "generatedAt": "2026-06-12T00:00:00Z",
                "targets": [{"target": "app.example.com", "ports": [443]}],
                "technologyMatrix": [],
                "counts": {"targets": 1, "webApplications": 0, "technologyComponents": 0, "loginPortals": 0, "findingCandidates": 3},
            },
            "targets": [
                {
                    "target": "app.example.com",
                    "asset": {"serviceCount": 0, "endpointCount": 2},
                    "webApplications": [],
                    "technologyComponents": [],
                    "loginPortals": [],
                    "protectedResources": [],
                    "findingCandidates": [
                        {"severity": "low", "category": "Open redirect candidate", "url": "https://app.example.com/a", "method": "GET", "parameter": "next", "source": "observation", "reason": "r-low", "candidateId": "cand-low", "evidenceIds": ["ev-low"], "occurrenceCount": 2},
                        {"severity": "high", "category": "Open redirect candidate", "url": "https://app.example.com/b", "method": "GET", "parameter": "return", "source": "observation", "reason": "r-high", "candidateId": "cand-high", "evidenceIds": ["ev-high"]},
                        {"severity": "medium", "category": "Command injection candidate", "url": "https://app.example.com/c", "method": "POST", "parameter": "cmd", "source": "observation", "reason": "r-cmd", "candidateId": "cand-cmd", "evidenceIds": []},
                    ],
                    "siteMap": {"endpointCount": 2, "tree": {}},
                }
            ],
        }
        with patch.object(layers.perimeter, "build_summary", return_value=payload):
            context = layers._perimeter_layer({"workspaceId": "engagement"})

        section = next(item for item in context["sections"] if item["sectionId"] == "candidate_review_items")
        self.assertEqual(section["kind"], "candidate_groups")
        groups = section["metadata"]["groups"]
        # Groups ordered by most-severe member: open redirect (high) before command injection (medium).
        self.assertEqual([group["category"] for group in groups], ["Open redirect candidate", "Command injection candidate"])
        redirect_group = groups[0]
        self.assertEqual(redirect_group["count"], 2)
        # Category is the heading, never a per-row column.
        self.assertNotIn("Category", redirect_group["headers"])
        for required in ("Request", "Candidate ID", "Evidence", "Count"):
            self.assertIn(required, redirect_group["headers"])
        severity_col = redirect_group["headers"].index("Severity")
        self.assertEqual([row[severity_col] for row in redirect_group["rows"]], ["high", "low"])
        evidence_col = redirect_group["headers"].index("Evidence")
        self.assertIn("ev-high", redirect_group["rows"][0][evidence_col])
        self.assertIn("ev-low", redirect_group["rows"][1][evidence_col])

        html = render_layer_report(context, "html")
        markdown = render_layer_report(context, "markdown")
        self.assertIn('class="candidate-group"', html)
        self.assertIn("Open redirect candidate", html)
        self.assertNotIn('class="finding candidate-observation"', html)
        self.assertIn("**Open redirect candidate (2 candidates)**", markdown)
        self.assertIn("**Command injection candidate (1 candidate)**", markdown)

    def test_workspace_next_steps_are_derived_from_report_context(self) -> None:
        layer_contexts = [
            {
                "layer": "perimeter",
                "summary": {},
                "sections": [
                    {
                        "sectionId": "candidate_review_items",
                        "metadata": {
                            "groups": [
                                {"category": "Security header hygiene candidate", "count": 3, "rows": [[1], [2], [3]]},
                                {"category": "Open redirect candidate", "count": 2, "rows": [[1], [2]]},
                            ]
                        },
                    }
                ],
            },
            {
                "layer": "js",
                "summary": {"assetCount": 2, "jsSignalCount": 0, "jsInferredEndpointCount": 0},
                "sections": [],
            },
            {
                "layer": "auth",
                "summary": {"loginPortalCount": 2, "protectedResourceCount": 0, "credentialMetadataCount": 1},
                "sections": [],
            },
            {
                "layer": "access_control",
                "summary": {"replayCount": 4},
                "sections": [
                    {
                        "sectionId": "candidates",
                        "metadata": {"groups": [{"category": "possible_broken_access_control", "count": 1, "rows": [[1]]}]},
                    }
                ],
            },
        ]

        steps = layers._workspace_recommended_next_steps(layer_contexts, [], ["generic fallback"])

        self.assertEqual(len(steps), 5)
        self.assertTrue(any("possible broken access-control" in item for item in steps))
        self.assertTrue(any("header/cookie hygiene" in item for item in steps))
        self.assertTrue(any("open-redirect" in item for item in steps))
        self.assertTrue(any("JavaScript analysis coverage" in item for item in steps))
        self.assertTrue(any("protected-resource baseline" in item for item in steps))
        self.assertNotIn("generic fallback", steps)

    def test_access_control_candidate_value_falls_back_to_replay_context(self) -> None:
        value = layers._access_control_candidate_value(
            {
                "type": "possible_broken_access_control",
                "method": "POST",
                "requestUrl": "https://app.example.com/api/Sicas",
                "matrixId": "rpc_ofe_gestion_difu_consulta",
                "replayId": "acr_123",
            }
        )

        self.assertEqual(value, "POST https://app.example.com/api/Sicas (rpc_ofe_gestion_difu_consulta)")

    def test_js_signals_render_as_grouped_compact_sections(self) -> None:
        section = layers._signal_section(
            "signals",
            "JavaScript Signals",
            ["Host", "Type", "Value", "Source Asset", "Reason"],
            [
                ["app.example.com", "js_spa_route", "admin", "main.js", "Angular route path found."],
                ["app.example.com", "js_rpc_command_group", "OFE:ALTA", "main.js", "RPC command group found."],
                ["app.example.com", "js_spa_route", "login", "main.js", "Angular route path found."],
            ],
        ).as_dict()
        context = {
            "workspaceId": "engagement",
            "layer": "js",
            "title": "JavaScript Intelligence Report",
            "generatedAt": "2026-06-13T00:00:00Z",
            "summary": {"jsSignalCount": 3},
            "targets": [],
            "gaps": [],
            "recommendedNextSteps": [],
            "sections": [section],
        }

        html = render_layer_report(context, "html")
        markdown = render_layer_report(context, "markdown")

        self.assertIn('class="tree signal-tree"', html)
        self.assertIn("SPA Route", html)
        self.assertIn("RPC Command Group", html)
        self.assertIn("Filter JavaScript signals", html)
        self.assertNotIn("<th", html.split("JavaScript Signals", 1)[1])
        self.assertIn("**SPA Route (2 signals)**", markdown)
        self.assertIn("`OFE:ALTA`", markdown)

    def test_documentation_builds_contexts_with_safe_redaction(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                ingested = workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "operator_note",
                    "note",
                    "text",
                    "Authorization: Bearer secret-token\nReviewed profile endpoint.",
                    {"token": "secret-token", "requestRef": "manual"},
                )
                finding = workspace.create_finding(
                    "engagement",
                    "app.example.com",
                    "Broken Object Level Authorization in Profile Endpoint",
                    severity="high",
                    confidence="medium",
                    description="Profile endpoint accepted an object reference from another account.",
                    evidence_ids=[ingested["evidenceId"]],
                    status="confirmed",
                    reproduction_steps=["Authenticate as user A.", "Request user B profile object."],
                    impact="A user may access another user's profile data.",
                    remediation="Enforce object ownership checks server-side.",
                )["finding"]

                context = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_finding_context",
                        {
                            "workspaceId": "engagement",
                            "target": "app.example.com",
                            "findingId": finding["id"],
                            "redactionMode": "safe",
                            "includeRawHttp": True,
                        },
                    )
                )

                finding_context = context["findingContext"]
                self.assertEqual(finding_context["finding"]["severity"], "high")
                self.assertEqual(finding_context["evidence"][0]["metadata"]["token"], "[REDACTED]")
                self.assertNotIn("rawPath", finding_context["evidence"][0])
                self.assertNotIn("raw", finding_context["evidence"][0])
                self.assertIn("sha256", finding_context["evidence"][0])

                draft = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_finding_draft",
                        {
                            "workspaceId": "engagement",
                            "target": "app.example.com",
                            "findingId": finding["id"],
                        },
                    )
                )
                self.assertEqual(draft["draft"]["title"], finding["title"])
                self.assertEqual(draft["draft"]["evidence"][0]["evidenceId"], ingested["evidenceId"])

    def test_documentation_does_not_read_raw_evidence_outside_target_evidence_dir(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                ingested = workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "operator_note",
                    "note",
                    "text",
                    "inside evidence",
                )
                finding = workspace.create_finding(
                    "engagement",
                    "app.example.com",
                    "Evidence Path Tamper Test",
                    evidence_ids=[ingested["evidenceId"]],
                )["finding"]
                outside_dir = workspace.workspace_path("engagement").parent / "engagement-malicious" / "targets" / "app.example.com" / "evidence"
                outside_dir.mkdir(parents=True)
                outside_raw = outside_dir / "outside_raw.txt"
                outside_raw.write_text("outside secret evidence", encoding="utf-8")

                meta_path = workspace.target_path("engagement", "app.example.com") / "evidence" / f"{ingested['evidenceId']}.json"
                metadata = json.loads(meta_path.read_text(encoding="utf-8"))
                metadata["rawPath"] = str(outside_raw)
                meta_path.write_text(json.dumps(metadata), encoding="utf-8")

                context = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_finding_context",
                        {
                            "workspaceId": "engagement",
                            "target": "app.example.com",
                            "findingId": finding["id"],
                            "redactionMode": "raw",
                            "includeRawHttp": True,
                        },
                    )
                )

                evidence = context["findingContext"]["evidence"][0]
                self.assertNotIn("raw", evidence)
                self.assertNotIn("sha256", evidence)

    def test_documentation_renders_markdown_and_exports_json(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "endpoints": [{"type": "endpoint", "url": "https://app.example.com/profile?id=1", "method": "GET"}],
                                "observations": [{"type": "ssti_candidate", "value": "https://app.example.com/profile", "priorityScore": 55}],
                            }
                        }
                    ),
                )

                templates = json.loads(stdio_server.call_tool("documentation.list_templates", {}))
                template_ids = {item["templateId"] for item in templates["templates"]}
                self.assertIn("standard_markdown_report", template_ids)
                self.assertIn("assessment_summary_report", template_ids)

                coverage = json.loads(stdio_server.call_tool("documentation.summarize_coverage", {"workspaceId": "engagement"}))
                self.assertIn("ssti", coverage["coverage"]["passiveOnlyModules"])
                self.assertIn("app.example.com", coverage["coverage"]["targetsWithTraffic"])

                rendered = json.loads(
                    stdio_server.call_tool(
                        "documentation.render_markdown",
                        {
                            "workspaceId": "engagement",
                            "contextType": "report",
                            "template": "standard_markdown_report",
                            "outputPath": "reports/report.md",
                        },
                    )
                )
                self.assertIn("# engagement Report", rendered["content"])
                self.assertTrue(Path(rendered["path"]).exists())

                exported = json.loads(
                    stdio_server.call_tool(
                        "documentation.export_json",
                        {
                            "workspaceId": "engagement",
                            "contextType": "coverage",
                            "outputPath": "reports/coverage.json",
                        },
                    )
                )
                self.assertEqual(exported["format"], "json")
                self.assertTrue(Path(exported["path"]).exists())

                blocked = stdio_server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "documentation.export_json",
                            "arguments": {
                                "workspaceId": "engagement",
                                "contextType": "coverage",
                                "outputPath": str(Path(tmp) / "outside.json"),
                            },
                        },
                    }
                )
                self.assertIsNotNone(blocked)
                self.assertEqual(blocked["error"]["code"], -32602)
                self.assertIn("allowExternalOutput", blocked["error"]["message"])

                sibling = stdio_server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "documentation.export_json",
                            "arguments": {
                                "workspaceId": "engagement",
                                "contextType": "coverage",
                                "outputPath": str(workspace.workspace_path("engagement").parent / "engagement-malicious" / "coverage.json"),
                            },
                        },
                    }
                )
                self.assertIsNotNone(sibling)
                self.assertEqual(sibling["error"]["code"], -32602)
                self.assertIn("allowExternalOutput", sibling["error"]["message"])

    def test_documentation_renders_assessment_summary_report(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com", "api.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "services": [
                                    {
                                        "type": "service",
                                        "host": "app.example.com",
                                        "port": 443,
                                        "name": "https",
                                        "product": "nginx",
                                        "version": "1.25",
                                    }
                                ],
                                "observations": [
                                    {
                                        "type": "open_redirect_candidate",
                                        "value": "https://app.example.com/login?next=/",
                                        "testPlanSummary": "Validate harmless off-site redirect behavior.",
                                    }
                                ],
                            }
                        }
                    ),
                )
                finding = workspace.create_finding(
                    "engagement",
                    "app.example.com",
                    "Missing Security Header",
                    severity="low",
                    confidence="high",
                    description="A response was missing a recommended security header.",
                    status="confirmed",
                    operator_reviewed=True,
                )["finding"]
                workspace.record_action(
                    "engagement",
                    "app.example.com",
                    {
                        "type": "tool_run",
                        "tool": "nuclei",
                        "profile": {"id": "low_noise", "options": {"rateLimit": 1}},
                        "target": "app.example.com",
                        "returnCode": 0,
                    },
                )

                rendered = json.loads(
                    stdio_server.call_tool(
                        "documentation.render_assessment_summary",
                        {
                            "workspaceId": "engagement",
                            "assessmentType": "Web Application Assessment",
                            "outputPath": "reports/assessment-summary.md",
                        },
                    )
                )

                self.assertEqual(rendered["templateId"], "assessment_summary_report")
                self.assertIn("# Assessment Summary Report", rendered["content"])
                self.assertIn("## 2. Technologies Detected", rendered["content"])
                self.assertIn("nginx 1.25 https", rendered["content"])
                self.assertIn("## 3. Actions Performed", rendered["content"])
                self.assertIn("nuclei", rendered["content"])
                self.assertNotIn("{'", rendered["content"])
                self.assertIn("## 4. Findings", rendered["content"])
                self.assertIn(finding["title"], rendered["content"])
                self.assertIn("open_redirect_candidate", rendered["content"])
                self.assertTrue(Path(rendered["path"]).exists())

                default_rendered = json.loads(
                    stdio_server.call_tool(
                        "documentation.render_assessment_summary",
                        {
                            "workspaceId": "engagement",
                            "assessmentType": "Web Application Assessment",
                        },
                    )
                )
                self.assertEqual(Path(default_rendered["path"]).name, "assessment-summary.md")
                self.assertEqual(Path(default_rendered["path"]).parent.name, "reports")

                nested_data = stdio_server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "documentation.render_assessment_summary",
                            "arguments": {
                                "workspaceId": "engagement",
                                "outputPath": "DATA/workspaces/engagement/reports/assessment-summary.md",
                            },
                        },
                    }
                )
                self.assertIsNotNone(nested_data)
                self.assertEqual(nested_data["error"]["code"], -32602)
                self.assertIn("workspace-relative", nested_data["error"]["message"])

    def test_documentation_renders_normalized_layer_and_workspace_reports(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "services": [
                                    {
                                        "type": "service",
                                        "host": "app.example.com",
                                        "port": 443,
                                        "protocol": "tcp",
                                        "name": "https",
                                        "product": "nginx",
                                        "version": "1.25",
                                    }
                                ],
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/login",
                                        "path": "/login",
                                        "method": "POST",
                                        "status": 200,
                                        "inputNames": ["username", "password"],
                                    },
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/api/users/123",
                                        "path": "/api/users/123",
                                        "method": "GET",
                                        "status": 200,
                                        "cookieNames": ["SESSIONID"],
                                    },
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/api/admin/users",
                                        "path": "/api/admin/users",
                                        "method": "GET",
                                        "source": "js_intelligence",
                                        "derived": True,
                                        "inferred": True,
                                        "sourceAsset": "https://app.example.com/static/app.js",
                                        "confidence": "medium",
                                    },
                                ],
                                "parameters": [
                                    {
                                        "type": "parameter",
                                        "name": "user_id",
                                        "location": "path",
                                        "method": "GET",
                                        "url": "https://app.example.com/api/users/123",
                                    }
                                ],
                                "observations": [
                                    {
                                        "type": "js_storage_key",
                                        "value": "accessToken",
                                        "confidence": "medium",
                                        "sourceAsset": "https://app.example.com/static/app.js",
                                        "reason": "Client-side storage key found during static analysis.",
                                    }
                                ],
                            }
                        }
                    ),
                )
                access_dir = workspace.target_model_dir("engagement", "app.example.com", "access-control")
                workspace._write_json(
                    access_dir / "objects.json",
                    [
                        {
                            "objectId": "obj_user",
                            "objectType": "user",
                            "method": "GET",
                            "endpointPattern": "/api/users/{user_id}",
                            "identifierName": "user_id",
                            "location": "path",
                            "testClass": "BOLA",
                            "priority": "high",
                            "reason": "Path contains user identifier.",
                        }
                    ],
                )
                workspace._write_json(
                    access_dir / "contexts.json",
                    [
                        {"contextId": "user_a", "label": "User A", "role": "user", "authState": "authenticated", "credentialId": "cred-a"},
                        {"contextId": "admin", "label": "Admin", "role": "admin", "authState": "authenticated", "credentialId": "cred-admin"},
                    ],
                )
                workspace._write_json(
                    access_dir / "matrix.json",
                    [
                        {
                            "matrixId": "acm_user",
                            "testClass": "BOLA",
                            "method": "GET",
                            "endpointPattern": "/api/users/{user_id}",
                            "requiredContexts": ["user_a", "admin"],
                            "riskTier": "medium",
                        }
                    ],
                )

                layers = json.loads(stdio_server.call_tool("documentation.list_layers", {}))
                self.assertEqual({item["layer"] for item in layers["layers"]}, {"perimeter", "js", "auth", "access_control", "web_vulnerabilities", "cve", "engagement"})

                templates = json.loads(stdio_server.call_tool("documentation.list_templates", {"contextType": "layer_report"}))
                self.assertIn("standard_layer_report", {item["templateId"] for item in templates["templates"]})

                context = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_layer_report_context",
                        {"workspaceId": "engagement", "target": "app.example.com", "layer": "access_control"},
                    )
                )
                self.assertEqual(context["contextType"], "layer_report")
                self.assertEqual(context["layerReport"]["layer"], "access_control")
                self.assertEqual(context["layerReport"]["summary"]["objectCount"], 1)
                self.assertEqual(context["layerReport"]["summary"]["matrixCount"], 1)

                js_report = json.loads(
                    stdio_server.call_tool(
                        "documentation.render_layer_report",
                        {
                            "workspaceId": "engagement",
                            "target": "app.example.com",
                            "layer": "js",
                            "outputPath": "reports/js-layer.html",
                            "returnContent": True,
                        },
                    )
                )
                self.assertEqual(js_report["format"], "html")
                self.assertIn("JavaScript Intelligence Report", js_report["content"])
                self.assertIn('class="banner"', js_report["content"])
                self.assertIn('class="banner-art"', js_report["content"])
                self.assertIn("agentic operations layer", js_report["content"])
                self.assertIn("js_inferred", js_report["content"])
                self.assertIn("accessToken", js_report["content"])
                assert_shared_html_shell(self, js_report["content"])
                self.assertTrue(Path(js_report["path"]).exists())

                workspace_report = json.loads(
                    stdio_server.call_tool(
                        "documentation.render_workspace_report",
                        {
                            "workspaceId": "engagement",
                            "layers": ["perimeter", "js", "auth", "access_control", "web_vulnerabilities"],
                            "outputPath": "reports/workspace-report.html",
                            "returnContent": True,
                        },
                    )
                )
                self.assertEqual(workspace_report["format"], "html")
                # Default render is now the full operator view (high-level is an opt-in).
                self.assertIn("Synapse Security Report", workspace_report["content"])
                self.assertIn('<body class="operator', workspace_report["content"])
                self.assertIn('class="banner"', workspace_report["content"])
                self.assertIn("Operator Report", workspace_report["content"])
                self.assertIn("High-Level", workspace_report["content"])
                self.assertIn("Application Surface Report", workspace_report["content"])
                self.assertIn("Authentication Surface Report", workspace_report["content"])
                self.assertIn("Access Control Report", workspace_report["content"])
                self.assertIn("Expand all", workspace_report["content"])
                assert_shared_html_shell(self, workspace_report["content"])
                # Consolidated reports no longer skip sections: both trees render.
                self.assertIn("Site Map", workspace_report["content"])
                self.assertIn("Request Map", workspace_report["content"])
                self.assertEqual(workspace_report["content"].count("Recommended Next Steps"), 1)
                self.assertIn('class="table-wrap"', workspace_report["content"])
                self.assertNotIn("<colgroup>", workspace_report["content"])
                self.assertTrue(Path(workspace_report["path"]).exists())

                blocked = stdio_server.handle(
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/call",
                        "params": {
                            "name": "documentation.render_layer_report",
                            "arguments": {
                                "workspaceId": "engagement",
                                "layer": "perimeter",
                                "outputPath": "DATA/workspaces/engagement/reports/perimeter-layer.html",
                            },
                        },
                    }
                )
                self.assertIsNotNone(blocked)
                self.assertEqual(blocked["error"]["code"], -32602)
                self.assertIn("workspace-relative", blocked["error"]["message"])

    def test_workspace_report_always_renders_access_control_with_empty_state(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/login",
                                        "path": "/login",
                                        "method": "GET",
                                        "status": 200,
                                    }
                                ]
                            }
                        }
                    ),
                )

                context = json.loads(
                    stdio_server.call_tool(
                        "documentation.build_layer_report_context",
                        {"workspaceId": "engagement", "target": "app.example.com", "layer": "access_control"},
                    )
                )
                # The access-control layer now always emits its full canonical section set.
                self.assertEqual(context["layerReport"]["summary"]["objectCount"], 0)
                self.assertEqual(
                    [section["sectionId"] for section in context["layerReport"]["sections"]],
                    ["objects", "contexts", "matrix", "replays", "candidates"],
                )

                workspace_report = json.loads(
                    stdio_server.call_tool(
                        "documentation.render_workspace_report",
                        {
                            "workspaceId": "engagement",
                            "layers": ["perimeter", "access_control"],
                            "outputPath": "reports/workspace-no-access-control.html",
                            "returnContent": True,
                        },
                    )
                )
                self.assertIn("Application Surface Report", workspace_report["content"])
                # Access control is always rendered, with explicit empty-state lines.
                self.assertIn("Access Control Report", workspace_report["content"])
                self.assertIn("Replay Results", workspace_report["content"])
                self.assertIn('class="empty-state"', workspace_report["content"])
                self.assertIn("No replay results recorded.", workspace_report["content"])
                self.assertIn("Site Map", workspace_report["content"])
                self.assertIn("/login", workspace_report["content"])
                self.assertNotIn("No tree records.", workspace_report["content"])
                self.assertEqual(workspace_report["content"].count("Recommended Next Steps"), 1)
                self.assertTrue(Path(workspace_report["path"]).exists())

    def test_internal_high_level_view_hides_operator_noise_with_css_only(self) -> None:
        cred_id = "cred-admin-test"
        approval_id = "approval-access-control-123"
        unix_path = "/tmp/synapse/workspaces/client/evidence/app.js"
        windows_path = "C:\\Users\\operator\\synapse\\workspace\\artifact.js"
        # Asset local paths are shown workspace-relative (no absolute/home prefix).
        unix_short = "workspaces/client/evidence/app.js"
        windows_short = "artifact.js"
        asset_url = "https://app.example.com/static/app.js"
        leaks = [cred_id, approval_id]
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/api/users/123",
                                        "path": "/api/users/123",
                                        "method": "GET",
                                        "status": 200,
                                    }
                                ]
                            }
                        }
                    ),
                )
                access_dir = workspace.target_model_dir("engagement", "app.example.com", "access-control")
                workspace._write_json(
                    access_dir / "objects.json",
                    [
                        {
                            "objectId": "obj_user",
                            "objectType": "user",
                            "method": "GET",
                            "endpointPattern": "/api/users/{user_id}",
                            "identifierName": "user_id",
                            "location": "path",
                            "testClass": "BOLA",
                            "priority": "high",
                            "reason": "Path contains user identifier.",
                        }
                    ],
                )
                workspace._write_json(
                    access_dir / "contexts.json",
                    [
                        {"contextId": "user_a", "label": "User A", "role": "user", "authState": "authenticated", "credentialId": "cred-user-a"},
                        {"contextId": "admin", "label": "Admin", "role": "admin", "authState": "authenticated", "credentialId": cred_id},
                    ],
                )
                workspace._write_json(
                    access_dir / "matrix.json",
                    [
                        {
                            "matrixId": "acm_user",
                            "testClass": "BOLA",
                            "method": "GET",
                            "endpointPattern": "/api/users/{user_id}",
                            "requiredContexts": ["user_a", "admin"],
                            "riskTier": "medium",
                        }
                    ],
                )
                workspace._write_json(
                    access_dir / "replays.json",
                    [
                        {
                            "replayId": "rep_user",
                            "matrixId": "acm_user",
                            "testClass": "BOLA",
                            "method": "GET",
                            "endpointPattern": "/api/users/{user_id}",
                            "assessment": "confirmed_bola",
                            "approval": {"approvalId": approval_id},
                        }
                    ],
                )
                js_intel._write_json_artifact(
                    "engagement",
                    "app.example.com",
                    "manifests",
                    "fetched-assets.json",
                    {
                        "source": "js_intel",
                        "workspaceId": "engagement",
                        "target": "app.example.com",
                        "assets": [
                            {"url": asset_url, "localPath": unix_path, "sha256": "abc123", "size": 1024, "status": 200, "contentType": "application/javascript"},
                            {"url": "https://app.example.com/static/vendor.js", "localPath": windows_path, "sha256": "def456", "size": 2048, "status": 200, "contentType": "application/javascript"},
                        ],
                    },
                )

                def _layer(layer: str, mode: str) -> dict:
                    return json.loads(
                        stdio_server.call_tool(
                            "documentation.build_layer_report_context",
                            {"workspaceId": "engagement", "target": "app.example.com", "layer": layer, "redactionMode": mode},
                        )
                    )["layerReport"]

                # high-level/internal context keeps operational values; generated HTML hides noisy columns with CSS only.
                high_ac = _layer("access_control", "high_level")
                high_ac_sections = {section["sectionId"]: section for section in high_ac["sections"]}
                self.assertIn(cred_id, json.dumps(high_ac))
                self.assertIn(approval_id, json.dumps(high_ac))
                self.assertIn("Credential ID", high_ac_sections["contexts"]["headers"])
                self.assertIn("Approval ID", high_ac_sections["replays"]["headers"])
                self.assertIn("/api/users/{user_id}", json.dumps(high_ac))
                self.assertIn("admin", json.dumps(high_ac))
                self.assertIn("confirmed_bola", json.dumps(high_ac))

                # raw access-control keeps the operational references as columns.
                raw_ac = _layer("access_control", "raw")
                raw_ac_sections = {section["sectionId"]: section for section in raw_ac["sections"]}
                self.assertIn(cred_id, json.dumps(raw_ac))
                self.assertIn(approval_id, json.dumps(raw_ac))
                self.assertIn("Credential ID", raw_ac_sections["contexts"]["headers"])
                self.assertIn("Approval ID", raw_ac_sections["replays"]["headers"])

                # internal keeps the approval reference but never secret values.
                internal_ac = _layer("access_control", "internal")
                self.assertIn(approval_id, json.dumps(internal_ac))

                # high-level JS context keeps the (workspace-relative) local paths; the HTML view only hides the column visually.
                high_js = _layer("js", "high_level")
                high_js_sections = {section["sectionId"]: section for section in high_js["sections"]}
                self.assertIn(unix_short, json.dumps(high_js))
                self.assertNotIn(unix_path, json.dumps(high_js))
                self.assertIn("Local Path", high_js_sections["assets"]["headers"])
                self.assertIn(asset_url, json.dumps(high_js))

                # raw js retains the local path column.
                raw_js = _layer("js", "raw")
                raw_js_sections = {section["sectionId"]: section for section in raw_js["sections"]}
                self.assertIn(unix_short, json.dumps(raw_js))
                self.assertIn("Local Path", raw_js_sections["assets"]["headers"])
                raw_js_report = json.loads(
                    stdio_server.call_tool(
                        "documentation.render_layer_report",
                        {
                            "workspaceId": "engagement",
                            "target": "app.example.com",
                            "layer": "js",
                            "redactionMode": "raw",
                            "format": "html",
                            "outputPath": "reports/raw-js.html",
                            "returnContent": True,
                        },
                    )
                )
                self.assertIn(windows_short, raw_js_report["content"])

                # A full high-level HTML report is internal. Operational values remain in the source,
                # while CSS selectors provide presentation-density switching.
                report = json.loads(
                    stdio_server.call_tool(
                        "documentation.render_workspace_report",
                        {
                            "workspaceId": "engagement",
                            "layers": ["js", "access_control"],
                            "redactionMode": "high_level",
                            "format": "html",
                            "outputPath": "reports/internal-workspace.html",
                            "returnContent": True,
                        },
                    )
                )
                for value in leaks:
                    self.assertIn(value, report["content"])
                self.assertIn("operator-only", report["content"])
                self.assertIn("body.high-level .operator-only", report["content"])
                self.assertIn("CSS hiding in this report is only for internal presentation-density switching", report["content"])
                self.assertIn("app.example.com", report["content"])
                self.assertIn("/api/users/{user_id}", report["content"])
                self.assertIn(asset_url, report["content"])

    def test_is_active_action_classifies_conservatively(self) -> None:
        self.assertFalse(is_active_action({"type": "tool_run", "tool": "documentation.render_markdown"}))
        self.assertFalse(is_active_action({"type": "operator_note", "tool": "operator_note"}))
        self.assertFalse(is_active_action({"type": "tool_run", "tool": "js.analyze_assets"}))
        self.assertFalse(is_active_action({"type": "tool_run", "tool": "sitemap.from_dump"}))
        self.assertTrue(is_active_action({"type": "active_validation", "tool": "ssti.validate", "approval": {"approvalId": "ap-1"}}))
        self.assertTrue(is_active_action({"type": "tool_run", "tool": "nuclei", "approval": {"approvalId": "ap-2"}}))
        self.assertTrue(is_active_action({"type": "tool_run", "tool": "nmap"}))
        self.assertTrue(is_active_action({"type": "http_request", "tool": "crawler.extended"}))
        self.assertTrue(is_active_action({"type": "tool_run", "tool": "custom", "sendsTraffic": True}))

    def test_coverage_prefers_workspace_scope_then_falls_back_to_global(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("scoped", organization="Example Corp", hosts=["app.example.com"])
                scope.save_scope(["other.example.com"], "test", "Example Client")
                coverage = json.loads(stdio_server.call_tool("documentation.summarize_coverage", {"workspaceId": "scoped"}))["coverage"]
                self.assertEqual(coverage["targetsInScope"], ["app.example.com"])
                self.assertNotIn("other.example.com", coverage["targetsInScope"])

        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("unscoped", organization="Example Corp")
                scope.save_scope(["global.example.com"], "test", "Example Client")
                coverage = json.loads(stdio_server.call_tool("documentation.summarize_coverage", {"workspaceId": "unscoped"}))["coverage"]
                self.assertIn("global.example.com", coverage["targetsInScope"])

    def test_coverage_counts_only_active_actions_as_active(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps({"entities": {"endpoints": [{"type": "endpoint", "url": "https://app.example.com/x", "path": "/x", "method": "GET"}]}}),
                )
                workspace.record_action("engagement", "app.example.com", {"type": "tool_run", "tool": "documentation.summarize_coverage"})
                workspace.record_action(
                    "engagement",
                    "app.example.com",
                    {"type": "active_validation", "tool": "access_control.execute_matrix_test", "approval": {"approvalId": "ap-1", "riskTier": "medium"}},
                )
                coverage = json.loads(stdio_server.call_tool("documentation.summarize_coverage", {"workspaceId": "engagement"}))["coverage"]
                self.assertIn("access_control", coverage["activeModules"])
                self.assertNotIn("documentation", coverage["activeModules"])
                self.assertIn("app.example.com", coverage["targetsScanned"])
                self.assertIn("access_control", coverage["adaptersUsed"])
                self.assertIn("documentation", coverage["adaptersUsed"])

    def test_coverage_distinguishes_analyzed_empty_from_never_analyzed(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps({"entities": {"endpoints": [{"type": "endpoint", "url": "https://app.example.com/health", "path": "/health", "method": "GET"}]}}),
                )
                gap = "No graphql passive candidate analysis is recorded for app.example.com."

                before = json.loads(stdio_server.call_tool("documentation.summarize_coverage", {"workspaceId": "engagement"}))["coverage"]
                self.assertIn(gap, before["untestedAreas"])

                result = json.loads(stdio_server.call_tool("graphql.analyze_workspace", {"workspaceId": "engagement", "target": "app.example.com"}))
                self.assertEqual(result["candidateCount"], 0)
                after = json.loads(stdio_server.call_tool("documentation.summarize_coverage", {"workspaceId": "engagement"}))["coverage"]
                self.assertIn("graphql", after["adaptersUsed"])
                self.assertNotIn("graphql", after["activeModules"])
                self.assertNotIn(gap, after["untestedAreas"])

    def test_consolidated_html_report_has_internal_operator_high_level_toggle(self) -> None:
        cred_id = "cred-admin-test"
        approval_id = "approval-access-control-123"
        unix_path = "/tmp/synapse/workspaces/client/evidence/app.js"
        windows_path = "C:\\Users\\operator\\synapse\\workspace\\artifact.js"
        unix_short = "workspaces/client/evidence/app.js"
        windows_short = "artifact.js"
        asset_url = "https://app.example.com/static/app.js"
        secret_value = "SUPERSECRETVALUE0001"
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                scope.save_scope(["app.example.com"], "test", "Example Corp")
                credentials.save_credential({"id": "cred-operator", "type": "bearer", "scopes": ["app.example.com"], "secret": secret_value})
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps({"entities": {"endpoints": [{"type": "endpoint", "url": "https://app.example.com/api/users/123", "path": "/api/users/123", "method": "GET", "status": 200}]}}),
                )
                access_dir = workspace.target_model_dir("engagement", "app.example.com", "access-control")
                workspace._write_json(access_dir / "objects.json", [{"objectId": "obj_user", "objectType": "user", "method": "GET", "endpointPattern": "/api/users/{user_id}", "identifierName": "user_id", "location": "path", "testClass": "BOLA", "priority": "high", "reason": "id"}])
                workspace._write_json(access_dir / "contexts.json", [{"contextId": "admin", "label": "Admin", "role": "admin", "authState": "authenticated", "credentialId": cred_id}])
                workspace._write_json(access_dir / "matrix.json", [{"matrixId": "acm_user", "testClass": "BOLA", "method": "GET", "endpointPattern": "/api/users/{user_id}", "requiredContexts": ["admin"], "riskTier": "medium"}])
                workspace._write_json(access_dir / "replays.json", [{"replayId": "rep_user", "matrixId": "acm_user", "testClass": "BOLA", "method": "GET", "endpointPattern": "/api/users/{user_id}", "assessment": "confirmed_bola", "approval": {"approvalId": approval_id}}])
                js_intel._write_json_artifact("engagement", "app.example.com", "manifests", "fetched-assets.json", {
                    "source": "js_intel", "workspaceId": "engagement", "target": "app.example.com",
                    "assets": [{"url": asset_url, "localPath": unix_path, "sha256": "abc", "size": 1, "status": 200, "contentType": "application/javascript"}, {"url": "https://app.example.com/v.js", "localPath": windows_path, "sha256": "def", "size": 2, "status": 200, "contentType": "application/javascript"}],
                })

                def render(mode: str) -> str:
                    return json.loads(
                        stdio_server.call_tool(
                            "documentation.render_workspace_report",
                            {
                                "workspaceId": "engagement",
                                "layers": ["perimeter", "js", "auth", "access_control", "web_vulnerabilities"],
                                "redactionMode": mode,
                                "format": "html",
                                "outputPath": f"reports/{mode}.html",
                                "returnContent": True,
                            },
                        )
                    )["content"]

                operator = render("internal")
                high = render("high_level")

                # Both generated files are internal HTML reports with the same Operator / High-Level toggle.
                canonical_titles = (
                    "Object And Function Candidates",
                    "Recorded User/Role Contexts",
                    "Access-Control Test Matrix",
                    "Replay Results",
                    "Access-Control Candidate Observations",
                    "JavaScript Assets",
                )
                for content in (operator, high):
                    self.assertTrue(content.startswith("<!doctype html>"))
                    self.assertIn('class="report-toc"', content)
                    self.assertIn('class="layer"', content)
                    # The "Object And Function Candidates" table must render as a table, not be
                    # mis-rendered as candidate callouts just because its title contains "candidates".
                    self.assertNotIn('class="finding candidate-observation"', content)
                    self.assertIn("agentic operations layer", content)
                    self.assertIn("mode-badge", content)
                    self.assertIn("setMode", content)
                    self.assertIn("aria-pressed", content)
                    self.assertIn("Operator Report", content)
                    self.assertIn("High-Level", content)
                    self.assertIn("Internal Summary", content)
                    self.assertIn("body.high-level .operator-only", content)
                    self.assertIn("body.operator .high-level-only", content)
                    self.assertIn("@media print", content)
                    self.assertIn("CSS hiding in this report is only for internal presentation-density switching", content)
                    self.assertIn("not a security or client-deliverable redaction mechanism", content)
                    self.assertNotIn("Client-facing", content)
                    self.assertNotIn("External Deliverable", content)
                    self.assertNotIn("Safe Report", content)
                    # Operator opted into design-template fonts (with system fallback).
                    self.assertIn("fonts.googleapis.com", content)
                    self.assertIn("system-ui", content)
                    for title in canonical_titles:
                        self.assertIn(title, content)
                    self.assertNotIn(secret_value, content)
                    self.assertIn(asset_url, content)
                    self.assertIn("/api/users/{user_id}", content)

                # Operational references are present in source; high-level is not a redacted deliverable.
                self.assertIn(approval_id, operator)
                self.assertIn(cred_id, operator)
                self.assertIn(approval_id, high)
                self.assertIn(cred_id, high)
                self.assertIn(unix_short, high)
                self.assertIn(windows_short, high)
                self.assertNotIn(unix_path, high)

    def test_workspace_report_includes_access_control_replays_and_candidates(self) -> None:
        with TemporaryDirectory() as tmp:
            with isolated_state(Path(tmp)):
                workspace.create_workspace("engagement", organization="Example Corp", hosts=["app.example.com"])
                workspace.ingest_data(
                    "engagement",
                    "app.example.com",
                    "adapter_result",
                    "adapter_result",
                    "json",
                    json.dumps(
                        {
                            "entities": {
                                "endpoints": [
                                    {
                                        "type": "endpoint",
                                        "url": "https://app.example.com/api/users/123",
                                        "path": "/api/users/123",
                                        "method": "GET",
                                        "status": 200,
                                    }
                                ],
                                "observations": [
                                    {
                                        "type": "access_control_idor_candidate",
                                        "value": "/api/users/{user_id} cross-context access",
                                        "confidence": "high",
                                        "priority": "high",
                                        "reason": "User-scoped object reachable across contexts.",
                                    }
                                ],
                            }
                        }
                    ),
                )
                access_dir = workspace.target_model_dir("engagement", "app.example.com", "access-control")
                workspace._write_json(
                    access_dir / "objects.json",
                    [
                        {
                            "objectId": "obj_user",
                            "objectType": "user",
                            "method": "GET",
                            "endpointPattern": "/api/users/{user_id}",
                            "identifierName": "user_id",
                            "location": "path",
                            "testClass": "BOLA",
                            "priority": "high",
                            "reason": "Path contains user identifier.",
                        }
                    ],
                )
                workspace._write_json(
                    access_dir / "contexts.json",
                    [
                        {"contextId": "user_a", "label": "User A", "role": "user", "authState": "authenticated", "credentialId": "cred-a"},
                        {"contextId": "admin", "label": "Admin", "role": "admin", "authState": "authenticated", "credentialId": "cred-admin"},
                    ],
                )
                workspace._write_json(
                    access_dir / "matrix.json",
                    [
                        {
                            "matrixId": "acm_user",
                            "testClass": "BOLA",
                            "method": "GET",
                            "endpointPattern": "/api/users/{user_id}",
                            "requiredContexts": ["user_a", "admin"],
                            "riskTier": "medium",
                        }
                    ],
                )
                workspace._write_json(
                    access_dir / "replays.json",
                    [
                        {
                            "replayId": "rep_user",
                            "matrixId": "acm_user",
                            "testClass": "BOLA",
                            "method": "GET",
                            "endpointPattern": "/api/users/{user_id}",
                            "assessment": "confirmed_bola",
                            "approval": {"approvalId": "approval-123"},
                        }
                    ],
                )

                for fmt, suffix in (("html", "html"), ("markdown", "md")):
                    report = json.loads(
                        stdio_server.call_tool(
                            "documentation.render_workspace_report",
                            {
                                "workspaceId": "engagement",
                                "layers": ["access_control"],
                                "redactionMode": "internal",
                                "format": fmt,
                                "outputPath": f"reports/ac-workspace.{suffix}",
                                "returnContent": True,
                            },
                        )
                    )
                    content = report["content"]
                    # The replay and candidate sections (which used to be dropped by [:3]) are present.
                    self.assertIn("Replay Results", content)
                    self.assertIn("confirmed_bola", content)
                    self.assertIn("Access-Control Candidate Observations", content)
                    self.assertIn("cross-context access", content)
                    # And the report does not stop at the matrix section.
                    self.assertLess(content.index("Access-Control Test Matrix"), content.index("Replay Results"))


class RedactionFieldNameTests(unittest.TestCase):
    def test_numeric_aggregate_under_sensitive_label_is_not_redacted(self) -> None:
        # The sensitive-field-name heuristic guards secret *values*. A per-module candidate
        # count under a label like "Headers Cookies" (marker contains "cookie") is an aggregate,
        # not a secret, and must survive redaction even with credentials excluded; a string
        # secret under the same kind of key still does not.
        from synapse_mcp.core.documentation import redaction

        policy = redaction.policy_from_args({"redactionMode": "internal"})
        result = redaction.redact({"headers_cookies": 25, "token": "secret-value"}, policy)
        self.assertEqual(result["headers_cookies"], 25)
        self.assertEqual(result["token"], "[REDACTED]")


class TechnologyItemFilterTests(unittest.TestCase):
    def test_bare_service_name_guess_is_not_a_technology(self) -> None:
        # A productless nmap service ("ppp" on 3000) and a stale low-confidence service-sourced
        # technology_component observation are port-table guesses, not detected technologies, and
        # must not appear in the assessment-summary Technologies table.
        from synapse_mcp.core.documentation.builder import _technology_items

        services = [
            {"type": "service", "host": "h", "port": 3000, "name": "ppp"},
            {"type": "service", "host": "h", "port": 443, "name": "https", "product": "nginx", "version": "1.25"},
        ]
        observations = [
            {"type": "technology_component", "name": "ppp", "source": "service", "confidence": "low"},
            {"type": "technology_component", "name": "OWASP Juice Shop", "source": "response_header", "confidence": "high"},
        ]
        names = {item["name"] for item in _technology_items(services, observations)}
        self.assertNotIn("ppp", names)
        self.assertTrue(any("nginx" in name for name in names))
        self.assertIn("OWASP Juice Shop", names)


if __name__ == "__main__":
    unittest.main()
