# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Protocol-free retained dispatch for the independently loadable core pack."""

from __future__ import annotations

import json
from typing import Any

from synapse_mcp.core import (
    background_jobs,
    cache,
    credentials,
    dumps,
    evidence,
    scope,
    workspace,
)
from synapse_mcp.core.adapters import default_registry as adapter_registry
from synapse_mcp.core.errors import McpError

from .adapter_metadata import derive_adapter_operational_metadata
from .legacy_bridge import bind_retained_legacy_implementation
from .registry import ActionRegistry


def bind_core_retained_implementation(registry: ActionRegistry) -> None:
    """Bind only core implementation modules for a core-only modern process."""

    adapter_registry.set_action_metadata_provider(
        lambda action_ids: derive_adapter_operational_metadata(
            action_ids,
            registry=registry,
        )
    )
    bind_retained_legacy_implementation(core_retained_call)


def core_retained_call(name: str, args: dict[str, Any]) -> str:
    if name == "jobs.list":
        return json.dumps(
            background_jobs.list_jobs(
                int(args.get("limit", 20)),
                bool(args.get("activeOnly", False)),
                str(args.get("workspaceId", "")),
                bool(args.get("includeResult", False)),
            ),
            indent=2,
        )
    if name == "jobs.status":
        return json.dumps(
            background_jobs.status(args["jobId"], bool(args.get("includeResult", False))),
            indent=2,
        )
    if name == "jobs.cancel":
        return json.dumps(background_jobs.cancel(args["jobId"]), indent=2)
    if name == "adapters.list":
        return json.dumps({"adapters": adapter_registry.list()}, indent=2)
    if name == "adapters.capabilities":
        return json.dumps(adapter_registry.capabilities(args["adapter"]), indent=2)
    if name == "scope.set":
        result = scope.save_scope(
            args["hosts"],
            args.get("notes", ""),
            args.get("organization", ""),
            args.get("patterns"),
            args.get("cidrs"),
            cursor=args.get("cursor"),
            limit=int(args.get("inventoryLimit", 50)),
            include_inventory=bool(args.get("includeInventory", False)),
        )
        if args.get("workspaceId"):
            result["workspace"] = workspace.create_workspace(
                args["workspaceId"],
                organization=args.get("organization", ""),
                notes=args.get("notes", ""),
                hosts=args["hosts"],
                patterns=args.get("patterns"),
                cidrs=args.get("cidrs"),
            )
        return json.dumps(result, indent=2)
    if name == "project.start":
        workspace_id = args.get("workspaceId") or args["organization"]
        result: dict[str, Any] = {
            "scope": scope.save_scope(
                args["hosts"],
                args.get("notes", ""),
                args["organization"],
                args.get("patterns"),
                args.get("cidrs"),
                cursor=args.get("cursor"),
                limit=int(args.get("inventoryLimit", 50)),
                include_inventory=bool(args.get("includeInventory", False)),
            ),
            "workspace": workspace.create_workspace(
                workspace_id,
                organization=args["organization"],
                notes=args.get("notes", ""),
                hosts=args["hosts"],
                patterns=args.get("patterns"),
                cidrs=args.get("cidrs"),
            ),
            "authenticationGuidance": credentials.auth_process_guidance(),
        }
        evidence_project = evidence.ensure_project(args["organization"], args["hosts"])
        evidence_hosts = evidence_project.get("hosts", [])
        result["evidenceProject"] = {
            "initialized": evidence_project.get("initialized", False),
            "organization": evidence_project.get("organization", args["organization"]),
            "path": evidence_project.get("path", ""),
            "hostCount": len(evidence_hosts) if isinstance(evidence_hosts, list) else 0,
        }
        if args.get("dumpPath") and args.get("fingerprint", True):
            from synapse_mcp.core import fingerprint

            result["fingerprint"] = fingerprint.from_dump(
                args["dumpPath"],
                args["organization"],
                "",
                int(args.get("limit", 5000)),
            )
        evidence.log_event(
            "project.start",
            f"Started project for {args['organization']} with {len(args['hosts'])} hosts.",
            {
                "organization": args["organization"],
                "workspaceId": workspace_id,
                "hosts": args["hosts"],
                "patterns": args.get("patterns", []),
                "cidrs": args.get("cidrs", []),
                "notes": args.get("notes", ""),
                "dumpPath": args.get("dumpPath", ""),
                "fingerprint": bool(args.get("dumpPath") and args.get("fingerprint", True)),
            },
        )
        return json.dumps(result, indent=2)
    if name == "scope.check_target":
        return json.dumps(
            scope.check_target(
                args["target"],
                cursor=args.get("cursor"),
                limit=int(args.get("limit", 50)),
                include_inventory=bool(args.get("includeInventory", False)),
            ),
            indent=2,
        )
    if name == "workspace.create":
        return json.dumps(
            workspace.create_workspace(
                args["workspaceId"],
                args.get("organization", ""),
                args.get("notes", ""),
                args.get("hosts", []),
                args.get("patterns"),
                args.get("cidrs"),
            ),
            indent=2,
        )
    if name == "workspace.add_target":
        return json.dumps(
            workspace.add_target(
                args["workspaceId"],
                args["target"],
                args.get("kind", "host"),
                args.get("notes", ""),
            ),
            indent=2,
        )
    if name == "workspace.ingest_data":
        return json.dumps(
            workspace.ingest_data(
                args.get("workspaceId"),
                args["target"],
                args["source"],
                args.get("dataType", "tool_output"),
                args.get("format", "text"),
                args["rawData"],
                args.get("metadata", {}),
            ),
            indent=2,
        )
    if name == "workspace.prepare_target_context":
        return json.dumps(
            workspace.prepare_target_context(
                args["workspaceId"],
                args["target"],
                args.get("purpose", "next_step_planning"),
                int(args.get("maxTokens", 1500)),
            ),
            indent=2,
        )
    if name == "workspace.summary":
        return json.dumps(
            workspace.workspace_summary(
                args["workspaceId"],
                cursor=args.get("cursor"),
                limit=int(args.get("limit", 50)),
                include_inventory=bool(args.get("includeInventory", False)),
            ),
            indent=2,
        )
    if name == "workspace.delete":
        return json.dumps(
            workspace.delete_workspace(args["workspaceId"], bool(args.get("confirm"))),
            indent=2,
        )
    if name == "workspace.create_finding":
        return json.dumps(
            workspace.create_finding(
                args["workspaceId"],
                args["target"],
                args["title"],
                args.get("severity", "info"),
                args.get("confidence", "low"),
                args.get("description", ""),
                args.get("evidenceIds", []),
                args.get("status", "confirmed"),
                args.get("affectedAssets"),
                args.get("reproductionSteps"),
                args.get("impact", ""),
                args.get("remediation", ""),
                bool(args.get("operatorReviewed", True)),
            ),
            indent=2,
        )
    if name == "workspace.update_finding":
        return json.dumps(
            workspace.update_finding(
                args["workspaceId"],
                args["target"],
                args["findingId"],
                args.get("updates", {}),
            ),
            indent=2,
        )
    if name == "workspace.promote_observation_to_finding":
        selector = {
            key: args[key]
            for key in ("observationId", "observationKey", "type", "value")
            if args.get(key)
        }
        return json.dumps(
            workspace.promote_observation_to_finding(
                args["workspaceId"],
                args["target"],
                selector,
                args.get("title", ""),
                args.get("severity", "info"),
                args.get("confidence", "low"),
                args.get("status", "candidate"),
            ),
            indent=2,
        )
    if name == "workspace.link_evidence_to_finding":
        return json.dumps(
            workspace.link_evidence_to_finding(
                args["workspaceId"],
                args["target"],
                args["findingId"],
                args.get("evidenceIds", []),
            ),
            indent=2,
        )
    if name == "workspace.mark_finding_reviewed":
        return json.dumps(
            workspace.mark_finding_reviewed(
                args["workspaceId"],
                args["target"],
                args["findingId"],
                args.get("status", "confirmed"),
                args.get("reviewer", "operator"),
                args.get("notes", ""),
            ),
            indent=2,
        )
    if name == "workspace.set_entity_reportable":
        return json.dumps(
            workspace.set_entity_reportable(
                args["workspaceId"],
                args["target"],
                args["entityType"],
                args.get("selector", {}),
                bool(args.get("isReportable", True)),
                args.get("reason", ""),
                args.get("reviewer", "operator"),
            ),
            indent=2,
        )
    if name == "workspace.record_candidate_validation":
        return json.dumps(
            workspace.record_candidate_validation(
                args["workspaceId"],
                args["target"],
                args.get("selector", {}),
                args["outcome"],
                args.get("vulnClass", ""),
                args.get("evidenceIds", []),
                args.get("notes", ""),
                args.get("reviewer", "operator"),
            ),
            indent=2,
        )
    if name == "workspace.curate_candidate":
        return json.dumps(
            workspace.curate_candidate(
                args["workspaceId"],
                args["target"],
                args.get("surfaceSelector", {}),
                args.get("add", []),
                args.get("remove", []),
                args.get("reason", ""),
                args.get("reviewer", "agent"),
            ),
            indent=2,
        )
    if name == "workspace.export_finding_context":
        return json.dumps(
            workspace.export_finding_context(
                args["workspaceId"], args["target"], args["findingId"]
            ),
            indent=2,
        )
    if name == "credentials.set":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Storing credentials requires confirm=true.")
        return json.dumps(credentials.save_credential(args), indent=2)
    if name == "credentials.list":
        return json.dumps(credentials.list_credentials(), indent=2)
    if name == "credentials.set_auth_profile":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Storing authentication profiles requires confirm=true.")
        return json.dumps(credentials.save_auth_profile(args), indent=2)
    if name == "credentials.set_browser_auth_profile":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Storing browser authentication profiles requires confirm=true.")
        return json.dumps(credentials.save_browser_auth_profile(args), indent=2)
    if name == "credentials.authenticate":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Authentication requires confirm=true.")
        return json.dumps(credentials.authenticate(args), indent=2)
    if name == "credentials.browser_auth_check_setup":
        return json.dumps(credentials.browser_auth_check_setup(args), indent=2)
    if name == "credentials.browser_authenticate":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Browser authentication requires confirm=true.")
        return json.dumps(credentials.browser_authenticate(args), indent=2)
    if name == "credentials.validate_session":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Session validation requires confirm=true.")
        return json.dumps(credentials.validate_session(args), indent=2)
    if name == "credentials.get":
        return json.dumps(credentials.get_credential(args["id"]), indent=2)
    if name == "credentials.delete":
        if args.get("confirm") is not True:
            raise McpError(-32001, "Deleting credentials requires confirm=true.")
        return json.dumps(credentials.delete_credential(args["id"]), indent=2)
    if name == "dumps.list":
        return json.dumps(dumps.list_dumps(), indent=2)
    if name == "cache.inspect_scope_data":
        return json.dumps(cache.inspect_scope_data(), indent=2)
    if name == "cache.clean_out_of_scope":
        return json.dumps(cache.clean_out_of_scope(bool(args.get("confirm"))), indent=2)
    if name == "cache.inspect_generated_artifacts":
        return json.dumps(cache.inspect_generated_artifacts(int(args.get("keep", 1))), indent=2)
    if name == "cache.clean_generated_artifacts":
        return json.dumps(
            cache.clean_generated_artifacts(
                bool(args.get("confirm")), int(args.get("keep", 1))
            ),
            indent=2,
        )
    if name == "evidence.log_event":
        event_data = dict(args.get("data") or {})
        for key in ("workspaceId", "target", "organization"):
            if args.get(key) is not None and key not in event_data:
                event_data[key] = args[key]
        return json.dumps(
            evidence.log_event(args["type"], args["summary"], event_data), indent=2
        )
    if name == "evidence.tail":
        return json.dumps(evidence.tail_events(int(args.get("limit", 20))), indent=2)
    if name == "evidence.init_project":
        return json.dumps(
            evidence.ensure_project(args["organization"], args.get("hosts", [])), indent=2
        )
    if name == "evidence.host_context":
        return json.dumps(
            evidence.host_context(
                args["target"], args.get("organization"), int(args.get("limit", 50))
            ),
            indent=2,
        )
    raise McpError(-32601, f"Unknown core action: {name}")
