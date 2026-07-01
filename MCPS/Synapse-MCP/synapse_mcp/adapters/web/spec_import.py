# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urljoin, urlsplit

from ...core import evidence, workspace
from ...core.adapters import AdapterResult, WorkspaceEntityBundle, candidate_observation
from ...core.errors import McpError
from .active_probe import redact_value_preview

SOURCE = "spec_import"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
# Defensive ceiling so a hostile or generated spec cannot explode the workspace.
MAX_ENTITIES = 2000


def capabilities(_: dict[str, Any] | None = None) -> str:
    from ...core.adapters.registry import default_registry

    return json.dumps(default_registry.capabilities("spec_import"), indent=2)


def import_spec(args: dict[str, Any]) -> str:
    workspace_id = args["workspaceId"]
    target = args["target"]
    raw = args.get("rawData")
    if not isinstance(raw, str) or not raw.strip():
        raise McpError(-32602, "rawData containing the API specification document is required.")
    payload = _parse_document(raw)
    if not isinstance(payload, dict):
        raise McpError(-32602, "Specification must be a JSON (or JSON-compatible YAML) object.")
    fmt = str(args.get("format", "") or "").lower() or _detect_format(payload)
    base = _base_url(target)
    if fmt in {"openapi", "swagger"}:
        endpoints, parameters, auth = _parse_openapi(payload, base)
    elif fmt == "postman":
        endpoints, parameters, auth = _parse_postman(payload, base)
    else:
        raise McpError(-32602, "Unrecognized specification format; expected openapi, swagger, or postman.")

    endpoints = endpoints[:MAX_ENTITIES]
    parameters = parameters[:MAX_ENTITIES]
    observations = [
        candidate_observation(
            candidate_type="documented_auth_scheme",
            value=scheme["name"],
            reason=f"Specification documents a {scheme['schemeType']} authentication scheme.",
            confidence="low",
            priority="info",
            tags=["spec-import", "auth"],
            metadata={key: value for key, value in scheme.items() if key != "name"},
        )
        for scheme in auth
    ]

    result = AdapterResult(
        adapter=SOURCE,
        mode="result_ingestion",
        workspace_id=workspace.normalize_workspace_id(workspace_id),
        target=workspace.normalize_target(target),
        summary=f"Imported {len(endpoints)} documented endpoints and {len(parameters)} parameters from {fmt} specification.",
        entities=WorkspaceEntityBundle(endpoints=endpoints, parameters=parameters, observations=observations),
        limitations=[
            "Imports documented surface only; presence in a spec is not proof an endpoint is live.",
            "Documented endpoints are marked inferred and are not treated as observed traffic.",
        ],
        metadata={"format": fmt, "authSchemeCount": len(auth)},
    )
    payload_out = {
        **result.as_ingest_payload(),
        "format": fmt,
        "endpointCount": len(endpoints),
        "parameterCount": len(parameters),
        "authSchemes": auth,
    }
    ingestion = None
    if args.get("ingest", True):
        ingestion = workspace.ingest_data(
            workspace_id,
            target,
            "adapter_result",
            "spec_import",
            "json",
            json.dumps(payload_out, indent=2, ensure_ascii=False),
            {"adapter": SOURCE, "format": fmt},
        )
    evidence.log_event(
        "spec_import.import_spec",
        f"Imported {fmt} specification for {workspace.normalize_target(target)}.",
        {
            "workspaceId": workspace.normalize_workspace_id(workspace_id),
            "target": workspace.normalize_target(target),
            "format": fmt,
            "endpointCount": len(endpoints),
            "parameterCount": len(parameters),
            "ingested": bool(ingestion),
        },
    )
    return json.dumps({**payload_out, **({"ingestion": ingestion} if ingestion else {})}, indent=2)


def _parse_document(raw: str) -> Any:
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    try:
        import yaml  # type: ignore

        return yaml.safe_load(raw)
    except Exception as exc:  # pragma: no cover - yaml optional / malformed input
        raise McpError(-32602, "rawData is not valid JSON and could not be parsed as YAML.") from exc


def _detect_format(payload: dict[str, Any]) -> str:
    if "openapi" in payload:
        return "openapi"
    if "swagger" in payload:
        return "swagger"
    if "info" in payload and "item" in payload:
        return "postman"
    if "paths" in payload:
        return "openapi"
    raise McpError(-32602, "Could not auto-detect specification format; pass format explicitly.")


def _base_url(target: str) -> str:
    raw = str(target).strip()
    if raw.startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        return f"{parsed.scheme}://{parsed.netloc}/"
    return f"https://{workspace.normalize_target(raw)}/"


def _resolve_url(base: str, candidate: str) -> str:
    candidate = str(candidate or "").strip()
    if candidate.startswith(("http://", "https://")):
        return candidate
    if candidate.startswith("//"):
        return f"https:{candidate}"
    return urljoin(base, candidate.lstrip("/") or "")


def _example_value(spec: dict[str, Any]) -> str:
    schema = spec.get("schema") if isinstance(spec.get("schema"), dict) else {}
    for source in (spec, schema):
        for key in ("example", "default"):
            value = source.get(key)
            if value not in (None, "", [], {}):
                return str(value)[:120]
    return ""


# --- OpenAPI / Swagger -----------------------------------------------------


def _openapi_servers(payload: dict[str, Any], base: str) -> list[str]:
    servers = payload.get("servers")
    resolved: list[str] = []
    if isinstance(servers, list):
        for server in servers:
            if not isinstance(server, dict):
                continue
            url = str(server.get("url", "") or "")
            variables = server.get("variables") if isinstance(server.get("variables"), dict) else {}
            for name, definition in variables.items():
                if isinstance(definition, dict) and definition.get("default") not in (None, ""):
                    url = url.replace("{" + str(name) + "}", str(definition["default"]))
            if url:
                resolved.append(_resolve_url(base, url))
    if resolved:
        return resolved
    # Swagger 2.0 host/basePath/schemes.
    host = str(payload.get("host", "") or "")
    if host:
        scheme = (payload.get("schemes") or ["https"])[0]
        base_path = str(payload.get("basePath", "") or "")
        return [f"{scheme}://{host}{base_path}".rstrip("/") + "/"]
    return [base]


def _parse_openapi(payload: dict[str, Any], base: str) -> tuple[list[dict], list[dict], list[dict]]:
    servers = _openapi_servers(payload, base)
    server = servers[0] if servers else base
    endpoints: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []
    paths = payload.get("paths") if isinstance(payload.get("paths"), dict) else {}
    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method, operation in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            url = _resolve_url(server.rstrip("/") + "/", str(path).lstrip("/"))
            method_upper = method.upper()
            op_params = operation.get("parameters") if isinstance(operation.get("parameters"), list) else []
            query_names: list[str] = []
            for spec in [*shared, *op_params]:
                param = _openapi_parameter(spec, url, method_upper, path)
                if param:
                    parameters.append(param)
                    if param["location"] == "query":
                        query_names.append(param["name"])
            request_content_types = _openapi_request_content_types(operation)
            parameters.extend(_openapi_body_parameters(operation, url, method_upper, path))
            endpoints.append(_endpoint(url, method_upper, path, sorted(set(query_names)), request_content_types=request_content_types))
    return endpoints, parameters, _openapi_auth(payload)


def _openapi_parameter(spec: Any, url: str, method: str, path: str) -> dict[str, Any] | None:
    if not isinstance(spec, dict) or not spec.get("name"):
        return None
    location = str(spec.get("in", "query") or "query").lower()
    if location == "body":  # Swagger 2 body wrapper handled separately.
        return None
    return _parameter(str(spec["name"]), location, url, method, path, _example_value(spec))


def _openapi_body_parameters(operation: dict[str, Any], url: str, method: str, path: str) -> list[dict[str, Any]]:
    params: list[dict[str, Any]] = []
    # OpenAPI 3 requestBody.
    request_body = operation.get("requestBody") if isinstance(operation.get("requestBody"), dict) else {}
    content = request_body.get("content") if isinstance(request_body.get("content"), dict) else {}
    for content_type, media in content.items():
        if not isinstance(media, dict):
            continue
        location = _body_location(str(content_type))
        schema = media.get("schema") if isinstance(media.get("schema"), dict) else {}
        for name, prop in _schema_properties(schema):
            params.append(_parameter(name, location, url, method, path, _example_value(prop)))
    # Swagger 2 body / formData parameters.
    for spec in operation.get("parameters") if isinstance(operation.get("parameters"), list) else []:
        if not isinstance(spec, dict):
            continue
        if str(spec.get("in", "")).lower() == "body":
            schema = spec.get("schema") if isinstance(spec.get("schema"), dict) else {}
            for name, prop in _schema_properties(schema):
                params.append(_parameter(name, "json", url, method, path, _example_value(prop)))
        elif str(spec.get("in", "")).lower() == "formdata" and spec.get("name"):
            params.append(_parameter(str(spec["name"]), "form", url, method, path, _example_value(spec)))
    return params


def _openapi_request_content_types(operation: dict[str, Any]) -> list[str]:
    request_body = operation.get("requestBody") if isinstance(operation.get("requestBody"), dict) else {}
    content = request_body.get("content") if isinstance(request_body.get("content"), dict) else {}
    content_types = [str(content_type) for content_type in content if content_type]
    consumes = operation.get("consumes")
    if isinstance(consumes, list):
        content_types.extend(str(item) for item in consumes if item)
    return sorted(set(content_types))


def _schema_properties(schema: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    return [(str(name), prop if isinstance(prop, dict) else {}) for name, prop in properties.items()]


def _body_location(content_type: str) -> str:
    lowered = content_type.lower()
    if "json" in lowered:
        return "json"
    if "form-urlencoded" in lowered or "multipart" in lowered:
        return "form"
    return "body"


def _openapi_auth(payload: dict[str, Any]) -> list[dict[str, Any]]:
    components = payload.get("components") if isinstance(payload.get("components"), dict) else {}
    schemes = components.get("securitySchemes") if isinstance(components.get("securitySchemes"), dict) else {}
    if not schemes and isinstance(payload.get("securityDefinitions"), dict):
        schemes = payload["securityDefinitions"]  # Swagger 2.0.
    auth = []
    for name, definition in schemes.items():
        if not isinstance(definition, dict):
            continue
        entry = {"name": str(name), "schemeType": str(definition.get("type", "unknown"))}
        for field in ("scheme", "in", "bearerFormat"):
            if definition.get(field):
                entry[field] = str(definition[field])
        if definition.get("type") == "apiKey" and definition.get("name"):
            entry["headerOrParamName"] = str(definition["name"])
        auth.append(entry)
    return auth


# --- Postman ---------------------------------------------------------------


def _parse_postman(payload: dict[str, Any], base: str) -> tuple[list[dict], list[dict], list[dict]]:
    endpoints: list[dict[str, Any]] = []
    parameters: list[dict[str, Any]] = []
    auth: list[dict[str, Any]] = []
    variables = _postman_variables(payload)

    def walk(items: Any) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            if isinstance(item.get("item"), list):
                walk(item["item"])
                continue
            request = item.get("request")
            if isinstance(request, dict):
                _postman_request(request, base, variables, endpoints, parameters, auth)

    walk(payload.get("item"))
    # Collection-level auth.
    if isinstance(payload.get("auth"), dict):
        scheme = _postman_auth(payload["auth"])
        if scheme:
            auth.append(scheme)
    # Deduplicate auth schemes by type.
    seen: set[str] = set()
    unique_auth = []
    for scheme in auth:
        if scheme["schemeType"] not in seen:
            seen.add(scheme["schemeType"])
            unique_auth.append(scheme)
    return endpoints, parameters, unique_auth


def _postman_variables(payload: dict[str, Any]) -> dict[str, str]:
    variables: dict[str, str] = {}
    for var in payload.get("variable") if isinstance(payload.get("variable"), list) else []:
        if isinstance(var, dict) and var.get("key"):
            variables[str(var["key"])] = str(var.get("value", ""))
    return variables


def _postman_substitute(value: str, variables: dict[str, str]) -> str:
    for key, replacement in variables.items():
        value = value.replace("{{" + key + "}}", replacement)
    return value


def _postman_request(
    request: dict[str, Any],
    base: str,
    variables: dict[str, str],
    endpoints: list[dict[str, Any]],
    parameters: list[dict[str, Any]],
    auth: list[dict[str, Any]],
) -> None:
    method = str(request.get("method", "GET") or "GET").upper()
    url_field = request.get("url")
    raw_url = ""
    query_specs: list[dict[str, Any]] = []
    if isinstance(url_field, str):
        raw_url = url_field
    elif isinstance(url_field, dict):
        raw_url = str(url_field.get("raw", "") or "")
        query_specs = url_field.get("query") if isinstance(url_field.get("query"), list) else []
    raw_url = _postman_substitute(raw_url, variables).split("?")[0]
    if not raw_url:
        return
    url = _resolve_url(base, raw_url)
    path = urlsplit(url).path or "/"
    query_names = []
    for spec in query_specs:
        if isinstance(spec, dict) and spec.get("key"):
            name = str(spec["key"])
            query_names.append(name)
            parameters.append(_parameter(name, "query", url, method, path, str(spec.get("value", "") or "")[:120]))
    parameters.extend(_postman_body_parameters(request.get("body"), url, method, path))
    endpoints.append(_endpoint(url, method, path, sorted(set(query_names))))
    if isinstance(request.get("auth"), dict):
        scheme = _postman_auth(request["auth"])
        if scheme:
            auth.append(scheme)


def _postman_body_parameters(body: Any, url: str, method: str, path: str) -> list[dict[str, Any]]:
    if not isinstance(body, dict):
        return []
    mode = str(body.get("mode", ""))
    params = []
    if mode == "urlencoded":
        for spec in body.get("urlencoded") if isinstance(body.get("urlencoded"), list) else []:
            if isinstance(spec, dict) and spec.get("key"):
                params.append(_parameter(str(spec["key"]), "form", url, method, path, str(spec.get("value", "") or "")[:120]))
    elif mode == "formdata":
        for spec in body.get("formdata") if isinstance(body.get("formdata"), list) else []:
            if isinstance(spec, dict) and spec.get("key"):
                params.append(_parameter(str(spec["key"]), "form", url, method, path, str(spec.get("value", "") or "")[:120]))
    elif mode == "raw":
        try:
            parsed = json.loads(body.get("raw", ""))
        except (json.JSONDecodeError, TypeError):
            parsed = None
        if isinstance(parsed, dict):
            for name, value in parsed.items():
                preview = "" if isinstance(value, (dict, list)) else str(value)[:120]
                params.append(_parameter(str(name), "json", url, method, path, preview))
    return params


def _postman_auth(auth: dict[str, Any]) -> dict[str, Any] | None:
    auth_type = str(auth.get("type", "") or "")
    if not auth_type:
        return None
    mapping = {"bearer": "http", "basic": "http", "apikey": "apiKey", "oauth2": "oauth2", "digest": "http"}
    return {"name": auth_type, "schemeType": mapping.get(auth_type.lower(), auth_type)}


# --- shared entity builders ------------------------------------------------


def _endpoint(url: str, method: str, path: str, query_parameters: list[str], *, request_content_types: list[str] | None = None) -> dict[str, Any]:
    endpoint = {
        "type": "endpoint",
        "url": url,
        "method": method,
        "path": path,
        "queryParameters": query_parameters,
        "source": SOURCE,
        "derived": True,
        "inferred": True,
        "observed": False,
        "confidence": "low",
    }
    if request_content_types:
        endpoint["requestContentTypes"] = request_content_types
    return endpoint


def _parameter(name: str, location: str, url: str, method: str, path: str, value_preview: str) -> dict[str, Any]:
    param = {
        "type": "parameter",
        "name": name,
        "location": location,
        "method": method,
        "url": url,
        "path": path,
        "source": SOURCE,
    }
    if value_preview:
        param["valuePreview"] = redact_value_preview(name, value_preview)
    return param
