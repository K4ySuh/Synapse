# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import re
import shlex
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

from ...core.errors import McpError
from .active_probe import redact_value_preview


SQLMAP_BIN = os.environ.get("SQLMAP_BIN", "sqlmap")

# sqlmap options that directly interact with the back-end OS or registry.
BLOCKED_OPTIONS = {
    "eval",
    "file-read",
    "file-write",
    "file-dest",
    "os-cmd",
    "os-shell",
    "os-pwn",
    "os-smbrelay",
    "os-bof",
    "priv-esc",
    "msf-path",
    "tmp-path",
    "reg-read",
    "reg-add",
    "reg-del",
    "reg-key",
    "reg-value",
    "reg-data",
    "reg-type",
}

SCALAR_TYPES = (str, int, float, bool)
INTERESTING_NAMES = (
    "id",
    "user",
    "uid",
    "account",
    "order",
    "item",
    "product",
    "cat",
    "category",
    "sort",
    "filter",
    "search",
    "query",
    "name",
    "email",
    "token",
    "ref",
    "number",
    "page",
)
STATIC_EXTENSIONS = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
    ".webp",
    ".avif",
    ".pdf",
    ".zip",
)


def normalize_option_name(name: str) -> str:
    normalized = name.strip()
    if not normalized:
        raise McpError(-32602, "Option names cannot be empty.")
    while normalized.startswith("-"):
        normalized = normalized[1:]
    return normalized


def validate_option_name(name: str) -> str:
    normalized = normalize_option_name(name)
    if normalized in BLOCKED_OPTIONS:
        raise McpError(-32602, f"Blocked sqlmap option: --{normalized}")
    return normalized


def append_option(cmd: list[str], name: str, value: Any) -> None:
    normalized = validate_option_name(name)
    flag = f"-{normalized}" if len(normalized) == 1 else f"--{normalized}"
    if isinstance(value, list):
        for item in value:
            append_option(cmd, name, item)
        return
    if value is None:
        return
    if isinstance(value, bool):
        if value:
            cmd.append(flag)
        return
    if not isinstance(value, SCALAR_TYPES[:-1]):
        raise McpError(-32602, f"Unsupported value type for option '{name}'")
    cmd.extend([flag, str(value)])


def build_sqlmap_command(level: int, risk: int, options: dict[str, Any] | None) -> list[str]:
    if level < 1 or level > 5:
        raise McpError(-32602, "level must be between 1 and 5")
    if risk < 1 or risk > 3:
        raise McpError(-32602, "risk must be between 1 and 3")
    cmd = [SQLMAP_BIN, "--level", str(level), "--risk", str(risk)]
    if options:
        if not isinstance(options, dict):
            raise McpError(-32602, "options must be an object")
        for name, value in options.items():
            normalized = normalize_option_name(name)
            if normalized in {"level", "risk"}:
                raise McpError(-32602, f"Pass '{normalized}' as a top-level argument, not inside options")
            append_option(cmd, name, value)
    return cmd


def stringify_command(cmd: list[str]) -> str:
    return shlex.join(cmd)


def split_headers_body(message: str) -> tuple[str, str]:
    if "\r\n\r\n" in message:
        return message.split("\r\n\r\n", 1)
    if "\n\n" in message:
        return message.split("\n\n", 1)
    return message, ""


def parse_request(raw_request: str) -> dict[str, Any]:
    head, body = split_headers_body(raw_request)
    lines = [line for line in head.replace("\r\n", "\n").split("\n") if line]
    if not lines:
        raise McpError(-32000, "Burp request is empty")
    parts = lines[0].split()
    if len(parts) < 3:
        raise McpError(-32000, "Invalid HTTP request line")
    headers: list[tuple[str, str]] = []
    header_map: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        normalized = name.strip().lower()
        stripped = value.strip()
        headers.append((name.strip(), stripped))
        if normalized not in header_map:
            header_map[normalized] = stripped
    return {
        "method": parts[0],
        "path": parts[1],
        "version": parts[2],
        "headers": headers,
        "headerMap": header_map,
        "body": body,
    }


def host_and_port(header_map: dict[str, str]) -> tuple[str, int | None]:
    host_header = header_map.get("host", "")
    if not host_header:
        return "", None
    if ":" in host_header:
        host, port_text = host_header.rsplit(":", 1)
        if port_text.isdigit():
            return host, int(port_text)
    return host_header, None


def interesting_name(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in INTERESTING_NAMES)


def base_candidate_score(location: str) -> int:
    return {
        "query": 90,
        "body": 88,
        "json": 86,
        "xml": 82,
        "cookie": 72,
        "header": 55,
        "path": 45,
    }.get(location, 40)


def score_candidate(location: str, name: str, value: str) -> int:
    score = base_candidate_score(location)
    if interesting_name(name):
        score += 10
    if value.isdigit():
        score += 5
    if re.fullmatch(r"[0-9a-fA-F-]{8,}", value):
        score += 3
    if len(value) > 40:
        score -= 5
    return max(1, min(score, 100))


def add_candidate(
    candidates: list[dict[str, Any]],
    seen: set[tuple[str, str]],
    *,
    location: str,
    name: str,
    value: str,
    reason: str,
) -> None:
    key = (location, name)
    if key in seen:
        return
    seen.add(key)
    candidates.append(
        {
            "location": location,
            "name": name,
            "valuePreview": redact_value_preview(name, value),
            "score": score_candidate(location, name, value),
            "reason": reason,
        }
    )


def extract_json_candidates(body: str, candidates: list[dict[str, Any]], seen: set[tuple[str, str]]) -> None:
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return

    def walk(prefix: str, value: Any) -> None:
        if isinstance(value, dict):
            for key, inner in value.items():
                next_prefix = f"{prefix}.{key}" if prefix else key
                walk(next_prefix, inner)
            return
        if isinstance(value, list):
            for idx, inner in enumerate(value):
                walk(f"{prefix}[{idx}]", inner)
            return
        if prefix and isinstance(value, (str, int, float, bool)):
            add_candidate(
                candidates,
                seen,
                location="json",
                name=prefix,
                value=str(value),
                reason="Scalar JSON field in request body.",
            )

    walk("", parsed)


def extract_xml_candidates(body: str, candidates: list[dict[str, Any]], seen: set[tuple[str, str]]) -> None:
    for name, value in re.findall(r"<([A-Za-z0-9_.:-]+)>([^<]{1,200})</\1>", body):
        add_candidate(
            candidates,
            seen,
            location="xml",
            name=name,
            value=value.strip(),
            reason="Simple XML element with scalar content in request body.",
        )


def extract_path_candidates(path: str, candidates: list[dict[str, Any]], seen: set[tuple[str, str]]) -> None:
    clean_path = path.split("?", 1)[0]
    for index, segment in enumerate(clean_path.split("/")):
        stripped = segment.strip()
        if not stripped:
            continue
        if stripped.isdigit() or re.fullmatch(r"[0-9a-fA-F-]{8,}", stripped):
            add_candidate(
                candidates,
                seen,
                location="path",
                name=f"path[{index}]",
                value=stripped,
                reason="Numeric or token-like URI segment may be injectable, but usually needs manual marking.",
            )


def extract_candidates(request: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    path = request["path"]
    header_map = request["headerMap"]
    body = request["body"]

    if "?" in path:
        query_string = path.split("?", 1)[1]
        for name, value in parse_qsl(query_string, keep_blank_values=True):
            add_candidate(
                candidates,
                seen,
                location="query",
                name=name,
                value=value,
                reason="Query-string parameter is a primary sqlmap target.",
            )

    content_type = header_map.get("content-type", "").split(";", 1)[0].strip().lower()
    if body:
        if content_type == "application/x-www-form-urlencoded":
            for name, value in parse_qsl(body, keep_blank_values=True):
                add_candidate(
                    candidates,
                    seen,
                    location="body",
                    name=name,
                    value=value,
                    reason="Form parameter in request body is a primary sqlmap target.",
                )
        elif "json" in content_type:
            extract_json_candidates(body, candidates, seen)
        elif "xml" in content_type or "soap" in content_type:
            extract_xml_candidates(body, candidates, seen)

    cookie_header = header_map.get("cookie")
    if cookie_header:
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
        except Exception:
            cookie = SimpleCookie()
        for morsel in cookie.values():
            add_candidate(
                candidates,
                seen,
                location="cookie",
                name=morsel.key,
                value=morsel.value,
                reason="Cookie parameter can be tested when stateful flows depend on it.",
            )

    for name, value in request["headers"]:
        normalized = name.lower()
        if normalized in {"host", "cookie", "content-length", "content-type", "connection"}:
            continue
        if normalized.startswith("x-") or normalized in {"referer", "user-agent"}:
            add_candidate(
                candidates,
                seen,
                location="header",
                name=name,
                value=value,
                reason="Custom or user-controlled header is sometimes parsed into SQL queries.",
            )

    extract_path_candidates(path, candidates, seen)
    return sorted(candidates, key=lambda item: item["score"], reverse=True)


def is_static_asset_path(path: str) -> bool:
    lowered = path.split("?", 1)[0].lower()
    if lowered.startswith("/i/"):
        return True
    return lowered.endswith(STATIC_EXTENSIONS)


def is_likely_interesting_request(request: dict[str, Any], candidates: list[dict[str, Any]]) -> bool:
    if request["method"].upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        return False
    if is_static_asset_path(request["path"]):
        return False
    if any(candidate["location"] in {"query", "body", "json", "xml", "path"} for candidate in candidates):
        return True
    return request["method"].upper() != "GET" and bool(request["body"].strip())


def build_candidate_options(request_file: Path, candidate: dict[str, Any]) -> dict[str, Any]:
    options: dict[str, Any] = {"r": str(request_file), "batch": True}
    if candidate["location"] != "path":
        options["p"] = candidate["name"]
    return options


def shellify_build_arguments(level: int, risk: int, options: dict[str, Any]) -> str:
    return stringify_command(build_sqlmap_command(level, risk, options))


def analyze_request(
    *,
    history_id: int,
    raw_request: str,
    max_candidates: int,
    include_commands: bool,
    level: int | None = None,
    risk: int | None = None,
    request_file: Path | None = None,
) -> dict[str, Any]:
    request = parse_request(raw_request)
    host, port = host_and_port(request["headerMap"])
    if include_commands and request_file is None:
        raise McpError(-32602, "request_file is required when include_commands is enabled")
    candidate_rows = []
    for candidate in extract_candidates(request)[:max_candidates]:
        if include_commands:
            if level is None or risk is None:
                raise McpError(-32602, "level and risk are required when include_commands is enabled")
            assert request_file is not None
            options = build_candidate_options(request_file, candidate)
            candidate_rows.append(
                {
                    **candidate,
                    "suggestedBuildArguments": {"level": level, "risk": risk, "options": options},
                    "suggestedShellCommand": shellify_build_arguments(level, risk, options),
                }
            )
        else:
            candidate_rows.append(candidate)
    notes = []
    if not candidate_rows:
        notes.append("No strong parameter candidates detected automatically.")
    if any(candidate["location"] == "path" for candidate in candidate_rows):
        notes.append("Path candidates may require manual '*' marking if sqlmap does not pick them up from the raw request.")
    if any(candidate["location"] == "json" and ("." in candidate["name"] or "[" in candidate["name"]) for candidate in candidate_rows):
        notes.append("Nested JSON selectors may need manual adjustment if sqlmap labels the parameter differently.")
    result = {
        "id": history_id,
        "host": host,
        "port": port,
        "requestLine": f"{request['method']} {request['path']} {request['version']}",
        "candidateCount": len(candidate_rows),
        "candidates": candidate_rows,
        "notes": notes,
    }
    if include_commands:
        assert request_file is not None
        result["requestFile"] = str(request_file)
    return result


def detect_technologies(raw_request: str, raw_response: str) -> dict[str, Any]:
    request = parse_request(raw_request)
    header_map = request["headerMap"]
    response_head = split_headers_body(raw_response)[0]
    haystack = "\n".join([raw_request, raw_response]).lower()
    technologies: set[str] = set()
    dbms_hints: set[str] = set()
    evidence: list[str] = []

    server = re.search(r"(?im)^Server:\s*([^\r\n]+)", raw_response)
    powered_by = re.search(r"(?im)^X-Powered-By:\s*([^\r\n]+)", raw_response)
    if server:
        technologies.add(server.group(1).strip())
        evidence.append(f"Server header: {server.group(1).strip()}")
    if powered_by:
        technologies.add(powered_by.group(1).strip())
        evidence.append(f"X-Powered-By header: {powered_by.group(1).strip()}")

    path = request["path"].lower()
    if "ords/" in path or "wwv_flow" in haystack or "oracle apex" in haystack:
        technologies.add("Oracle APEX/ORDS")
        dbms_hints.add("Oracle")
        evidence.append("Oracle APEX/ORDS route or parameter observed")
    if ".php" in path or "phpsessid" in haystack or "php" in haystack:
        technologies.add("PHP")
        dbms_hints.update({"MySQL", "MariaDB"})
        evidence.append("PHP marker observed")
    if "asp.net" in haystack or ".aspx" in path or "aspnet_sessionid" in haystack:
        technologies.add("ASP.NET")
        dbms_hints.add("Microsoft SQL Server")
        evidence.append("ASP.NET marker observed")
    if "jsessionid" in haystack or "x-powered-by: servlet" in response_head.lower():
        technologies.add("Java Servlet")
        dbms_hints.update({"Oracle", "PostgreSQL", "Microsoft SQL Server"})
        evidence.append("Java servlet marker observed")
    if "express" in haystack:
        technologies.add("Express")
        evidence.append("Express marker observed")
    if header_map.get("content-type", "").startswith("application/json"):
        technologies.add("JSON API")

    error_signatures = {
        "Oracle": ("ora-", "oracle error", "quoted string not properly terminated"),
        "MySQL": ("mysql", "mariadb", "you have an error in your sql syntax"),
        "PostgreSQL": ("postgresql", "pg_query", "unterminated quoted string"),
        "Microsoft SQL Server": ("sql server", "microsoft ole db", "odbc sql server", "unclosed quotation mark"),
        "SQLite": ("sqlite", "sqlite3.operationalerror"),
    }
    for dbms, signatures in error_signatures.items():
        if any(signature in haystack for signature in signatures):
            dbms_hints.add(dbms)
            evidence.append(f"{dbms} error signature observed")

    return {
        "technologies": sorted(technologies),
        "possibleDbms": sorted(dbms_hints),
        "evidence": evidence[:12],
    }


def resolve_dump_history_path(dump_path_text: str) -> tuple[Path, Path]:
    path = Path(dump_path_text).expanduser().resolve()
    if path.is_dir():
        history_path = path / "history.jsonl"
        dump_dir = path
    elif path.name == "manifest.json":
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise McpError(-32602, f"Could not read dump manifest: {exc}") from exc
        history_path = Path(manifest.get("historyJsonl", path.parent / "history.jsonl")).resolve()
        dump_dir = path.parent
    else:
        history_path = path
        dump_dir = path.parent
    if not history_path.exists():
        raise McpError(-32602, f"Dump history file not found: {history_path}")
    return dump_dir, history_path


def load_dump_entries(dump_path_text: str) -> tuple[Path, list[dict[str, Any]]]:
    dump_dir, history_path = resolve_dump_history_path(dump_path_text)
    entries = []
    with history_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                entry = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise McpError(-32602, f"Invalid JSONL at {history_path}:{line_number}: {exc}") from exc
            request_file = Path(entry.get("requestFile", "")).expanduser()
            if not request_file.is_absolute():
                request_file = (dump_dir / request_file).resolve()
            else:
                request_file = request_file.resolve()
            response_file_text = entry.get("responseFile")
            response_file = None
            if response_file_text:
                response_file = Path(response_file_text).expanduser()
                response_file = response_file.resolve() if response_file.is_absolute() else (dump_dir / response_file).resolve()
            entries.append({**entry, "requestFile": str(request_file), "responseFile": str(response_file) if response_file else None})
    return dump_dir, entries


def analyze_burp_dump(args: dict[str, Any]) -> str:
    level = int(args.get("level", 5))
    risk = int(args.get("risk", 3))
    max_candidates = int(args.get("maxCandidatesPerRequest", 5))
    only_interesting = bool(args.get("onlyInteresting", True))
    include_commands = bool(args.get("includeCommands", True))
    dump_dir, entries = load_dump_entries(args["dumpPath"])
    results = []
    skipped = 0
    warnings = []
    aggregate_technologies: set[str] = set()
    aggregate_dbms: set[str] = set()

    for entry in entries:
        request_file = Path(entry["requestFile"])
        if not request_file.exists():
            skipped += 1
            warnings.append(f"Missing request file for history item {entry.get('id')}: {request_file}")
            continue
        raw_request = request_file.read_text(encoding="utf-8", errors="replace")
        raw_response = ""
        if entry.get("responseFile") and Path(entry["responseFile"]).exists():
            raw_response = Path(entry["responseFile"]).read_text(encoding="utf-8", errors="replace")
        request = parse_request(raw_request)
        base_candidates = extract_candidates(request)
        if only_interesting and not is_likely_interesting_request(request, base_candidates):
            skipped += 1
            continue
        analysis = analyze_request(
            history_id=int(entry.get("id", len(results))),
            raw_request=raw_request,
            max_candidates=max_candidates,
            include_commands=include_commands,
            level=level if include_commands else None,
            risk=risk if include_commands else None,
            request_file=request_file,
        )
        tech = detect_technologies(raw_request, raw_response)
        aggregate_technologies.update(tech["technologies"])
        aggregate_dbms.update(tech["possibleDbms"])
        analysis["technologyDetection"] = tech
        if only_interesting and not analysis["candidates"]:
            skipped += 1
            continue
        results.append(analysis)

    payload = {
        "dumpDir": str(dump_dir),
        "entryCount": len(entries),
        "analyzedRequests": len(results),
        "skippedRequests": skipped,
        "level": level if include_commands else None,
        "risk": risk if include_commands else None,
        "aggregateTechnologies": sorted(aggregate_technologies),
        "aggregatePossibleDbms": sorted(aggregate_dbms),
        "warnings": warnings,
        "results": results,
    }
    return json.dumps(payload, indent=2)
