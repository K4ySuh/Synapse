# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import json
import re
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from ...core.errors import McpError
from .active_probe import redact_value_preview


TEXTUAL_TYPES = ("text/html", "application/xhtml", "application/xml", "text/xml", "application/json")
XSS_TEST_MODES = ("reflection_marker", "context_breakout", "execution")
XSS_MODE_RISK_TIERS = {
    "reflection_marker": "low",
    "context_breakout": "medium",
    "execution": "high",
}
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


class HtmlSinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.sinks: list[dict[str, Any]] = []
        self.forms: list[dict[str, Any]] = []
        self._in_script = False
        self._script_text: list[str] = []
        self._script_index = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() == "script":
            self._in_script = True
            self._script_text = []
            src = attr_map.get("src")
            if src:
                self.sinks.append({"type": "external-script", "tag": tag, "src": src[:160], "risk": "info"})
        if tag.lower() == "form":
            self.forms.append(
                {
                    "method": attr_map.get("method", "GET").upper(),
                    "action": attr_map.get("action", ""),
                    "id": attr_map.get("id", ""),
                    "name": attr_map.get("name", ""),
                }
            )
        for name, value in attr_map.items():
            if name.startswith("on"):
                self.sinks.append(
                    {"type": "event-handler", "tag": tag, "attribute": name, "sample": value[:160], "risk": "high"}
                )
            if name in {"href", "src", "action", "formaction"} and value.strip().lower().startswith("javascript:"):
                self.sinks.append(
                    {"type": "javascript-url", "tag": tag, "attribute": name, "sample": value[:160], "risk": "high"}
                )
            if "{{" in value or "${" in value or "<%" in value:
                self.sinks.append(
                    {"type": "template-marker", "tag": tag, "attribute": name, "sample": value[:160], "risk": "medium"}
                )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._in_script:
            text = "".join(self._script_text).strip()
            if text:
                sink = classify_script_text(text)
                sink["scriptIndex"] = self._script_index
                self.sinks.append(sink)
                self._script_index += 1
            self._in_script = False
            self._script_text = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_text.append(data)

def split_http_message(raw: str) -> tuple[str, dict[str, str], str]:
    head, sep, body = raw.partition("\r\n\r\n")
    if not sep:
        head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    start = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return start, headers, body


def parse_request(raw: str) -> dict[str, Any]:
    start, headers, body = split_http_message(raw)
    parts = start.split(" ", 2)
    method = parts[0] if len(parts) >= 1 else ""
    target = parts[1] if len(parts) >= 2 else ""
    query = urlsplit(target).query
    content_type = headers.get("content-type", "")
    params: list[dict[str, Any]] = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        params.append({"location": "query", "name": name, "value": value})
    if body:
        if "application/x-www-form-urlencoded" in content_type:
            for name, value in parse_qsl(body, keep_blank_values=True):
                params.append({"location": "body", "name": name, "value": value})
                if name == "p_json":
                    params.extend(extract_apex_json_items(value))
        elif "json" in content_type:
            params.extend(extract_json_params(body))
    cookie_header = headers.get("cookie", "")
    if cookie_header:
        cookie = SimpleCookie()
        try:
            cookie.load(cookie_header)
            for name, morsel in cookie.items():
                params.append({"location": "cookie", "name": name, "value": morsel.value})
        except Exception:
            pass
    return {"method": method, "target": target, "headers": headers, "body": body, "params": params}


def extract_apex_json_items(value: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(value)
    except json.JSONDecodeError:
        return []
    items = data.get("pageItems", {}).get("itemsToSubmit", [])
    params = []
    for item in items:
        if isinstance(item, dict) and item.get("n") is not None:
            params.append(
                {
                    "location": "apex-page-item",
                    "name": str(item.get("n")),
                    "value": "" if item.get("v") is None else str(item.get("v")),
                    "protected": "ck" in item,
                }
            )
    return params


def extract_json_params(body: str) -> list[dict[str, Any]]:
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return []
    out: list[dict[str, Any]] = []

    def walk(value: Any, path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                walk(child, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")
        else:
            out.append({"location": "json", "name": path, "value": "" if value is None else str(value)})

    walk(data, "")
    return out


def parse_response(raw: str) -> dict[str, Any]:
    start, headers, body = split_http_message(raw)
    return {"status": start, "headers": headers, "body": body}


def resolve_dump_history_path(dump_path_text: str) -> tuple[Path, Path]:
    path = Path(dump_path_text).expanduser().resolve()
    if path.is_dir():
        return path, path / "history.jsonl"
    if path.name == "manifest.json":
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise McpError(-32602, f"Could not read dump manifest: {exc}") from exc
        return path.parent, Path(manifest.get("historyJsonl", path.parent / "history.jsonl")).resolve()
    return path.parent, path


def load_dump_entries(dump_path_text: str) -> tuple[Path, list[dict[str, Any]]]:
    dump_dir, history_path = resolve_dump_history_path(dump_path_text)
    if not history_path.exists():
        raise McpError(-32602, f"Dump history file not found: {history_path}")
    entries = []
    for line_number, line in enumerate(history_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            raise McpError(-32602, f"Invalid JSONL at {history_path}:{line_number}: {exc}") from exc
        for key in ("requestFile", "responseFile"):
            if entry.get(key):
                file_path = Path(entry[key]).expanduser()
                entry[key] = str(file_path.resolve() if file_path.is_absolute() else (dump_dir / file_path).resolve())
        entries.append(entry)
    return dump_dir, entries


def classify_script_text(text: str) -> dict[str, Any]:
    patterns = {
        "dom-write": r"\b(document\.write|innerHTML|outerHTML|insertAdjacentHTML)\b",
        "script-execution": r"\b(eval|Function|setTimeout|setInterval)\s*\(",
        "url-source": r"\b(location|document\.URL|document\.referrer|URLSearchParams)\b",
        "storage-source": r"\b(localStorage|sessionStorage|postMessage)\b",
        "jquery-html": r"\.html\s*\(",
    }
    matches = [name for name, pattern in patterns.items() if re.search(pattern, text)]
    risk = "medium" if matches else "info"
    if any(name in matches for name in ("dom-write", "script-execution")) and any(
        name in matches for name in ("url-source", "storage-source")
    ):
        risk = "high"
    return {
        "type": "inline-script",
        "risk": risk,
        "signals": matches,
        "sample": re.sub(r"\s+", " ", text)[:220],
    }


def analyze_headers(headers: dict[str, str]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    csp = headers.get("content-security-policy")
    if not csp:
        findings.append({"type": "missing-csp", "severity": "medium", "detail": "No Content-Security-Policy header observed."})
    else:
        weak = []
        if "'unsafe-inline'" in csp:
            weak.append("unsafe-inline")
        if "'unsafe-eval'" in csp:
            weak.append("unsafe-eval")
        if "*" in csp:
            weak.append("wildcard source")
        findings.append({"type": "csp", "severity": "info" if not weak else "medium", "detail": csp[:240]})
    if headers.get("x-xss-protection"):
        findings.append(
            {
                "type": "legacy-xss-filter",
                "severity": "info",
                "detail": f"X-XSS-Protection observed: {headers['x-xss-protection']}",
            }
        )
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append({"type": "missing-nosniff", "severity": "low", "detail": "X-Content-Type-Options nosniff not observed."})
    if headers.get("access-control-allow-credentials", "").lower() == "true":
        findings.append(
            {
                "type": "cors-credentials",
                "severity": "info",
                "detail": "Access-Control-Allow-Credentials is true; review allowed origins for sensitive flows.",
            }
        )
    return findings


def detect_technologies(request: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    evidence = []
    tech = set()
    possible = set()
    server = response["headers"].get("server", "")
    if server:
        tech.add(server.split("/")[0])
        evidence.append(f"Server header: {server}")
    combined = request["target"] + "\n" + response["body"][:4000]
    if "/ords/" in combined or "wwv_flow" in combined or "p_flow_id" in combined:
        tech.add("Oracle APEX/ORDS")
        possible.add("Oracle")
        evidence.append("Oracle APEX/ORDS route or parameter observed")
    if "text/html" in response["headers"].get("content-type", ""):
        tech.add("HTML")
    if "application/json" in response["headers"].get("content-type", ""):
        tech.add("JSON API")
    return {"technologies": sorted(tech), "possibleBackends": sorted(possible), "evidence": evidence}


def find_reflections(params: list[dict[str, Any]], body: str) -> list[dict[str, Any]]:
    reflections = []
    lowered = body.lower()
    for param in params:
        value = str(param.get("value", ""))
        if len(value) < 3:
            continue
        index = lowered.find(value.lower())
        if index == -1:
            continue
        context = reflection_context(body, index)
        reflections.append(
            {
                "location": param["location"],
                "name": param["name"],
                "valuePreview": redact_value_preview(param["name"], value, limit=100),
                "context": context,
                "risk": "high" if context in {"script", "attribute"} else "medium",
            }
        )
    return reflections[:20]


def reflection_context(body: str, index: int) -> str:
    before = body[max(0, index - 120) : index].lower()
    after = body[index : index + 120].lower()
    if "<script" in before and "</script" in after:
        return "script"
    if re.search(r"<[^>]+\s[\w:-]+\s*=\s*['\"][^'\"]*$", before):
        return "attribute"
    if "<" in before and ">" in after:
        return "html"
    return "text"


def score_param(param: dict[str, Any], reflections: list[dict[str, Any]]) -> int:
    name = str(param["name"]).lower()
    location = param["location"]
    score = 40
    if location in {"query", "body", "json", "apex-page-item"}:
        score += 25
    if any(word in name for word in ("q", "search", "query", "name", "desc", "message", "html", "url", "redirect", "callback")):
        score += 20
    if any(r["name"] == param["name"] and r["location"] == location for r in reflections):
        score += 25
    if param.get("protected"):
        score -= 15
    return min(score, 100)


def infer_context(param: dict[str, Any], reflections: list[dict[str, Any]]) -> str:
    for reflection in reflections:
        if reflection["name"] == param["name"] and reflection["location"] == param["location"]:
            return reflection["context"]
    if param["location"] == "json":
        return "json"
    if "url" in str(param["name"]).lower() or str(param["value"]).lower().startswith(("http", "/")):
        return "url"
    return "unknown"


def generate_test_code(args: dict[str, Any]) -> str:
    parameter = str(args["parameter"])
    context = str(args.get("context", "unknown"))
    url = str(args.get("url", ""))
    plan = build_test_plan(
        parameter=parameter,
        context=context,
        url=url,
        mode=args.get("mode", "reflection_marker"),
        marker=args.get("marker"),
    )
    payloads = plan["payloads"]
    if plan["mode"] == "reflection_marker":
        return json.dumps(plan, indent=2)
    helper = [
        f"// Authorized manual XSS {plan['mode']} helper ({plan['riskTier']} risk).",
        f"const parameter = {json.dumps(parameter)};",
        f"const payloads = {json.dumps(payloads, indent=2)};",
    ]
    if url:
        helper.extend(
            [
                f"const target = new URL({json.dumps(url)}, location.origin);",
                "for (const payload of payloads) {",
                "  target.searchParams.set(parameter, payload);",
                "  console.log(target.toString());",
                "}",
            ]
        )
    else:
        helper.extend(
            [
                "for (const payload of payloads) {",
                "  console.log(`${parameter}=${encodeURIComponent(payload)}`);",
                "}",
            ]
        )
    plan["browserConsoleHelper"] = "\n".join(helper)
    return json.dumps(plan, indent=2)


def build_test_plan(
    *,
    parameter: str,
    context: str = "unknown",
    url: str = "",
    mode: Any = "reflection_marker",
    marker: Any = None,
) -> dict[str, Any]:
    normalized_mode = normalize_test_mode(mode)
    normalized_marker = validate_reflection_marker(marker, seed=f"{parameter}|{context}|{url}")
    if normalized_mode == "reflection_marker":
        payloads = [normalized_marker]
        encoding_variants = [
            {"encoding": "raw", "value": normalized_marker},
            {"encoding": "url", "value": normalized_marker},
            {"encoding": "html", "value": normalized_marker},
        ]
        capability = "reflection_only"
    elif normalized_mode == "context_breakout":
        payloads = context_breakout_payloads(context, normalized_marker)
        encoding_variants = []
        capability = "syntax_breakout"
    else:
        payloads = execution_payloads_for_context(context, normalized_marker)
        encoding_variants = []
        capability = "script_execution"
    return {
        "parameter": parameter,
        "context": context,
        "url": url,
        "mode": normalized_mode,
        "riskTier": XSS_MODE_RISK_TIERS[normalized_mode],
        "payloadCapability": capability,
        "marker": normalized_marker,
        "payloads": payloads,
        "exactWirePayloads": list(payloads),
        "encodingVariants": encoding_variants,
        "browserConsoleHelper": None,
    }


def normalize_test_mode(value: Any) -> str:
    mode = str(value or "reflection_marker").strip().lower()
    if mode not in XSS_TEST_MODES:
        raise McpError(-32602, f"XSS mode must be one of: {', '.join(XSS_TEST_MODES)}.")
    return mode


def validate_reflection_marker(value: Any, *, seed: str) -> str:
    if value is None or str(value) == "":
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16].upper()
        return f"SYNAPSEXSS{digest}"
    marker = str(value)
    if not re.fullmatch(r"[A-Za-z0-9]{4,80}", marker):
        raise McpError(-32602, "XSS reflection markers must be 4-80 ASCII alphanumeric characters and are sent without rewriting.")
    return marker


def context_breakout_payloads(context: str, marker: str) -> list[str]:
    payloads = {
        "html": [f'"><synapse-xss data-token="{marker}"></synapse-xss>'],
        "attribute": [f'" data-synapse-xss="{marker}" x="', f"' data-synapse-xss='{marker}' x='"],
        "script": [f"';/*{marker}*/", f'";/*{marker}*/'],
        "js-string": [f"';/*{marker}*/", f'";/*{marker}*/'],
        "url": [f"synapse-xss-{marker}"],
        "json": [f'"{marker}"'],
        "unknown": [f'"><synapse-xss data-token="{marker}"></synapse-xss>', f'" data-synapse-xss="{marker}" x="'],
    }
    return payloads.get(str(context).lower(), payloads["unknown"])


def execution_payloads_for_context(context: str, marker: str) -> list[str]:
    common = {
        "html": [f'<img src=x onerror=alert("{marker}")>', f'<svg onload=alert("{marker}")>'],
        "attribute": [f'" autofocus onfocus=alert("{marker}") x="', f"' onmouseover=alert(\"{marker}\") x='"],
        "script": [f"';alert(\"{marker}\");//", f'";alert(\"{marker}\");//', f'</script><img src=x onerror=alert("{marker}")>'],
        "js-string": [f"';alert(\"{marker}\");//", f'";alert(\"{marker}\");//'],
        "url": [f'javascript:alert("{marker}")', f'data:text/html,<svg onload=alert("{marker}")>'],
        "json": [f'"}}<img src=x onerror=alert("{marker}")>', f'\\";alert(\"{marker}\");//'],
        "unknown": [f'<img src=x onerror=alert("{marker}")>', f'"><svg onload=alert("{marker}")>', f"';alert(\"{marker}\");//"],
    }
    return common.get(str(context).lower(), common["unknown"])


def analyze_entry(entry: dict[str, Any], max_findings: int, include_test_code: bool) -> dict[str, Any] | None:
    request_file = Path(entry.get("requestFile", ""))
    response_file = Path(entry.get("responseFile", "")) if entry.get("responseFile") else None
    if not request_file.exists():
        return None
    raw_request = request_file.read_text(encoding="utf-8", errors="replace")
    raw_response = response_file.read_text(encoding="utf-8", errors="replace") if response_file and response_file.exists() else ""
    request = parse_request(raw_request)
    response = parse_response(raw_response)
    content_type = response["headers"].get("content-type", "")
    target_path = urlsplit(request["target"]).path
    if target_path.lower().endswith(STATIC_EXTENSIONS) and "text/html" not in content_type:
        return None

    header_findings = analyze_headers(response["headers"])
    parser = HtmlSinkParser()
    if any(kind in content_type for kind in TEXTUAL_TYPES) or raw_response:
        try:
            parser.feed(response["body"][:500000])
        except Exception:
            pass
    reflections = find_reflections(request["params"], response["body"])
    technologies = detect_technologies(request, response)

    candidates = []
    seen = set()
    for param in request["params"]:
        key = (param["location"], param["name"])
        if key in seen:
            continue
        seen.add(key)
        score = score_param(param, reflections)
        if score < 55:
            continue
        context = infer_context(param, reflections)
        candidate = {
            "location": param["location"],
            "name": param["name"],
            "valuePreview": redact_value_preview(param["name"], param.get("value", "")),
            "score": score,
            "likelyContext": context,
            "reason": candidate_reason(param, context, reflections),
        }
        if include_test_code:
            candidate["testCode"] = json.loads(generate_test_code({"parameter": param["name"], "context": context}))
        candidates.append(candidate)
    candidates.sort(key=lambda item: item["score"], reverse=True)

    html_sinks = parser.sinks[:max_findings]
    interesting = bool(candidates or reflections or html_sinks or any(f["severity"] in {"medium", "high"} for f in header_findings))
    return {
        "id": entry.get("id"),
        "host": entry.get("host"),
        "requestLine": entry.get("requestLine") or f"{request['method']} {request['target']}".strip(),
        "status": entry.get("status") or response["status"],
        "requestFile": str(request_file),
        "responseFile": str(response_file) if response_file else None,
        "contentType": content_type,
        "technologyDetection": technologies,
        "securityHeaders": header_findings,
        "htmlSinks": html_sinks,
        "forms": parser.forms[:max_findings],
        "reflections": reflections,
        "injectionCandidates": candidates[:max_findings],
        "interesting": interesting,
    }


def candidate_reason(param: dict[str, Any], context: str, reflections: list[dict[str, Any]]) -> str:
    if any(r["name"] == param["name"] and r["location"] == param["location"] for r in reflections):
        return f"Parameter value is reflected in {context} context."
    if param["location"] == "apex-page-item":
        return "Oracle APEX page item submitted inside p_json; test manually because checksums may protect it."
    if param["location"] in {"query", "body"}:
        return "User-controllable request parameter in a dynamic endpoint."
    if param["location"] == "json":
        return "Scalar JSON field in request body."
    return "Stateful or header-derived value; lower priority unless reflected."


def analyze_burp_dump(args: dict[str, Any]) -> str:
    dump_dir, entries = load_dump_entries(args["dumpPath"])
    only_interesting = bool(args.get("onlyInteresting", True))
    max_findings = int(args.get("maxFindingsPerResponse", 12))
    include_test_code = bool(args.get("includeTestCode", True))
    results = []
    skipped = 0
    aggregate_tech: set[str] = set()
    aggregate_backends: set[str] = set()
    for entry in entries:
        analysis = analyze_entry(entry, max_findings, include_test_code)
        if not analysis:
            skipped += 1
            continue
        aggregate_tech.update(analysis["technologyDetection"]["technologies"])
        aggregate_backends.update(analysis["technologyDetection"]["possibleBackends"])
        if only_interesting and not analysis["interesting"]:
            skipped += 1
            continue
        results.append(analysis)
    return json.dumps(
        {
            "dumpDir": str(dump_dir),
            "entryCount": len(entries),
            "analyzedRequests": len(results),
            "skippedRequests": skipped,
            "aggregateTechnologies": sorted(aggregate_tech),
            "aggregatePossibleBackends": sorted(aggregate_backends),
            "results": results,
        },
        indent=2,
    )
