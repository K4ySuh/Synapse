# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urljoin, urlsplit

from .models import SOURCE


CODE_URL_MARKERS = ("})();", "=>", "function ", "return ", "var ", "let ", "const ", "class ")


def normalize_candidate_url(raw: str, base_url: str) -> str:
    raw = str(raw or "").strip()
    if not raw:
        return ""
    if any(char in raw for char in ("\r", "\n", "\t", "`", "{", "}")):
        return ""
    # A literal with whitespace is prose (e.g. an extracted error/help string that
    # happens to embed a URL), not a route. Real URLs and paths carry no raw spaces.
    if " " in raw:
        return ""
    if any(marker in raw.lower() for marker in CODE_URL_MARKERS):
        return ""
    if raw.startswith("//"):
        scheme = urlsplit(base_url).scheme or "https"
        url = f"{scheme}:{raw}"
    elif raw.startswith(("http://", "https://")):
        url = raw
    elif raw.startswith("/"):
        url = urljoin(base_url, raw)
    else:
        # A bare single-token relative literal with no path separator or extension is an
        # identifier or constant (e.g. "admin", "userId", "ACCOUNT"), not an endpoint
        # path. Real relative route literals carry a "/" (or a file extension).
        if "/" not in raw and "." not in raw:
            return ""
        url = urljoin(base_url.rstrip("/") + "/", raw)
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    if any(char in parsed.path for char in ("{", "}", "`")) or parsed.path.count("/") > 40:
        return ""
    if has_repeated_path_phrase(parsed.path):
        return ""
    return url


def has_repeated_path_phrase(path: str) -> bool:
    segments = [segment for segment in str(path).split("/") if segment]
    if len(segments) < 6:
        return False
    for width in (1, 2, 3):
        for index in range(0, len(segments) - (width * 3) + 1):
            phrase = segments[index : index + width]
            if (
                phrase
                and segments[index + width : index + (width * 2)] == phrase
                and segments[index + (width * 2) : index + (width * 3)] == phrase
            ):
                return True
    return False


def query_parameters(url: str) -> list[str]:
    return sorted({name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True) if name})


def observed_endpoint_keys(existing_endpoints: list[dict[str, Any]]) -> set[tuple[str, str]]:
    keys = set()
    for endpoint in existing_endpoints:
        if not isinstance(endpoint, dict):
            continue
        if endpoint.get("derived") or endpoint.get("inferred"):
            continue
        method = str(endpoint.get("method") or "GET").upper()
        url = str(endpoint.get("url") or "")
        if url:
            keys.add((method, url))
    return keys


def build_entities(
    analysis: dict[str, Any],
    *,
    target: str,
    base_url: str,
    existing_endpoints: list[dict[str, Any]] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    entities: dict[str, list[dict[str, Any]]] = {"endpoints": [], "parameters": [], "observations": []}
    observed_keys = observed_endpoint_keys(existing_endpoints or [])
    endpoint_urls_by_raw: dict[tuple[str, str, str], str] = {}
    emitted_endpoint_keys: set[tuple[str, str]] = set()
    base_host = (urlsplit(base_url).hostname or "").lower()
    target_host = str(target or "").lower()

    for candidate in analysis.get("endpoints", []) if isinstance(analysis.get("endpoints"), list) else []:
        if not isinstance(candidate, dict):
            continue
        raw = str(candidate.get("raw") or "")
        method = str(candidate.get("method") or "GET").upper()
        url = normalize_candidate_url(raw, base_url)
        if not url:
            continue
        parsed = urlsplit(url)
        source_asset = str(candidate.get("sourceAsset") or "")
        endpoint_urls_by_raw[(raw, method, source_asset)] = url
        common = {
            "source": SOURCE,
            "sourceAsset": source_asset,
            "confidence": candidate.get("confidence", "low"),
            "derived": True,
            "inferred": True,
            "observed": False,
            "discoveryMethod": "static_js",
            "reason": candidate.get("reason", ""),
            "line": candidate.get("line", 0),
        }
        candidate_host = (parsed.hostname or "").lower()
        if candidate_host and candidate_host not in {base_host, target_host}:
            entities["observations"].append(
                {
                    "type": "js_external_endpoint_reference",
                    "value": url,
                    "method": method,
                    "target": target,
                    "externalHost": candidate_host,
                    **common,
                    "reason": "JavaScript references an external host; recorded as an inferred external reference, not as target-owned endpoint.",
                    "priority": "low",
                    "priorityScore": 20,
                }
            )
            continue
        if (method, url) in observed_keys:
            entities["observations"].append(
                {
                    "type": "js_endpoint_reference",
                    "value": url,
                    "method": method,
                    "target": target,
                    **common,
                    "reason": "JavaScript references an endpoint already observed in workspace data.",
                    "priority": "low",
                    "priorityScore": 25,
                }
            )
            continue
        if (method, url) in emitted_endpoint_keys:
            continue
        emitted_endpoint_keys.add((method, url))
        entities["endpoints"].append(
            {
                "type": "endpoint",
                "url": url,
                "method": method,
                "host": (parsed.hostname or "").lower(),
                "path": parsed.path or "/",
                "queryParameters": query_parameters(url),
                **common,
            }
        )
        entities["observations"].append(
            {
                "type": "js_inferred_endpoint",
                "value": url,
                "method": method,
                "target": target,
                **common,
                "priority": "medium" if candidate.get("confidence") in {"high", "medium"} else "low",
                "priorityScore": 55 if candidate.get("confidence") == "high" else 45 if candidate.get("confidence") == "medium" else 25,
            }
        )
        for name in query_parameters(url):
            entities["parameters"].append(
                {
                    "type": "parameter",
                    "name": name,
                    "location": "query",
                    "method": method,
                    "url": url,
                    "path": parsed.path or "/",
                    **common,
                }
            )

    fallback_url = base_url
    for candidate in analysis.get("parameters", []) if isinstance(analysis.get("parameters"), list) else []:
        if not isinstance(candidate, dict):
            continue
        name = str(candidate.get("name") or "")
        if not name:
            continue
        source_asset = str(candidate.get("sourceAsset") or "")
        raw = str(candidate.get("endpointRaw") or "")
        method = str(candidate.get("method") or "GET").upper()
        location = str(candidate.get("location", "unknown") or "unknown")
        if not raw and location == "identifier":
            continue
        url = (endpoint_urls_by_raw.get((raw, method, source_asset)) or normalize_candidate_url(raw, base_url)) if raw else fallback_url
        if not url:
            continue
        parsed = urlsplit(url)
        parameter_host = (parsed.hostname or "").lower()
        if parameter_host and parameter_host not in {base_host, target_host}:
            continue
        entities["parameters"].append(
            {
                "type": "parameter",
                "name": name,
                "location": location,
                "method": method,
                "url": url,
                "path": parsed.path or "/",
                "source": SOURCE,
                "sourceAsset": source_asset,
                "confidence": candidate.get("confidence", "low"),
                "derived": True,
                "inferred": True,
                "reason": candidate.get("reason", ""),
            }
        )

    for signal in analysis.get("signals", []) if isinstance(analysis.get("signals"), list) else []:
        if not isinstance(signal, dict):
            continue
        signal_type = str(signal.get("type") or "js_signal")
        value = str(signal.get("value") or "")
        if not value:
            continue
        entities["observations"].append(
            {
                "type": f"js_{signal_type}",
                "value": value,
                "target": target,
                "source": SOURCE,
                "sourceAsset": signal.get("sourceAsset", ""),
                "confidence": signal.get("confidence", "low"),
                "metadata": signal.get("metadata", {}),
                "reason": signal.get("reason", "JavaScript static analysis signal."),
                "derived": True,
                "inferred": True,
                "priority": "medium" if signal.get("confidence") in {"high", "medium"} else "low",
                "priorityScore": 50 if signal.get("confidence") == "high" else 40 if signal.get("confidence") == "medium" else 20,
            }
        )

    for library in analysis.get("libraries", []) if isinstance(analysis.get("libraries"), list) else []:
        if not isinstance(library, dict):
            continue
        name = str(library.get("name") or "")
        if not name:
            continue
        version = str(library.get("version") or "")
        entities["observations"].append(
            {
                "type": "technology_component",
                "value": " ".join([name, version]).strip(),
                "name": name,
                "version": version,
                "cpe": str(library.get("cpe") or ""),
                "versionPrecision": str(library.get("versionPrecision") or "unknown"),
                "layer": "javascript_library",
                "source": "js_asset",
                "target": target,
                "sourceAsset": str(library.get("sourceAsset") or ""),
                "confidence": str(library.get("confidence") or "low"),
                "reason": str(library.get("reason") or f"Client-side library {name} detected in JavaScript asset."),
                "evidenceIds": [],
                "derived": True,
                "inferred": True,
            }
        )

    entities["parameters"] = _dedupe(entities["parameters"], ("method", "url", "location", "name", "sourceAsset"))
    entities["observations"] = _dedupe(entities["observations"], ("type", "value", "method", "sourceAsset"))
    return entities


def _dedupe(items: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    result = []
    for item in items:
        marker = tuple(item.get(key) for key in keys)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(item)
    return result
