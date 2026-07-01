# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit


STATIC_ASSET_EXTENSIONS = (
    ".css",
    ".js",
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
HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")
COMMON_ROOT_ASSET_PREFIXES = (
    "assets/",
    "static/",
    "dist/",
    "build/",
    "public/",
    "vendor/",
    "scripts/",
    "styles/",
)
COMMON_ROOT_ASSET_FILES = (
    "main.js",
    "polyfills.js",
    "scripts.js",
    "styles.css",
    "runtime.js",
    "vendor.js",
)
METHOD_PREFIX_RE = re.compile(r"^\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://\S+)\s*$", re.IGNORECASE)


def strip_method_prefix(value: Any) -> str:
    text = str(value or "").strip()
    match = METHOD_PREFIX_RE.match(text)
    return match.group(2) if match else text


def normalize_surface_url(value: Any) -> str:
    text = strip_method_prefix(value)
    parsed = urlsplit(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def observation_surface_url(observation: dict[str, Any]) -> str:
    for key in ("url", "requestUrl", "value"):
        url = normalize_surface_url(observation.get(key, ""))
        if url:
            return url
    return ""


def is_static_asset_url(url: Any) -> bool:
    return urlsplit(str(url or "")).path.lower().endswith(STATIC_ASSET_EXTENSIONS)


def has_repeated_path_segment(url: Any) -> bool:
    segments = [segment.lower() for segment in urlsplit(str(url or "")).path.split("/") if segment]
    for index in range(len(segments) - 1):
        if segments[index] == segments[index + 1]:
            return True
    return False


def is_numeric_spa_route(url: Any) -> bool:
    segments = [segment for segment in urlsplit(str(url or "")).path.split("/") if segment]
    return len(segments) == 1 and segments[0].isdigit()


def is_candidate_noise_url(url: Any) -> bool:
    clean = normalize_surface_url(url)
    if not clean:
        return False
    return is_static_asset_url(clean) or is_numeric_spa_route(clean) or has_repeated_path_segment(clean)


def is_spa_shell_asset_record(record: dict[str, Any]) -> bool:
    if not isinstance(record, dict) or not is_static_asset_url(record.get("url", "")):
        return False
    if not record.get("fetched"):
        return False
    content_types = [str(item).lower() for item in (record.get("contentTypes") or []) if str(item).strip()]
    if not content_types:
        return False
    return all(any(kind in content_type for kind in HTML_CONTENT_TYPES) for content_type in content_types)


def is_likely_spa_asset_pollution(url: Any) -> bool:
    path = urlsplit(str(url or "")).path.lower()
    if not path.endswith(STATIC_ASSET_EXTENSIONS):
        return False
    segments = [segment for segment in path.split("/") if segment]
    if has_repeated_path_segment(str(url)):
        return True
    for index in range(1, len(segments) - 1):
        if segments[index : index + 2] == ["assets", "public"]:
            return True
    return False


def should_resolve_asset_from_root(raw: str) -> bool:
    clean = raw.strip().lstrip("./")
    lower = clean.lower()
    if not lower or lower.startswith(("/", "http://", "https://", "//")):
        return False
    if not lower.endswith(STATIC_ASSET_EXTENSIONS):
        return False
    return lower.startswith(COMMON_ROOT_ASSET_PREFIXES) or lower in COMMON_ROOT_ASSET_FILES or lower.startswith("chunk-")


def resolve_discovered_link(raw: str, page_base: str) -> str:
    if should_resolve_asset_from_root(raw):
        parsed = urlsplit(page_base)
        if parsed.scheme and parsed.netloc:
            root = f"{parsed.scheme}://{parsed.netloc}/"
            return urljoin(root, raw)
    return urljoin(page_base, raw)
