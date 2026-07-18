# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections import Counter
import hashlib
import math
import re
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlsplit, urlunsplit


REDACTED_QUERY_VALUE = "<redacted>"
SENSITIVE_QUERY_NAMES = {
    "access_token",
    "assertion",
    "auth",
    "authorization",
    "code",
    "context",
    "credential",
    "csrf",
    "id_token",
    "jwt",
    "nonce",
    "oauth_token",
    "password",
    "relaystate",
    "samlrequest",
    "samlresponse",
    "secret",
    "session",
    "sessionid",
    "sid",
    "state",
    "ticket",
    "token",
}
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_+/=-]+$")


def value_fingerprint(value: Any) -> str:
    return hashlib.sha256(str(value or "").encode("utf-8", errors="replace")).hexdigest()[:16]


def is_sensitive_query_name(name: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(name or "").strip().lower()).strip("_")
    if normalized in SENSITIVE_QUERY_NAMES:
        return True
    tokens = {token for token in normalized.split("_") if token}
    return bool(tokens & {"auth", "authorization", "credential", "csrf", "jwt", "nonce", "password", "secret", "session", "ticket", "token"})


def is_high_entropy_value(value: Any) -> bool:
    text = str(value or "").strip()
    if len(text) < 24 or not _OPAQUE_RE.fullmatch(text):
        return False
    counts = Counter(text)
    entropy = -sum((count / len(text)) * math.log2(count / len(text)) for count in counts.values())
    return entropy >= 3.5 or len(text) >= 48


def normalize_parameter_name(name: Any) -> str:
    text = str(name or "").strip().lstrip("?&")
    # Some producers hand parse_qsl an encoded complete ``name=value``
    # fragment. Decode at most twice, then keep only the actual name.
    for _ in range(2):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded.strip().lstrip("?&")
    if "=" in text:
        text = text.split("=", 1)[0].strip()
    if not text or any(ord(char) < 32 for char in text):
        return ""
    text = text[:128]
    if is_high_entropy_value(text):
        return f"opaque_{value_fingerprint(text)[:12]}"
    return text


def safe_query_items(value: Any) -> list[dict[str, Any]]:
    parsed = urlsplit(str(value or ""))
    items: list[dict[str, Any]] = []
    for raw_name, raw_value in parse_qsl(parsed.query, keep_blank_values=True):
        decoded_name = str(raw_name).strip().lstrip("?&")
        embedded_value = ""
        for _ in range(2):
            decoded = unquote(decoded_name)
            if decoded == decoded_name:
                break
            decoded_name = decoded.strip().lstrip("?&")
        if "=" in decoded_name:
            decoded_name, embedded_value = decoded_name.split("=", 1)
        name = normalize_parameter_name(decoded_name)
        if not name:
            continue
        raw = str(raw_value or embedded_value)
        redacted = bool(raw) and (is_sensitive_query_name(name) or is_high_entropy_value(raw))
        item: dict[str, Any] = {"name": name, "value": REDACTED_QUERY_VALUE if redacted else raw, "redacted": redacted}
        if redacted:
            item["valueFingerprint"] = value_fingerprint(raw)
        items.append(item)
    return items


def _safe_netloc(parsed: Any) -> str:
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    return f"{host}:{port}" if port is not None else host


def redact_url_query_values(value: Any, base: str | None = None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    absolute = urljoin(base, text) if base else text
    parsed = urlsplit(absolute)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return ""
    safe_items = safe_query_items(absolute)
    query_parts: list[str] = []
    raw_parts = parsed.query.split("&") if parsed.query else []
    for index, item in enumerate(safe_items):
        raw_part = raw_parts[index] if index < len(raw_parts) else ""
        raw_name = unquote(raw_part.partition("=")[0]).strip().lstrip("?&")
        malformed_name = "=" in raw_name or normalize_parameter_name(raw_name) != raw_name
        if raw_part and not item["redacted"] and not malformed_name:
            query_parts.append(raw_part)
            continue
        encoded_name = quote(item["name"], safe="._-")
        encoded_value = quote(str(item["value"]), safe="")
        query_parts.append(f"{encoded_name}={encoded_value}" if item["value"] != "" else encoded_name)
    query = "&".join(query_parts)
    return urlunsplit((parsed.scheme.lower(), _safe_netloc(parsed), parsed.path or "/", query, ""))


def canonical_url_identity(value: Any, base: str | None = None) -> str:
    redacted = redact_url_query_values(value, base)
    if not redacted:
        return ""
    parsed = urlsplit(redacted)
    names = sorted({item["name"] for item in safe_query_items(redacted)})
    # Preserve only sorted names in the identity; quote directly so no value
    # material or redaction marker can enter keys, candidate IDs, or summaries.
    query = "&".join(quote(name, safe="._-") for name in names)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", query, ""))


def url_identity_key(value: Any) -> str:
    """Collapse only redacted variants while preserving benign value variants."""
    safe_url = redact_url_query_values(value)
    if not safe_url:
        return ""
    if any(item.get("redacted") for item in safe_query_items(value)):
        return canonical_url_identity(value)
    return safe_url


def redact_value_preview(name: Any, value: Any, *, limit: int = 120) -> tuple[str, str]:
    text = str(value or "")
    if not text:
        return "", ""
    if is_sensitive_query_name(name) or is_high_entropy_value(text):
        return REDACTED_QUERY_VALUE, value_fingerprint(text)
    return text[:limit], ""
