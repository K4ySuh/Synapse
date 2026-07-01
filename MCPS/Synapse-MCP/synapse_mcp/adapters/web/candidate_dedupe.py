# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


def collapse_host_wide(candidates: list[dict[str, Any]], *, subject_key: str) -> list[dict[str, Any]]:
    collapsed: dict[tuple[str, str], dict[str, Any]] = {}
    affected_seen: dict[tuple[str, str], set[str]] = {}
    for candidate in candidates:
        url = str(candidate.get("url", "") or "")
        host = urlsplit(url).netloc.lower()
        subject = str(candidate.get(subject_key, "") or "").lower()
        key = (host, subject)
        current = collapsed.get(key)
        if current is None:
            item = dict(candidate)
            item["dedupeScope"] = "host"
            item["host"] = host
            if subject_key != "subject":
                item["subject"] = subject
            item["affectedUrls"] = [url] if url else []
            item["affectedCount"] = 1 if url else 0
            collapsed[key] = item
            affected_seen[key] = {url} if url else set()
            continue
        seen = affected_seen.setdefault(key, set(current.get("affectedUrls", [])))
        if url:
            current["affectedCount"] = int(current.get("affectedCount", 0) or 0) + 1
            if url not in seen and len(current.setdefault("affectedUrls", [])) < 20:
                current["affectedUrls"].append(url)
                seen.add(url)
        evidence_ids = current.setdefault("evidenceIds", [])
        for evidence_id in candidate.get("evidenceIds", []) if isinstance(candidate.get("evidenceIds"), list) else []:
            if evidence_id not in evidence_ids:
                evidence_ids.append(evidence_id)
    return sorted(collapsed.values(), key=lambda item: int(item.get("priorityScore", 0) or 0), reverse=True)
