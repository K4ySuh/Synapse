# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


SOURCE = "js_intelligence"
Confidence = Literal["low", "medium", "high"]


@dataclass
class JsAsset:
    url: str
    host: str = ""
    path: str = ""
    source: str = SOURCE
    source_endpoint: str = ""
    local_path: str = ""
    sha256: str = ""
    status: int | None = None
    content_type: str = ""
    size: int = 0
    fetched_at: str = ""
    discovered_from: list[str] = field(default_factory=list)
    confidence: Confidence = "medium"

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return {
            "url": payload["url"],
            "host": payload["host"],
            "path": payload["path"],
            "source": payload["source"],
            "sourceEndpoint": payload["source_endpoint"],
            "localPath": payload["local_path"],
            "sha256": payload["sha256"],
            "status": payload["status"],
            "contentType": payload["content_type"],
            "size": payload["size"],
            "fetchedAt": payload["fetched_at"],
            "discoveredFrom": payload["discovered_from"],
            "confidence": payload["confidence"],
        }


@dataclass
class JsEndpointCandidate:
    raw: str
    method: str = "GET"
    source_asset: str = ""
    line: int = 0
    offset: int = 0
    confidence: Confidence = "low"
    reason: str = ""
    source: str = SOURCE
    inferred: bool = True

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return {
            "raw": payload["raw"],
            "method": payload["method"],
            "sourceAsset": payload["source_asset"],
            "line": payload["line"],
            "offset": payload["offset"],
            "confidence": payload["confidence"],
            "reason": payload["reason"],
            "source": payload["source"],
            "inferred": payload["inferred"],
        }


@dataclass
class JsParameterCandidate:
    name: str
    endpoint_raw: str = ""
    method: str = "GET"
    location: str = "unknown"
    source_asset: str = ""
    confidence: Confidence = "low"
    reason: str = ""
    source: str = SOURCE

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return {
            "name": payload["name"],
            "endpointRaw": payload["endpoint_raw"],
            "method": payload["method"],
            "location": payload["location"],
            "sourceAsset": payload["source_asset"],
            "confidence": payload["confidence"],
            "reason": payload["reason"],
            "source": payload["source"],
        }


@dataclass
class JsSignal:
    type: str
    value: str
    source_asset: str = ""
    confidence: Confidence = "low"
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = SOURCE

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        return {
            "type": payload["type"],
            "value": payload["value"],
            "sourceAsset": payload["source_asset"],
            "confidence": payload["confidence"],
            "reason": payload["reason"],
            "metadata": payload["metadata"],
            "source": payload["source"],
        }


@dataclass
class JsAnalysisResult:
    assets: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    parameters: list[dict[str, Any]] = field(default_factory=list)
    signals: list[dict[str, Any]] = field(default_factory=list)
    libraries: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    source: str = SOURCE

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "assets": self.assets,
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "signals": self.signals,
            "libraries": self.libraries,
            "summary": self.summary,
        }
