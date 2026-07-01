# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC
from typing import Any

from .models import AdapterMetadata


class AdapterUnsupportedMethod(NotImplementedError):
    def __init__(self, adapter: str, method: str):
        super().__init__(f"Adapter '{adapter}' does not support '{method}'.")
        self.adapter = adapter
        self.method = method

    def to_response(self) -> dict[str, Any]:
        return {
            "error": "unsupported_adapter_method",
            "adapter": self.adapter,
            "method": self.method,
            "message": str(self),
        }


class SynapseAdapter(ABC):
    metadata: AdapterMetadata

    def capabilities(self) -> dict[str, Any]:
        return self.metadata.as_dict()

    def passive_analyze(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AdapterUnsupportedMethod(self.metadata.name, "passive_analyze")

    def plan(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AdapterUnsupportedMethod(self.metadata.name, "plan")

    def build_command(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AdapterUnsupportedMethod(self.metadata.name, "build_command")

    def run_profile(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AdapterUnsupportedMethod(self.metadata.name, "run_profile")

    def ingest_results(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        raise AdapterUnsupportedMethod(self.metadata.name, "ingest_results")
