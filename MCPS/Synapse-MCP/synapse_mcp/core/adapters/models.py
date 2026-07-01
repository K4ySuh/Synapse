# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


AdapterCategory = Literal[
    "web",
    "network",
    "cloud",
    "identity",
    "red_team",
    "reporting",
    "custom",
]

AdapterCapability = Literal[
    "passive_analysis",
    "test_planning",
    "active_testing",
    "command_building",
    "result_ingestion",
    "finding_generation",
]

RiskTier = Literal["info", "low", "medium", "high", "critical"]
AdapterExecutionMode = Literal["passive_only", "sync_only", "sync_default", "async_default"]


def to_camel(value: str) -> str:
    parts = value.split("_")
    return parts[0] + "".join(part.capitalize() for part in parts[1:])


class AdapterMetadata(BaseModel):
    name: str
    version: str = "0.1.0"
    category: AdapterCategory
    description: str
    capabilities: list[AdapterCapability]

    requires_scope: bool = True
    sends_traffic: bool = False
    requires_confirmation: bool = False
    requires_credentials: bool = False
    touches_third_party: bool = False

    default_risk_tier: RiskTier = "low"
    execution_mode: AdapterExecutionMode = "passive_only"
    background_job_provider: str = ""
    executor_tool: str = ""

    produces: list[str] = Field(default_factory=lambda: ["observations", "evidence"])
    limitations: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    def as_dict(self, *, by_alias: bool = True) -> dict[str, Any]:
        return self.model_dump(by_alias=by_alias)

    model_config = {"alias_generator": to_camel, "populate_by_name": True}
