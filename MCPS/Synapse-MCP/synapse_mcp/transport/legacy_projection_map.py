# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Protocol-specific legacy names and serializers for migrated actions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


SerializerChoice = Literal["transport", "executor"]


@dataclass(frozen=True, slots=True)
class LegacyProjection:
    legacy_name: str
    serializer: SerializerChoice


LEGACY_PROJECTION_MAP = {
    "jobs.status": LegacyProjection("jobs.status", "transport"),
    "workspace.summary": LegacyProjection("workspace.summary", "transport"),
    "workspace.prepare_target_context": LegacyProjection(
        "workspace.prepare_target_context",
        "transport",
    ),
    "headers_cookies.analyze_workspace": LegacyProjection(
        "headers_cookies.analyze_workspace",
        "executor",
    ),
    "cors.execute_test": LegacyProjection("cors.execute_test", "executor"),
    "crawler.crawl": LegacyProjection("crawler.crawl", "executor"),
}
