# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Canonical operational-effect vocabulary and replay-safety coverage.

This module is protocol and transport independent. Descriptor declarations,
sealed execution plans, authority grants, and continuations all consume this
single relation so a replay class cannot change meaning between layers.
"""

from __future__ import annotations


TRAFFIC_DESTINATIONS = frozenset({"authorized_target", "third_party"})
LOCAL_WRITE_DOMAINS = frozenset(
    {
        "workspace",
        "evidence",
        "credentials",
        "jobs",
        "runtime_config",
        "reports_artifacts",
    }
)
REPLAY_SAFETY_VALUES = (
    "pure_read",
    "idempotent_write",
    "non_idempotent",
    "idempotent_control",
    "conditional",
)

_REPLAY_COVERAGE = {
    "pure_read": frozenset({"pure_read"}),
    "idempotent_write": frozenset({"pure_read", "idempotent_write", "idempotent_control"}),
    "idempotent_control": frozenset({"pure_read", "idempotent_write", "idempotent_control"}),
    "conditional": frozenset({"pure_read", "conditional"}),
    "non_idempotent": frozenset(REPLAY_SAFETY_VALUES),
}


def validate_replay_safety(value: object) -> str:
    normalized = str(value)
    if normalized not in _REPLAY_COVERAGE:
        raise ValueError(f"Unknown replay-safety class: {normalized}")
    return normalized


def replay_safety_covers(granted: object, required: object) -> bool:
    maximum = validate_replay_safety(granted)
    actual = validate_replay_safety(required)
    return actual in _REPLAY_COVERAGE[maximum]


def validate_effect_names(*, traffic: object, local_writes: object) -> None:
    traffic_values = {str(item) for item in traffic}  # type: ignore[union-attr]
    local_write_values = {str(item) for item in local_writes}  # type: ignore[union-attr]
    unknown_traffic = sorted(traffic_values.difference(TRAFFIC_DESTINATIONS))
    unknown_writes = sorted(local_write_values.difference(LOCAL_WRITE_DOMAINS))
    if unknown_traffic:
        raise ValueError(f"Unknown traffic destination: {', '.join(unknown_traffic)}")
    if unknown_writes:
        raise ValueError(f"Unknown local-write domain: {', '.join(unknown_writes)}")
