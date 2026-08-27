# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Provider-neutral immutable capability-pack contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Any, Callable

from synapse_mcp.app.actions.descriptor import ActionDescriptor


_PACK_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_VERSION_PATTERN = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)"
    r"(?:(?P<stage>a|b|rc)(?P<number>\d+))?$"
)


@dataclass(frozen=True, slots=True, order=True)
class CapabilityPackId:
    """Stable high-level operational capability identity."""

    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not _PACK_ID_PATTERN.fullmatch(self.value):
            raise ValueError(f"Malformed capability pack id: {self.value!r}")

    @classmethod
    def parse(cls, value: "CapabilityPackId | str") -> "CapabilityPackId":
        return value if isinstance(value, cls) else cls(value)

    def __str__(self) -> str:
        return self.value


class CapabilityPackOrigin(str, Enum):
    BUILTIN = "builtin"
    EXTERNAL = "external"


@dataclass(frozen=True, slots=True)
class CapabilityResource:
    """One on-demand operational documentation/resource contribution."""

    uri: str
    title: str
    summary: str
    media_type: str = "application/json"

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, str)
            for value in (self.uri, self.title, self.summary, self.media_type)
        ):
            raise ValueError("capability resource fields must be strings")
        if not self.uri.startswith("synapse://"):
            raise ValueError("capability resource URI must use the synapse scheme")
        if not self.title.strip() or not self.summary.strip() or not self.media_type.strip():
            raise ValueError("capability resource title, summary, and media type are required")


@dataclass(frozen=True, slots=True)
class CapabilityAvailability:
    """Pack-level availability declaration; action runtime probes remain canonical."""

    kind: str
    summary: str

    def __post_init__(self) -> None:
        if not isinstance(self.kind, str) or not isinstance(self.summary, str):
            raise ValueError("pack availability fields must be strings")
        if self.kind not in {"always", "runtime"}:
            raise ValueError(f"unknown pack availability declaration: {self.kind}")
        if not self.summary.strip():
            raise ValueError("pack availability summary is required")


DescriptorProvider = Callable[[], tuple[ActionDescriptor[Any, Any], ...]]


def version_key(value: str) -> tuple[int, int, int, int, int]:
    """Compare the repository's supported PEP-440-like release versions."""

    match = _VERSION_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError(f"unsupported application version: {value!r}")
    stage = match.group("stage")
    stage_rank = {"a": 0, "b": 1, "rc": 2, None: 3}[stage]
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        stage_rank,
        int(match.group("number") or 0),
    )


@dataclass(frozen=True, slots=True)
class CapabilityPackManifest:
    """Immutable startup contribution around canonical action descriptors."""

    id: CapabilityPackId
    title: str
    summary: str
    contract_version: int
    origin: CapabilityPackOrigin
    distribution_id: str
    descriptor_provider: DescriptorProvider
    action_ids: tuple[str, ...]
    dependencies: tuple[CapabilityPackId, ...] = ()
    resources: tuple[CapabilityResource, ...] = ()
    availability: tuple[CapabilityAvailability, ...] = ()
    application_min: str = "0.6.0b0"
    application_max_exclusive: str = "0.7.0"

    def __post_init__(self) -> None:
        from synapse_mcp.app.actions.identity import ActionId

        if not isinstance(self.id, CapabilityPackId):
            raise ValueError("manifest id must be a CapabilityPackId")
        if not isinstance(self.title, str) or not isinstance(self.summary, str):
            raise ValueError(f"{self.id}: title and summary must be strings")
        if not self.title.strip() or not self.summary.strip():
            raise ValueError(f"{self.id}: title and summary are required")
        if type(self.contract_version) is not int or self.contract_version != 1:
            raise ValueError(f"{self.id}: unsupported capability-pack contract version")
        if not isinstance(self.origin, CapabilityPackOrigin):
            raise ValueError(f"{self.id}: invalid origin")
        if not isinstance(self.distribution_id, str):
            raise ValueError(f"{self.id}: distribution identity must be a string")
        if not self.distribution_id.strip():
            raise ValueError(f"{self.id}: distribution identity is required")
        if not callable(self.descriptor_provider):
            raise ValueError(f"{self.id}: descriptor provider must be callable")
        if not isinstance(self.action_ids, tuple):
            raise ValueError(f"{self.id}: action ids must be an immutable tuple")
        if not self.action_ids:
            raise ValueError(f"{self.id}: at least one action id is required")
        for action_id in self.action_ids:
            if not isinstance(action_id, str):
                raise ValueError(f"{self.id}: action ids must be strings")
            ActionId.parse(action_id)
        if len(self.action_ids) != len(set(self.action_ids)):
            raise ValueError(f"{self.id}: action ids must be unique")
        if not isinstance(self.dependencies, tuple) or not all(
            isinstance(item, CapabilityPackId) for item in self.dependencies
        ):
            raise ValueError(f"{self.id}: dependencies must be an immutable CapabilityPackId tuple")
        dependency_ids = tuple(str(item) for item in self.dependencies)
        if len(dependency_ids) != len(set(dependency_ids)) or str(self.id) in dependency_ids:
            raise ValueError(f"{self.id}: dependencies must be unique and cannot include self")
        if not isinstance(self.resources, tuple) or not all(
            isinstance(item, CapabilityResource) for item in self.resources
        ):
            raise ValueError(f"{self.id}: resources must be an immutable CapabilityResource tuple")
        if len(self.resources) != len({item.uri for item in self.resources}):
            raise ValueError(f"{self.id}: resource URIs must be unique")
        if not isinstance(self.availability, tuple) or not all(
            isinstance(item, CapabilityAvailability) for item in self.availability
        ):
            raise ValueError(
                f"{self.id}: availability must be an immutable CapabilityAvailability tuple"
            )
        if not isinstance(self.application_min, str) or not isinstance(
            self.application_max_exclusive, str
        ):
            raise ValueError(f"{self.id}: application compatibility versions must be strings")
        minimum = version_key(self.application_min)
        maximum = version_key(self.application_max_exclusive)
        if minimum >= maximum:
            raise ValueError(f"{self.id}: invalid application compatibility range")

    def supports(self, application_version: str) -> bool:
        current = version_key(application_version)
        return version_key(self.application_min) <= current < version_key(
            self.application_max_exclusive
        )
