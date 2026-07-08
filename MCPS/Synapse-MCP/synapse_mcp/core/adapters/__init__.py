# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Core adapter framework primitives."""

from .base import AdapterUnsupportedMethod, SynapseAdapter
from .models import AdapterExecutionMode, AdapterMetadata
from .registry import AdapterRegistry, default_registry
from .results import (
    ActionEntity,
    AdapterResult,
    DetectionGapFindingEntity,
    EndpointEntity,
    EvidenceReference,
    FindingEntity,
    ObservationEntity,
    ParameterEntity,
    PretextCandidateEntity,
    RecommendedTest,
    ServiceEntity,
    WorkspaceEntityBundle,
    candidate_observation,
    passive_finding,
    surface_candidate,
)

__all__ = [
    "AdapterMetadata",
    "AdapterExecutionMode",
    "AdapterRegistry",
    "AdapterResult",
    "AdapterUnsupportedMethod",
    "EndpointEntity",
    "EvidenceReference",
    "FindingEntity",
    "PretextCandidateEntity",
    "DetectionGapFindingEntity",
    "ObservationEntity",
    "ParameterEntity",
    "RecommendedTest",
    "ServiceEntity",
    "SynapseAdapter",
    "WorkspaceEntityBundle",
    "ActionEntity",
    "candidate_observation",
    "passive_finding",
    "surface_candidate",
    "default_registry",
]
