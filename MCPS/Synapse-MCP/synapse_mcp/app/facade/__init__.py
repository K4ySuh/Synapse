# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Protocol-independent compact and direct Synapse application surfaces."""

from .catalog import ActionCatalogService, action_annotations, effect_summary
from .contracts import (
    COMPACT_INPUT_MODELS,
    ActionDescription,
    ApplicationOperation,
    FacadeCallContext,
    FacadeEnvelope,
    ResourceReference,
)
from .projections import (
    CompactProjection,
    DirectProjection,
    SurfaceMode,
    build_application_projection,
)
from .resources import ResourceAccessError, ResourceReferenceService
from .services import (
    ActionExecutionService,
    COMPACT_OPERATION_NAMES,
    CompactFacadeService,
    OperationHandleService,
    passive_gate_reasons,
)

__all__ = [
    "ActionCatalogService",
    "ActionDescription",
    "ActionExecutionService",
    "ApplicationOperation",
    "COMPACT_INPUT_MODELS",
    "COMPACT_OPERATION_NAMES",
    "CompactFacadeService",
    "CompactProjection",
    "DirectProjection",
    "FacadeCallContext",
    "FacadeEnvelope",
    "OperationHandleService",
    "ResourceAccessError",
    "ResourceReference",
    "ResourceReferenceService",
    "SurfaceMode",
    "action_annotations",
    "build_application_projection",
    "effect_summary",
    "passive_gate_reasons",
]
