# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Purple-team correlation helpers."""

from .gap_analysis import generate_gap_finding, mark_detection_outcome
from .technique_reference import TECHNIQUE_DETECTION_MAP, TechniqueReference

__all__ = [
    "TECHNIQUE_DETECTION_MAP",
    "TechniqueReference",
    "generate_gap_finding",
    "mark_detection_outcome",
]
