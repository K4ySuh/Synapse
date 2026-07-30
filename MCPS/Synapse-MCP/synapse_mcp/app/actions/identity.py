# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Canonical application action identity."""

from __future__ import annotations

import re
from dataclasses import dataclass


_SEGMENT_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True, slots=True)
class ActionId:
    """A canonical ``pack.local_name`` application identifier."""

    pack: str
    local_name: str

    def __post_init__(self) -> None:
        if not isinstance(self.pack, str) or not isinstance(self.local_name, str):
            raise ValueError("Action id segments must be strings")
        segments = (self.pack, *self.local_name.split("."))
        if "." in self.pack or not all(_SEGMENT_PATTERN.fullmatch(segment) for segment in segments):
            raise ValueError(f"Malformed action id: {self.pack}.{self.local_name}")

    @classmethod
    def parse(cls, value: str) -> ActionId:
        """Parse an action id, splitting once at the first dot."""

        if not isinstance(value, str) or "." not in value:
            raise ValueError(f"Action id must be in pack.local_name form: {value!r}")
        pack, local_name = value.split(".", 1)
        return cls(pack=pack, local_name=local_name)

    def __str__(self) -> str:
        return f"{self.pack}.{self.local_name}"
