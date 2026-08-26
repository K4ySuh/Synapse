# Copyright 2026 Javier Roldán Ortiz
# SPDX-License-Identifier: Apache-2.0

"""Read-only application service and resource projection for selected packs."""

from __future__ import annotations

import json

from .loader import AssembledCapabilityPacks


CAPABILITY_PACK_CATALOG_URI = "synapse://capability-packs"
CAPABILITY_PACK_RESOURCE_TEMPLATE = "synapse://capability-packs/{pack_id}"


class CapabilityPackCatalogService:
    """Expose selected immutable startup contributions without transport state."""

    def __init__(self, assembly: AssembledCapabilityPacks) -> None:
        self.assembly = assembly

    def list(self) -> dict:
        return self.assembly.as_document()

    def inspect(self, pack_id: str) -> dict:
        manifest = self.assembly.pack(pack_id)
        document = self.assembly.as_document()
        return next(
            item for item in document["packs"] if item["packId"] == str(manifest.id)
        )

    def read_resource(self, uri: str) -> tuple[str, str]:
        if uri == CAPABILITY_PACK_CATALOG_URI:
            value = self.list()
        elif uri.startswith(f"{CAPABILITY_PACK_CATALOG_URI}/"):
            pack_id = uri.removeprefix(f"{CAPABILITY_PACK_CATALOG_URI}/")
            if not pack_id or "/" in pack_id:
                raise LookupError(f"Unknown capability-pack resource: {uri}")
            value = self.inspect(pack_id)
        else:
            raise LookupError(f"Unknown capability-pack resource: {uri}")
        return "application/json", json.dumps(value, indent=2, sort_keys=True)
