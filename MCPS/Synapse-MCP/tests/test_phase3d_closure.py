"""Deterministic automated gates owned by Phase 3D closure."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import unittest

from synapse_mcp.app.facade import CompactProjection, DirectProjection
from synapse_mcp.transport.stdio_server import TOOL_SCHEMAS


FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "phase3d"


def _serialize(value: list[dict[str, object]]) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _surface_values() -> dict[str, list[dict[str, object]]]:
    return {
        "legacy": list(TOOL_SCHEMAS),
        "modern-compact": [
            operation.model_dump(mode="json", by_alias=True)
            for operation in CompactProjection().operations()
        ],
        "modern-direct": [
            operation.model_dump(mode="json", by_alias=True)
            for operation in DirectProjection().operations()
        ],
    }


class Phase3DPayloadGateTests(unittest.TestCase):
    def test_payload_fixtures_match_the_frozen_serialization_boundary(self) -> None:
        manifest = json.loads(
            (FIXTURE_DIR / "payload-manifest.json").read_text(encoding="utf-8")
        )
        values = _surface_values()
        self.assertEqual(manifest["legacyBaselineBytes"], 99_337)
        self.assertEqual(manifest["compactMaximumBytes"], 24_834)
        recorded_surfaces = manifest["applicationProjection"]["surfaces"]
        for name, surface in values.items():
            with self.subTest(surface=name):
                payload = _serialize(surface)
                fixture = (FIXTURE_DIR / f"{name}-tools.json").read_bytes()
                self.assertEqual(fixture, payload + b"\n")
                recorded = recorded_surfaces[name]
                self.assertEqual(recorded["toolCount"], len(surface))
                self.assertEqual(recorded["compactUtf8Bytes"], len(payload))
                self.assertEqual(recorded["sha256"], sha256(payload).hexdigest())

    def test_compact_gate_and_repeated_determinism(self) -> None:
        first = _surface_values()
        second = _surface_values()
        for name in first:
            self.assertEqual(_serialize(first[name]), _serialize(second[name]))
        legacy = _serialize(first["legacy"])
        compact = _serialize(first["modern-compact"])
        direct = _serialize(first["modern-direct"])
        self.assertEqual(len(first["legacy"]), 174)
        self.assertEqual(len(legacy), 99_337)
        self.assertEqual(len(first["modern-compact"]), 11)
        self.assertLessEqual(len(compact), 24_834)
        self.assertLess(len(compact) * 4, len(legacy))
        self.assertEqual(len(first["modern-direct"]), 174)
        self.assertGreater(len(direct), len(legacy))


if __name__ == "__main__":
    unittest.main()
