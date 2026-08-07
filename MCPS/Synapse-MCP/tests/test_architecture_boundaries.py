from __future__ import annotations

import ast
from pathlib import Path
import unittest


PACKAGE_ROOT = Path(__file__).resolve().parents[1] / "synapse_mcp"


def _module_and_package(path: Path) -> tuple[str, str]:
    relative = path.relative_to(PACKAGE_ROOT).with_suffix("")
    parts = ("synapse_mcp", *relative.parts)
    if parts[-1] == "__init__":
        module = ".".join(parts[:-1])
        return module, module
    module = ".".join(parts)
    return module, module.rsplit(".", 1)[0]


def _resolved_imports(path: Path) -> set[str]:
    _, package = _module_and_package(path)
    package_parts = package.split(".")
    imports: set[str] = set()
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module:
                    imports.add(node.module)
                    imports.update(
                        f"{node.module}.{alias.name}"
                        for alias in node.names
                        if alias.name != "*"
                    )
                continue
            keep = len(package_parts) - (node.level - 1)
            base = package_parts[: max(keep, 0)]
            if node.module:
                base.extend(node.module.split("."))
            resolved_base = ".".join(base)
            imports.add(resolved_base)
            imports.update(
                f"{resolved_base}.{alias.name}"
                for alias in node.names
                if resolved_base and alias.name != "*"
            )
    return imports


def _assert_no_imports(test: unittest.TestCase, roots, forbidden) -> None:
    failures: list[str] = []
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            for imported in sorted(_resolved_imports(path)):
                if any(
                    imported == prefix or imported.startswith(f"{prefix}.")
                    for prefix in forbidden
                ):
                    failures.append(f"{path.relative_to(PACKAGE_ROOT)} -> {imported}")
    test.assertEqual(failures, [], "forbidden imports:\n" + "\n".join(failures))


class ArchitectureBoundaryTests(unittest.TestCase):
    def test_application_layer_has_no_transport_imports(self) -> None:
        _assert_no_imports(
            self,
            [PACKAGE_ROOT / "app"],
            {"synapse_mcp.transport"},
        )

    def test_core_and_adapters_do_not_import_app_or_transport(self) -> None:
        _assert_no_imports(
            self,
            [PACKAGE_ROOT / "core", PACKAGE_ROOT / "adapters"],
            {"synapse_mcp.app", "synapse_mcp.transport"},
        )


if __name__ == "__main__":
    unittest.main()
