"""AST guard — Code surface MUST NOT call report_finding.

This test parses every Python file under src/vxis/interaction/code/
and asserts that none of them contain a call to `report_finding`.
The Code surface is a hypothesis-only layer; findings are emitted only
after a dynamic surface (web/desktop) confirms a hypothesis.

If this test fails it means a developer accidentally added a
report_finding call inside the Code surface, which would bypass the
dynamic-verification requirement and corrupt scoring.
"""
from __future__ import annotations

import ast
from pathlib import Path


_CODE_SURFACE_DIR = (
    Path(__file__).parent.parent.parent.parent.parent
    / "src" / "vxis" / "interaction" / "code"
)


def _collect_report_finding_calls(tree: ast.AST) -> list[tuple[int, str]]:
    """Return (lineno, source_repr) for every call to report_finding."""
    violations: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name: str | None = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name == "report_finding":
                violations.append((node.lineno, ast.unparse(node)))
    return violations


def test_no_report_finding_in_code_surface():
    """All files under interaction/code/ must be free of report_finding calls."""
    assert _CODE_SURFACE_DIR.is_dir(), (
        f"Code surface directory not found: {_CODE_SURFACE_DIR}\n"
        "Has phase-A2 been implemented yet?"
    )

    all_violations: list[str] = []

    for py_file in sorted(_CODE_SURFACE_DIR.rglob("*.py")):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue  # Broken file — a different test catches syntax errors

        for lineno, call_src in _collect_report_finding_calls(tree):
            rel = py_file.relative_to(_CODE_SURFACE_DIR.parent.parent.parent)
            all_violations.append(f"  {rel}:{lineno}: {call_src}")

    assert not all_violations, (
        "Code surface MUST NOT call report_finding — findings are only emitted "
        "after dynamic surface confirmation:\n" + "\n".join(all_violations)
    )
