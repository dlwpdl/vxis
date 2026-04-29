"""CodeEyes — Python AST walker for the Code surface.

Implements the Eyes ABC for the CODE TargetKind. Uses Python's stdlib
`ast` module exclusively (no third-party tree-sitter dependency).
Non-Python files return success=False with summary="lang_unsupported".

Supported focuses:
    "imports"   — list all imported modules (import X / from X import Y)
    "functions" — list all top-level and nested function/async function defs
    "classes"   — list all class definitions with their base classes
    "calls"     — find all call-sites of a specific function name
                  (requires keyword arg: name="func_name")

IMPORTANT: CodeEyes MUST NOT call report_finding at any point.
"""
from __future__ import annotations

import ast
from pathlib import Path

from vxis.interaction.surface import Eyes, InteractionEnvelope, Target, TargetKind


class CodeEyes(Eyes):
    """Python AST inspector for the CODE surface.

    `target.entry` is treated as the repo root. File paths passed via
    `path` keyword are resolved relative to that root.
    """

    def __init__(self, target: Target) -> None:
        self._target = target
        self._root = Path(target.entry).expanduser().resolve()

    # ------------------------------------------------------------------
    # Eyes ABC lifecycle — no-ops for AST walking
    # ------------------------------------------------------------------

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    # ------------------------------------------------------------------
    # Core dispatch
    # ------------------------------------------------------------------

    async def observe(self, focus: str, **kw: object) -> InteractionEnvelope:
        """Walk a Python file's AST and return structural information.

        Args:
            focus: one of "imports", "functions", "classes", "calls"
            **kw:
                path: str — relative path to the Python file (required)
                name: str — function name to search for (required for "calls")

        Returns:
            InteractionEnvelope with surface_kind=CODE.
            artifacts["lines"] contains newline-separated findings.
        """
        path_str = str(kw.get("path", ""))
        if not path_str:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary="path argument required for CodeEyes.observe",
                error="missing path",
            )

        resolved = (self._root / path_str).expanduser().resolve()
        try:
            resolved.relative_to(self._root)
        except ValueError:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary="path traversal rejected",
                error=f"{path_str!r} resolves outside repo root",
            )

        if not resolved.is_file():
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary=f"file not found: {path_str}",
                error="file not found",
            )

        if resolved.suffix.lower() != ".py":
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary="lang_unsupported",
                error=f"CodeEyes supports Python (.py) only; got {resolved.suffix!r}",
            )

        try:
            source = resolved.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(resolved))
        except SyntaxError as exc:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary=f"syntax error in {path_str}: {exc}",
                error=str(exc),
            )
        except OSError as exc:
            return InteractionEnvelope(
                surface_kind=TargetKind.CODE,
                success=False,
                summary=f"read error: {exc}",
                error=str(exc),
            )

        rel = str(resolved.relative_to(self._root))

        if focus == "imports":
            return self._extract_imports(tree, rel)
        if focus == "functions":
            return self._extract_functions(tree, rel)
        if focus == "classes":
            return self._extract_classes(tree, rel)
        if focus == "calls":
            name = str(kw.get("name", ""))
            if not name:
                return InteractionEnvelope(
                    surface_kind=TargetKind.CODE,
                    success=False,
                    summary="name argument required for focus='calls'",
                    error="missing name",
                )
            return self._extract_calls(tree, rel, name)

        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=False,
            summary=f"unknown focus: {focus!r}",
            error=f"CodeEyes supports 'imports','functions','classes','calls'; got {focus!r}",
        )

    # ------------------------------------------------------------------
    # AST extraction helpers
    # ------------------------------------------------------------------

    def _extract_imports(self, tree: ast.AST, rel: str) -> InteractionEnvelope:
        lines: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    lines.append(f"import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                names = ", ".join(a.name for a in node.names)
                lines.append(f"from {module} import {names}")
        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=True,
            summary=f"{rel}: {len(lines)} import(s)",
            artifacts={"path": rel, "lines": "\n".join(lines)},
        )

    def _extract_functions(self, tree: ast.AST, rel: str) -> InteractionEnvelope:
        lines: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = [a.arg for a in node.args.args]
                prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
                lines.append(
                    f"line {node.lineno}: {prefix} {node.name}({', '.join(args)})"
                )
        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=True,
            summary=f"{rel}: {len(lines)} function(s)",
            artifacts={"path": rel, "lines": "\n".join(lines)},
        )

    def _extract_classes(self, tree: ast.AST, rel: str) -> InteractionEnvelope:
        lines: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                bases = [ast.unparse(b) for b in node.bases]
                base_str = f"({', '.join(bases)})" if bases else ""
                lines.append(f"line {node.lineno}: class {node.name}{base_str}")
        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=True,
            summary=f"{rel}: {len(lines)} class(es)",
            artifacts={"path": rel, "lines": "\n".join(lines)},
        )

    def _extract_calls(
        self, tree: ast.AST, rel: str, name: str
    ) -> InteractionEnvelope:
        lines: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = _call_name(node)
                if call_name and (call_name == name or call_name.endswith(f".{name}")):
                    lines.append(f"line {node.lineno}: {call_name}(...)")
        return InteractionEnvelope(
            surface_kind=TargetKind.CODE,
            success=True,
            summary=f"{rel}: {len(lines)} call(s) to '{name}'",
            artifacts={"path": rel, "lines": "\n".join(lines)},
        )


def _call_name(node: ast.Call) -> str | None:
    """Extract the textual name from a Call node's func attribute."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return ast.unparse(func)
    return None
