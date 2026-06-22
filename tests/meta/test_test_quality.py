from __future__ import annotations

import ast
from pathlib import Path


class _AssertionVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.has_assertion = False

    def visit_Assert(self, node: ast.Assert) -> None:
        self.has_assertion = True
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if "pytest.raises" in ast.unparse(item.context_expr):
                self.has_assertion = True
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        for item in node.items:
            if "pytest.raises" in ast.unparse(item.context_expr):
                self.has_assertion = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        called = ast.unparse(node.func)
        if ".assert_" in called or called in {"pytest.fail", "self.fail"}:
            self.has_assertion = True
        self.generic_visit(node)


def test_every_test_function_has_an_assertion_contract() -> None:
    missing: list[str] = []
    for path in sorted(Path("tests").rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not node.name.startswith("test"):
                continue
            visitor = _AssertionVisitor()
            visitor.visit(node)
            if not visitor.has_assertion:
                missing.append(f"{path}:{node.lineno}:{node.name}")

    assert missing == []
