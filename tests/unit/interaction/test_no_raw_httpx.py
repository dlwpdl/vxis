"""AST guard — phase-B: enforce that raw `httpx` imports stay confined to the
HTTP-abstraction owners after the full skill + growth purge.

ALLOWED: abstraction owners that legitimately hold raw httpx (impl side).
  - src/vxis/interaction/hands.py        — SessionManager / TargetSession
  - src/vxis/agent/tools/hands_tools.py  — BrainTool wrapper around Hands
  - src/vxis/ghost/transport.py          — httpx.AsyncBaseTransport subclass
                                           (wired into hands.py via GhostTransport)

Every other file in src/vxis must route HTTP through SessionManager.
"""
from __future__ import annotations

import ast
import pathlib

ALLOWED: frozenset[str] = frozenset({
    "src/vxis/interaction/hands.py",
    "src/vxis/agent/tools/hands_tools.py",
    "src/vxis/ghost/transport.py",
})


def test_no_module_uses_raw_httpx() -> None:
    """phase-B full purge — raw httpx confined to ALLOWED owners only."""
    root = pathlib.Path(__file__).resolve().parents[3] / "src" / "vxis"
    repo_root = root.parents[1]
    offenders: list[str] = []

    for p in root.rglob("*.py"):
        rel = p.resolve().relative_to(repo_root).as_posix()
        if any(rel.endswith(a) or rel == a for a in ALLOWED):
            continue
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [n.name for n in node.names]
                if isinstance(node, ast.ImportFrom) and node.module:
                    names.append(node.module)
                if any(n and n.split(".")[0] == "httpx" for n in names):
                    offenders.append(f"{rel}:{node.lineno}")

    assert offenders == [], (
        "raw httpx found outside ALLOWED abstraction owners — route through "
        "vxis.interaction.hands.SessionManager instead:\n  "
        + "\n  ".join(offenders)
    )
