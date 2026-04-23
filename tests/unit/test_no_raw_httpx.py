"""AST guard — phase-B.4: enforce that raw `httpx` imports stay confined to the
HTTP-abstraction owners. All other call-sites must route through
`SessionManager` (Hands) so X-Ray, CSRF auto-injection, WAF detection, and
Surface dispatch keep working uniformly.

The plan (`scalable-cuddling-wave.md` phase-B.4) called out 4 sites to fix in
this commit:

    - src/vxis/core/fp_pipeline.py:20
    - src/vxis/plugins/game/economy_tester.py:209,245,291,331,378
    - src/vxis/agent/scan_loop.py (`import httpx as _httpx` fallback)
    - src/vxis/agent/tools/fingerprint_tools.py:267

The ALLOWED set below contains exactly the abstraction owners that *should*
keep raw httpx (the impl side) — anything else added to it is regression.

Known-deferred offenders (skills/growth/ghost/playbook md) live in DEFERRED
and will be purged in a follow-up phase. Adding new files there is a
regression too — the test fails if any file uses raw httpx without being in
ALLOWED ∪ DEFERRED.
"""
from __future__ import annotations

import ast
import pathlib

# Files that legitimately own the httpx abstraction. Adding to this list
# requires architectural justification.
ALLOWED: frozenset[str] = frozenset({
    "src/vxis/interaction/hands.py",        # the SessionManager / TargetSession owner
    "src/vxis/agent/tools/hands_tools.py",  # tool-call wrapper around Hands
    "src/vxis/ghost/transport.py",          # httpx.AsyncBaseTransport impl — legitimately owns raw httpx
})

# Pre-existing offenders carved out of phase-B.4 scope. These are tracked for
# a follow-up phase. The list must only shrink — never grow.
# phase-B (skill purge): all skill + growth + ghost entries have been cleaned.
# ghost/transport.py is now promoted to ALLOWED (it is an httpx transport impl).
DEFERRED: frozenset[str] = frozenset()


def _imports_httpx(path: pathlib.Path) -> int | None:
    """Return the line number of the first httpx import, or None if absent."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] == "httpx":
                    return node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] == "httpx":
                return node.lineno
    return None


def test_no_module_uses_raw_httpx_outside_allowed_or_deferred() -> None:
    """phase-B.4 — raw httpx is confined to ALLOWED + DEFERRED files only."""
    root = pathlib.Path(__file__).resolve().parents[2] / "src" / "vxis"
    repo_root = root.parents[1]
    new_offenders: list[str] = []

    for py in root.rglob("*.py"):
        rel = py.resolve().relative_to(repo_root).as_posix()
        if rel in ALLOWED or rel in DEFERRED:
            continue
        line = _imports_httpx(py)
        if line is not None:
            new_offenders.append(f"{rel}:{line}")

    assert not new_offenders, (
        "raw httpx introduced outside the abstraction owners — route through "
        "vxis.interaction.hands.SessionManager instead. Offenders:\n  "
        + "\n  ".join(new_offenders)
    )


def test_phase_b4_documented_files_are_clean() -> None:
    """phase-B.4 — the 4 sites the plan called out for this commit are fixed."""
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    plan_targets = [
        "src/vxis/core/fp_pipeline.py",
        "src/vxis/plugins/game/economy_tester.py",
        "src/vxis/agent/scan_loop.py",
        "src/vxis/agent/tools/fingerprint_tools.py",
    ]
    still_dirty: list[str] = []
    for rel in plan_targets:
        line = _imports_httpx(repo_root / rel)
        if line is not None:
            still_dirty.append(f"{rel}:{line}")
    assert not still_dirty, (
        "phase-B.4 plan targets still import raw httpx:\n  " + "\n  ".join(still_dirty)
    )


def test_deferred_set_only_shrinks() -> None:
    """phase-B.4 — DEFERRED tracks pre-existing debt; new entries are forbidden."""
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    stale: list[str] = []
    for rel in DEFERRED:
        path = repo_root / rel
        if not path.exists():
            stale.append(f"{rel} (file gone — remove from DEFERRED)")
            continue
        if _imports_httpx(path) is None:
            stale.append(f"{rel} (cleaned — remove from DEFERRED)")
    assert not stale, (
        "DEFERRED list is stale — prune cleaned-up entries:\n  " + "\n  ".join(stale)
    )
