"""Phase Q — surface guard tests.

Brain LLM ignores the desktop preamble's "DO NOT call web skills" rule on
~30% of iters and dispatches `run_skill test_infra` etc. against file://
paths, producing false-positive cloud_metadata reports. The dispatch-level
guard at scan_loop.py L805 must:

1. Block the dispatch (no actual run_skill call).
2. Inject a tool result with `surface_guard_blocked=True`.
3. Inject a SYSTEM HINT so Brain re-plans toward a desktop skill.
4. Continue the loop (not crash).

Symmetric: web targets must NOT be blocked from running web skills.
"""

from __future__ import annotations

import pytest

from vxis.agent.scan_loop import ScanAgentLoop, _DESKTOP_SKILLS
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.interaction.surface import TargetKind


class _FinishTool:
    name = "finish_scan"
    description = "end scan"
    input_schema = {"type": "object"}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary="finished", data={"final": True})


class _RunSkillSpy:
    """run_skill stub that records every dispatch — guard must prevent web
    skills from reaching here on desktop targets."""

    name = "run_skill"
    description = "fire payloads"
    input_schema = {
        "type": "object",
        "properties": {"skill": {"type": "string"}},
    }

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def run(self, **kwargs) -> ToolResult:
        self.calls.append(dict(kwargs))
        return ToolResult(
            ok=True,
            summary=f"ran {kwargs.get('skill')}",
            data={"findings": []},
        )


@pytest.mark.asyncio
async def test_surface_guard_blocks_web_skill_on_desktop_target() -> None:
    spy = _RunSkillSpy()
    reg = ToolRegistry()
    reg.register(spy)
    reg.register(_FinishTool())

    loop = ScanAgentLoop(
        target="/Applications/Calculator.app",
        registry=reg,
        max_iters=3,
        target_kind=TargetKind.DESKTOP,
    )

    decisions = iter(
        [
            [("run_skill", {"skill": "test_infra", "target_url": "/Applications/Calculator.app"})],
            [("run_skill", {"skill": "test_csrf", "target_url": "/Applications/Calculator.app"})],
            [("finish_scan", {})],
        ]
    )

    async def _fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop._decide = _fake_decide  # type: ignore[assignment]
    await loop.run()

    # Spy must have received ZERO calls — guard blocks before dispatch.
    assert spy.calls == [], f"web skills reached dispatch: {spy.calls}"

    # Tool messages must record the block.
    blocks = [
        m
        for m in loop.state.messages
        if m.get("role") == "tool"
        and isinstance(m.get("content"), dict)
        and (m["content"].get("result") or {}).get("data", {}).get("surface_guard_blocked")
    ]
    assert len(blocks) == 2, f"expected 2 blocks, got {len(blocks)}"
    assert blocks[0]["content"]["result"]["data"]["requested_skill"] == "test_infra"
    assert blocks[1]["content"]["result"]["data"]["requested_skill"] == "test_csrf"


@pytest.mark.asyncio
async def test_surface_guard_allows_desktop_skill_on_desktop_target() -> None:
    spy = _RunSkillSpy()
    reg = ToolRegistry()
    reg.register(spy)
    reg.register(_FinishTool())

    loop = ScanAgentLoop(
        target="/Applications/Calculator.app",
        registry=reg,
        max_iters=2,
        target_kind=TargetKind.DESKTOP,
    )

    decisions = iter(
        [
            [
                (
                    "run_skill",
                    {"skill": "test_signature_audit", "target_url": "/Applications/Calculator.app"},
                )
            ],
            [("finish_scan", {})],
        ]
    )

    async def _fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop._decide = _fake_decide  # type: ignore[assignment]
    await loop.run()

    assert len(spy.calls) == 1
    assert spy.calls[0]["skill"] == "test_signature_audit"


@pytest.mark.asyncio
async def test_surface_guard_inert_on_web_target() -> None:
    """Web targets must keep their existing behaviour — guard only fires on
    desktop kind."""
    spy = _RunSkillSpy()
    reg = ToolRegistry()
    reg.register(spy)
    reg.register(_FinishTool())

    loop = ScanAgentLoop(
        target="http://localhost:3000",
        registry=reg,
        max_iters=2,
        target_kind=TargetKind.WEB,
    )

    decisions = iter(
        [
            [("run_skill", {"skill": "test_infra", "target_url": "http://localhost:3000"})],
            [("finish_scan", {})],
        ]
    )

    async def _fake_decide(state):
        try:
            return next(decisions)
        except StopIteration:
            return [("finish_scan", {})]

    loop._decide = _fake_decide  # type: ignore[assignment]
    await loop.run()

    assert len(spy.calls) == 1
    assert spy.calls[0]["skill"] == "test_infra"


def test_desktop_skills_set_is_frozen() -> None:
    assert isinstance(_DESKTOP_SKILLS, frozenset)
    assert "test_signature_audit" in _DESKTOP_SKILLS
    assert "test_infra" not in _DESKTOP_SKILLS


def test_desktop_skills_matches_vector_mapping() -> None:
    """Symmetry pin: every key in `_DESKTOP_SKILL_TO_VECTORS` MUST be in
    `_DESKTOP_SKILLS` — otherwise new skills add vectors to the denominator
    (`total_vectors` in VC scoring) without being dispatchable, producing
    a permanent Vector Coverage penalty.

    Regression: Phase-F commits 3ff0e57 (test_ipc_injection) + 89235e8
    (test_binary_protections) added 4 new DESK-* vectors to the mapping
    but left `_DESKTOP_SKILLS` at 6 entries — smoke rerun showed VC
    dropped 120→98 (-18%) on both Calculator and ProtoPie because the
    loop's surface guard rejected every Brain dispatch of the new skills.
    """
    from vxis.pipeline.scan_pipeline_v2 import _DESKTOP_SKILL_TO_VECTORS

    missing = set(_DESKTOP_SKILL_TO_VECTORS) - _DESKTOP_SKILLS
    assert missing == set(), (
        f"skills mapped to desktop vectors but not in _DESKTOP_SKILLS: "
        f"{sorted(missing)} — this guarantees VC penalty (vectors in "
        f"denominator but never attempted). Add to scan_loop.py:134."
    )


# ─── Phase Q2: dedup discriminator ────────────────────────────────────
# Without it, 18 dylib_hijack findings on the same .app bundle dedup to a
# single VXIS-NNNN. The promotion block must append the per-finding key
# (dylib name, entitlement, scheme, flag) to affected_component so each
# distinct issue gets its own report row. Tested by inspecting the
# promotion-block source for the discriminator logic — driving through
# scan_loop's auto-scheduler is too brittle for a unit test.


def test_phase_q2_promotion_block_includes_discriminator_logic() -> None:
    """Source-level guard: the desktop auto-promotion block must include
    the dedup discriminator logic. If someone refactors the block away,
    this test catches it."""
    import pathlib

    src = pathlib.Path("src/vxis/agent/scan_loop_run_skills.py").read_text()
    # Block exists.
    assert "Desktop skill auto-promotion" in src
    # Discriminator logic appends per-finding key.
    assert 'finding.get("dylib")' in src
    assert 'finding.get("entitlement_key")' in src
    assert 'finding.get("scheme")' in src
    assert 'finding.get("flag")' in src
    # Joins discriminator with '#' so finding_tools dedup treats each
    # combo as a distinct slot.
    assert '_loc_with_disc = f"{_loc}#{_disc}"' in src


def test_phase_q2_discriminator_separator_choice() -> None:
    """'#' is preferred over '/' or ':' because file paths legitimately
    contain '/' and ':' (Windows drive letters), but '#' never appears in
    a normal POSIX path or .app bundle structure — making it a safe
    reversible delimiter for downstream report rendering."""
    import pathlib

    src = pathlib.Path("src/vxis/agent/scan_loop_run_skills.py").read_text()
    # Make sure we aren't accidentally using a separator that collides
    # with path semantics.
    assert 'f"{_loc}#{_disc}"' in src
