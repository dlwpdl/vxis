"""Phase Q10 — scan_loop must return real skill names so the pipeline's
`_DESKTOP_SKILL_TO_VECTORS` mapping can credit vector_attempted.

Phase Q9 smoke confirmed `[SCORE] DESKTOP — VC:0` even after Calculator.app
ran test_dylib_hijack + test_signature_audit + test_entitlement_audit. Root
cause: scan_loop returns `_skills_completed`, which contains queue aliases
the iter-25 sweep block creates (e.g. `test_dylib_hijack__sweep25`). The
pipeline's mapping keys are real names (`test_dylib_hijack`), so the
`if skill_name in _completed_skills` lookup never matches → VC=0.

Symmetric companion bug: Brain-direct run_skill dispatches (the LLM picking
a skill on its own, not the auto-exec ladder) never get added to either
`_skills_completed` or `_real_skills_completed` set. So even if Brain
manually picks test_signature_audit, no VC credit.

Both must be fixed for VC to reflect actual skill coverage.
"""

from __future__ import annotations

import pathlib

import pytest

from vxis.agent.scan_loop import ScanAgentLoop
from vxis.agent.tool_registry import ToolRegistry, ToolResult
from vxis.interaction.surface import TargetKind


class _FinishTool:
    name = "finish_scan"
    description = "end scan"
    input_schema = {"type": "object"}

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(ok=True, summary="finished", data={"final": True})


class _RunSkillStub:
    """Successful run_skill stub — every dispatch returns ok=True with no
    findings, so the loop advances cleanly while we observe what scan_loop
    records into its skills_completed set."""

    name = "run_skill"
    description = "fire payloads"
    input_schema = {
        "type": "object",
        "properties": {"skill": {"type": "string"}},
    }

    async def run(self, **kwargs) -> ToolResult:
        return ToolResult(
            ok=True,
            summary=f"ran {kwargs.get('skill')}",
            data={"findings": []},
        )


@pytest.mark.asyncio
async def test_brain_direct_run_skill_credits_skills_completed() -> None:
    """When Brain LLM picks `run_skill` directly (not via the auto-exec
    ladder), the chosen skill name MUST appear in the returned
    `skills_completed` so that pipeline's _DESKTOP_SKILL_TO_VECTORS lookup
    credits vector_attempted. Pre-Q10 this set was empty for Brain-direct
    runs, producing VC:0 on Calculator.app."""
    reg = ToolRegistry()
    reg.register(_RunSkillStub())
    reg.register(_FinishTool())

    loop = ScanAgentLoop(
        target="/System/Applications/Calculator.app",
        registry=reg,
        max_iters=3,
        target_kind=TargetKind.DESKTOP,
    )

    decisions = iter(
        [
            [
                (
                    "run_skill",
                    {
                        "skill": "test_signature_audit",
                        "target_url": "/System/Applications/Calculator.app",
                    },
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
    result = await loop.run()

    assert "test_signature_audit" in result["skills_completed"], (
        f"Brain-direct run_skill MUST credit skills_completed, got {result['skills_completed']!r}"
    )


def test_run_method_returns_real_skill_set_not_aliases() -> None:
    """Source-level guard: scan_loop's run() return MUST surface
    `_real_skills_completed`, not `_skills_completed`. The latter contains
    queue aliases like `test_dylib_hijack__sweep25` that the iter-25 sweep
    block injects — and the pipeline's `_DESKTOP_SKILL_TO_VECTORS` keys are
    real skill names, so alias entries never match.

    Driving the actual sweep mechanism from a unit test is too brittle
    (requires iter≥25 + brain decisions + skill registry); this source-level
    check catches the regression directly.
    """
    src = pathlib.Path("src/vxis/agent/scan_loop_run.py").read_text()
    # The return dict at the end of run() must use _real_skills_completed
    # for the "skills_completed" key. If someone reverts to
    # `list(_skills_completed)`, this fails.
    assert '"skills_completed": list(_real_skills_completed)' in src, (
        "scan_loop.run() must return _real_skills_completed under "
        "'skills_completed' key — alias names break the pipeline mapping."
    )
