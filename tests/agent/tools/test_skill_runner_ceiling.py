"""NOW-2/2d (F2) — exploitation ceiling governs the run_skill attack-template entrypoint.

Under a below-lateral ceiling (read-only/none), active attack skills are refused at
the run_skill gate and never executed; passive recon skills still run; no active
policy = legacy passthrough.
"""
import pytest

import vxis.agent.tools.skill_runner as sr
from vxis.agent.policy.runtime_policy import clear_active_policy, set_active_policy
from vxis.agent.policy.scan_policy import PROFILE_POLICY_TABLE
from vxis.agent.tool_registry import ToolRegistry
from vxis.agent.tools.skill_runner import RunSkillTool


@pytest.fixture
def spy(monkeypatch):
    calls: list[dict] = []

    async def _fn(**kwargs):
        calls.append(kwargs)
        return {"ok": True, "accessible": []}

    fake = {"test_injection": {"fn": _fn}, "enumerate_endpoints": {"fn": _fn}}
    monkeypatch.setattr("vxis.agent.skills.SKILL_REGISTRY", fake, raising=False)
    monkeypatch.setattr("vxis.agent.skill_audit.audit_registered_skill", lambda *a, **k: {}, raising=False)
    sr._reset_cache_for_tests()
    yield calls
    sr._reset_cache_for_tests()


def _reg():
    reg = ToolRegistry()
    reg.register(RunSkillTool())
    return reg


@pytest.mark.asyncio
async def test_run_skill_active_blocked_under_readonly(spy):
    tok = set_active_policy(PROFILE_POLICY_TABLE["standard"])  # read-only
    try:
        r = await _reg().dispatch("run_skill", {"skill": "test_injection", "target_url": "http://t"})
    finally:
        clear_active_policy(tok)
    assert r.ok is False and r.error == "ceiling_blocked"
    assert spy == []  # the active skill fn was never invoked


@pytest.mark.asyncio
async def test_run_skill_passive_allowed_under_readonly(spy):
    tok = set_active_policy(PROFILE_POLICY_TABLE["standard"])  # read-only
    try:
        r = await _reg().dispatch("run_skill", {"skill": "enumerate_endpoints", "target_url": "http://t"})
    finally:
        clear_active_policy(tok)
    assert r.error != "ceiling_blocked"
    assert len(spy) == 1  # passive recon ran


@pytest.mark.asyncio
async def test_run_skill_active_allowed_at_full_ceiling(spy):
    tok = set_active_policy(PROFILE_POLICY_TABLE["aggressive"])  # full
    try:
        r = await _reg().dispatch("run_skill", {"skill": "test_injection", "target_url": "http://t"})
    finally:
        clear_active_policy(tok)
    assert r.error != "ceiling_blocked"
    assert len(spy) == 1


@pytest.mark.asyncio
async def test_run_skill_active_allowed_when_no_policy(spy):
    # legacy: ceiling off → active skill runs (no regression for non-policy scans)
    r = await _reg().dispatch("run_skill", {"skill": "test_injection", "target_url": "http://t"})
    assert r.error != "ceiling_blocked"
    assert len(spy) == 1
