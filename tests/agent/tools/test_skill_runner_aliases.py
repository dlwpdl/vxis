from __future__ import annotations

import pytest

from vxis.agent.tools.skill_runner import RunSkillTool, _normalize_skill_name, _reset_cache_for_tests
from vxis.agent.skills import SKILL_REGISTRY


@pytest.mark.asyncio
async def test_run_skill_normalizes_exploit_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    _reset_cache_for_tests()

    async def _fake_injection(*, url: str, **kwargs):
        return {"vulnerable": False, "url": url, "kwargs": kwargs}

    original = SKILL_REGISTRY["test_injection"]["fn"]
    monkeypatch.setitem(SKILL_REGISTRY["test_injection"], "fn", _fake_injection)
    try:
        tool = RunSkillTool()
        result = await tool.run(
            skill="exploit_sqli",
            target_url="http://localhost:3000/search?q=",
            params={},
        )
        assert result.ok is True
        assert "skill:test_injection" in result.summary
    finally:
        monkeypatch.setitem(SKILL_REGISTRY["test_injection"], "fn", original)


def test_normalize_skill_name_maps_common_aliases() -> None:
    assert _normalize_skill_name("exploit_sqli") == "test_injection"
    assert _normalize_skill_name("auth_bypass") == "attempt_auth"
    assert _normalize_skill_name("sqli_bypass") == "attempt_auth"
    assert _normalize_skill_name("sqli_test") == "test_injection"
    assert _normalize_skill_name("exploit_ssrf") == "test_ssrf"
    assert _normalize_skill_name("attempt_auth") == "attempt_auth"
