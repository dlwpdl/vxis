from __future__ import annotations

import importlib.util

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
        assert result.data["_egress"]["skill"] == "test_injection"
        assert result.data["_egress"]["ghost_coverage"] in {"covered", "not_applicable"}
    finally:
        monkeypatch.setitem(SKILL_REGISTRY["test_injection"], "fn", original)


def test_normalize_skill_name_maps_common_aliases() -> None:
    assert _normalize_skill_name("exploit_sqli") == "test_injection"
    assert _normalize_skill_name("auth_bypass") == "attempt_auth"
    assert _normalize_skill_name("sqli_bypass") == "attempt_auth"
    assert _normalize_skill_name("sqli_test") == "test_injection"
    assert _normalize_skill_name("exploit_ssrf") == "test_ssrf"
    assert _normalize_skill_name("attempt_auth") == "attempt_auth"


@pytest.mark.asyncio
async def test_run_skill_blocks_registered_skill_with_raw_egress(tmp_path) -> None:
    _reset_cache_for_tests()
    module_path = tmp_path / "bad_skill_module.py"
    module_path.write_text(
        "\n".join(
            [
                "import requests",
                "async def execute(target_url, **kwargs):",
                "    requests.get(target_url)",
                "    return {'vulnerable': False}",
            ]
        ),
        encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location("bad_skill_module", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    SKILL_REGISTRY["bad_raw_skill"] = {
        "fn": module.execute,
        "description": "bad raw egress skill",
        "args": "target_url",
    }
    try:
        result = await RunSkillTool().run(
            skill="bad_raw_skill",
            target_url="http://localhost:3000",
        )
    finally:
        SKILL_REGISTRY.pop("bad_raw_skill", None)

    assert result.ok is False
    assert result.error == "raw_egress"
    assert result.data["blocked"] is True
    assert result.data["egress"]["errors"]


@pytest.mark.asyncio
async def test_run_skill_does_not_mutate_caller_params(monkeypatch: pytest.MonkeyPatch) -> None:
    # The caller (scan loop) reuses its params dict across retries to compute the
    # stuck-loop cache key. Mutating it (params.pop('url')) changes the key on the
    # next call, silently bypassing the anti-loop guard.
    _reset_cache_for_tests()

    async def _fake_injection(*, url: str, **kwargs):
        return {"vulnerable": False, "findings": []}

    original = SKILL_REGISTRY["test_injection"]["fn"]
    monkeypatch.setitem(SKILL_REGISTRY["test_injection"], "fn", _fake_injection)
    try:
        params = {"url": "http://localhost:3000/search?q=", "round": 1}
        await RunSkillTool().run(
            skill="test_injection",
            target_url="http://localhost:3000",
            params=params,
        )
        assert params == {"url": "http://localhost:3000/search?q=", "round": 1}
    finally:
        monkeypatch.setitem(SKILL_REGISTRY["test_injection"], "fn", original)
