from __future__ import annotations

import pytest

from vxis.agent.egress_contract import describe_tool_target_egress
from vxis.agent.tools import build_default_registry
from vxis.agent.tools.security_skill_tools import (
    LoadSecuritySkillTool,
    SearchSecuritySkillsTool,
)


def _write_skill(base, slug: str, *, name: str, description: str, tags: list[str]) -> None:
    skill_dir = base / "skills" / slug
    skill_dir.mkdir(parents=True)
    (skill_dir / "references").mkdir()
    (skill_dir / "references" / "standards.md").write_text("MITRE and OWASP notes", encoding="utf-8")
    (skill_dir / "SKILL.md").write_text(
        "\n".join(
            [
                "---",
                f"name: {name}",
                f"description: {description}",
                "domain: cybersecurity",
                "subdomain: web-application-security",
                "tags:",
                *[f"  - {tag}" for tag in tags],
                "---",
                "",
                f"# {name}",
                "",
                "## Workflow",
                "Check CSP, HSTS, cookies, and browser security headers.",
            ]
        ),
        encoding="utf-8",
    )


@pytest.mark.asyncio
async def test_search_security_skills_finds_local_agentskills_repo(tmp_path, monkeypatch) -> None:
    _write_skill(
        tmp_path,
        "performing-security-headers-audit",
        name="performing-security-headers-audit",
        description="Audit HTTP security headers including CSP and HSTS.",
        tags=["security-headers", "csp", "hsts"],
    )
    _write_skill(
        tmp_path,
        "performing-dns-enumeration",
        name="performing-dns-enumeration",
        description="Enumerate DNS records and zone transfer exposure.",
        tags=["dns", "recon"],
    )
    monkeypatch.setenv("VXIS_SECURITY_SKILLS_DIR", str(tmp_path))

    result = await SearchSecuritySkillsTool().run(query="CSP HSTS headers", limit=3)

    assert result.ok is True
    assert result.data["matches"][0]["name"] == "performing-security-headers-audit"
    assert result.data["matches"][0]["score"] > 0
    assert "execute only through VXIS tools" in result.data["usage"]


@pytest.mark.asyncio
async def test_load_security_skill_returns_content_and_supporting_files(tmp_path, monkeypatch) -> None:
    _write_skill(
        tmp_path,
        "performing-security-headers-audit",
        name="performing-security-headers-audit",
        description="Audit HTTP security headers including CSP and HSTS.",
        tags=["security-headers", "csp", "hsts"],
    )
    monkeypatch.setenv("VXIS_SECURITY_SKILLS_DIR", str(tmp_path / "skills"))

    result = await LoadSecuritySkillTool().run(name="performing-security-headers-audit")

    assert result.ok is True
    assert result.data["slug"] == "performing-security-headers-audit"
    assert "## Workflow" in result.data["content"]
    assert "references/standards.md" in result.data["linked_files"]
    assert "Reference only" in result.data["safety"]


def test_default_registry_exposes_security_skill_bridge() -> None:
    names = build_default_registry().list_tools()

    assert "search_security_skills" in names
    assert "load_security_skill" in names
    assert describe_tool_target_egress("search_security_skills")["mode"] == "offline"
    assert describe_tool_target_egress("load_security_skill")["target_facing"] is False
