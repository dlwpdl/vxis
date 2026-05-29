from __future__ import annotations

from vxis.agent.skill_audit import (
    audit_registered_skill,
    audit_registered_skills,
    audit_skill_file,
)
from vxis.agent.skills import SKILL_REGISTRY


def test_registered_skills_pass_static_egress_audit() -> None:
    audit = audit_registered_skills(SKILL_REGISTRY)

    assert audit["ok"] is True
    assert audit["errors"] == []
    assert {item["skill"] for item in audit["skills"]} == set(SKILL_REGISTRY)
    assert audit_registered_skill("test_injection", SKILL_REGISTRY)["mode"] == "ghost_transport"
    assert audit_registered_skill("test_infra", SKILL_REGISTRY)["mode"] == "ghost_transport"


def test_skill_egress_audit_rejects_raw_network_patterns(tmp_path) -> None:
    offender = tmp_path / "bad_skill.py"
    offender.write_text(
        "\n".join(
            [
                "import httpx",
                "import requests",
                "import socket",
                "import asyncio",
                "from urllib.request import urlopen",
                "async def execute(target_url):",
                "    await asyncio.create_subprocess_exec('curl', target_url)",
                "    requests.get(target_url)",
                "    httpx.get(target_url)",
                "    socket.gethostbyname('example.com')",
                "    urlopen(target_url)",
                "    return {}",
            ]
        ),
        encoding="utf-8",
    )

    issues = audit_skill_file(offender)
    codes = {issue.code for issue in issues}

    assert "raw_http_import" in codes
    assert "raw_socket_import" in codes
    assert "raw_urlopen_import" in codes
    assert "raw_subprocess_call" in codes
    assert "raw_http_call" in codes
    assert "raw_socket_call" in codes
    assert "raw_urlopen_call" in codes


def test_desktop_skill_subprocess_is_allowed_for_local_static_analysis() -> None:
    dylib_audit = audit_registered_skill("test_dylib_hijack", SKILL_REGISTRY)

    assert dylib_audit["mode"] == "offline_local_analysis"
    assert dylib_audit["ghost_coverage"] == "not_applicable"
    assert dylib_audit["errors"] == []
