from __future__ import annotations

from vxis.agent.skill_context import (
    recommend_skill_names,
    render_skill_context,
    select_skill_cards,
)


def test_select_skill_context_prioritizes_idor() -> None:
    cards = select_skill_cards(
        task="Validate IDOR on /api/users/{id} with low privilege session",
        role="exploit_worker",
        target_kind="web",
    )

    assert cards[0].name == "test_idor"
    assert "control" in cards[0].validation.lower()


def test_render_skill_context_contains_execution_and_validation() -> None:
    rendered = render_skill_context(
        task="JWT claim tampering and session role escalation",
        role="post_exploit_worker",
        target_kind="web",
    )

    assert "test_auth_deep" in rendered
    assert "validate:" in rendered
    assert "action:" in rendered
    assert "run_skill" in rendered


def test_explicit_skills_are_preserved_first() -> None:
    names = recommend_skill_names(
        task="Map routes before auth testing",
        role="recon_worker",
        explicit_skills=["test_sensitive_files"],
        target_kind="web",
    )

    assert names[0] == "test_sensitive_files"
    assert "enumerate_endpoints" in names


def test_desktop_target_filters_web_skills() -> None:
    names = recommend_skill_names(
        task="macOS Electron app with dangerous entitlement and local storage secrets",
        role="exploit_worker",
        target_kind="desktop",
    )

    assert "test_injection" not in names
    assert any(name.startswith("test_") for name in names)
    assert "test_local_storage_secrets" in names or "test_entitlement_audit" in names
