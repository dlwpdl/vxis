from __future__ import annotations

import json

from vxis.agent.skill_context import render_skill_context
from vxis.skillopt_bridge import (
    build_train_command,
    export_searchqa_split,
    import_optimized_skill,
    list_optimized_skills,
    render_optimized_skill_context,
    set_optimized_skill_active,
)


def test_export_searchqa_split_from_jsonl(tmp_path):
    cases = tmp_path / "cases.jsonl"
    rows = [
        {
            "id": f"c{i}",
            "target": "https://app.example.test",
            "evidence": {"hint": "two identities exist"},
            "trajectory": "attempt_auth succeeded; post_auth_enum found object ids",
            "expected_action": "run_skill test_idor",
            "task_type": "axis2_authz",
        }
        for i in range(5)
    ]
    cases.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")

    result = export_searchqa_split(cases, tmp_path / "out", seed=7)

    assert result.total == 5
    assert result.train >= 1
    train_items = json.loads((tmp_path / "out" / "train" / "items.json").read_text())
    assert {"id", "question", "context", "answers", "task_type"} <= set(train_items[0])
    assert train_items[0]["answers"]
    assert (tmp_path / "out" / "vxis_searchqa_config.yaml").exists()
    assert (tmp_path / "out" / "vxis_seed_skill.md").exists()


def test_imported_skillopt_guidance_renders_for_matching_task(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_SKILLOPT_HOME", str(tmp_path))
    skill = tmp_path / "best_skill.md"
    skill.write_text(
        "# Learned Axis-2 Rule\n\nAlways enumerate owned objects before BOLA.", encoding="utf-8"
    )

    entry = import_optimized_skill(
        skill,
        name="axis2",
        surface="web",
        families=["access_control"],
        roles=["director"],
        triggers=["bola", "authorization"],
    )

    assert entry.name == "axis2"
    assert [item.name for item in list_optimized_skills()] == ["axis2"]
    rendered = render_optimized_skill_context(
        task="authorization BOLA test",
        role="director",
        target_kind="web",
    )
    assert "Optimized SkillOpt guidance" in rendered
    assert "Always enumerate owned objects" in rendered

    disabled = set_optimized_skill_active("axis2", False)
    assert disabled.active is False
    assert (
        render_optimized_skill_context(
            task="authorization BOLA test",
            role="director",
            target_kind="web",
        )
        == ""
    )


def test_render_skill_context_appends_imported_skillopt_guidance(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_SKILLOPT_HOME", str(tmp_path))
    skill = tmp_path / "best_skill.md"
    skill.write_text(
        "# Learned Chain Rule\n\nPrefer execute_chain after post-auth token.", encoding="utf-8"
    )
    import_optimized_skill(
        skill,
        name="chain",
        surface="web",
        families=["chain"],
        roles=["post_exploit_worker"],
        triggers=["chain"],
    )

    rendered = render_skill_context(
        task="post-auth chain to crown jewel",
        role="post_exploit_worker",
        target_kind="web",
        max_chars=4000,
    )

    assert "execute_chain" in rendered
    assert "Optimized SkillOpt guidance" in rendered
    assert "Prefer execute_chain" in rendered


def test_seed_baseline_injected_when_no_optimized_skills(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_SKILLOPT_HOME", str(tmp_path))  # empty home → nothing imported
    monkeypatch.delenv("VXIS_SKILLOPT_ENABLED", raising=False)
    assert list_optimized_skills() == []
    rendered = render_optimized_skill_context(
        task="ssrf cloud impact", role="director", target_kind="web"
    )
    assert rendered  # non-empty baseline is always present
    assert "Baseline SkillOpt strategy" in rendered
    assert "proof gap" in rendered  # built-in seed body content


def test_optimized_skill_takes_precedence_over_seed_baseline(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_SKILLOPT_HOME", str(tmp_path))
    skill = tmp_path / "best_skill.md"
    skill.write_text(
        "# Learned Rule\n\nAlways enumerate owned objects before BOLA.", encoding="utf-8"
    )
    import_optimized_skill(
        skill,
        name="axis2",
        surface="web",
        families=["access_control"],
        roles=["director"],
        triggers=["bola"],
    )
    rendered = render_optimized_skill_context(
        task="authorization BOLA test", role="director", target_kind="web"
    )
    assert "Optimized SkillOpt guidance" in rendered
    assert "Always enumerate owned objects" in rendered
    assert "Baseline SkillOpt strategy" not in rendered  # seed suppressed once a skill exists


def test_seed_baseline_respects_disabled_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_SKILLOPT_HOME", str(tmp_path))  # empty home
    monkeypatch.setenv("VXIS_SKILLOPT_ENABLED", "0")
    assert render_optimized_skill_context(task="anything", role="director", target_kind="web") == ""


def test_build_train_command_defaults_to_named_split_and_run_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("VXIS_SKILLOPT_HOME", str(tmp_path))

    command = build_train_command("axis2", epochs=2, workers=4)

    assert command[:3] == ["python", "scripts/train.py", "--config"]
    assert str(tmp_path / "splits" / "axis2" / "vxis_searchqa_config.yaml") in command
    assert "train.num_epochs=2" in command
    assert "env.workers=4" in command
    assert f"env.out_root={tmp_path / 'runs' / 'axis2'}" in command
