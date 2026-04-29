"""run_skill 도구 description 위상 강등 테스트 (phase-3).

문제 (2026-04-20 Juice Shop 재스캔): Brain 이 shell_exec/python_exec 샌드박스
(sqlmap, nuclei, ffuf, nikto 즉시 사용 가능) 를 두고 `run_skill` 메타-디스패처
만 반복. 원인: RunSkillTool.description 이 15 skill 리스트를 "attack menu" 로
상단 전시해, Brain 에게 "이게 모든 공격 도구" 로 읽힘.

해결 방향: description 에 sandbox primacy 명시. run_skill 을 "convenience
wrapper for recurring patterns" 로 포지셔닝. 15-skill 리스트는 남기되, 맨
앞에서 "**First**, reach for shell_exec/python_exec when evidence points to
bespoke technique" 식으로 primacy 를 sandbox 로 넘긴다.

See: wiki/sources/incidents/2026_04_20_brain_prompt_prison.md
"""
from __future__ import annotations

from vxis.agent.tools.skill_runner import RunSkillTool


def test_description_acknowledges_sandbox_primacy() -> None:
    """description 은 shell_exec / python_exec 를 primary 로 명시해야.

    Brain 은 tool description 을 읽고 "어떤 tool 이 1순위인지" 학습한다.
    run_skill description 이 스스로를 primary 로 말하면 Brain 이 거기 고인다.
    """
    desc = RunSkillTool.description
    has_sandbox_ref = "shell_exec" in desc or "python_exec" in desc or "sandbox" in desc.lower()
    assert has_sandbox_ref, (
        "run_skill description lost sandbox reference. Brain will default to "
        "run_skill instead of exploring shell_exec/python_exec."
    )


def test_description_positions_as_convenience_not_primary() -> None:
    """description 첫 문장이 'pre-built attack skill' 로 시작하면 안 된다.

    이 어휘는 Brain 에게 '완제품 공격 도구' 로 각인. convenience wrapper 로
    reframe 필요: 'reusable attack template', 'shortcut', 'optional helper',
    또는 sandbox primacy 먼저 언급.
    """
    desc = RunSkillTool.description
    # 첫 200 chars 안에 sandbox 언급 또는 "convenience / shortcut / helper /
    # wrapper / optional" 어휘 중 하나는 있어야
    head = desc[:250].lower()
    primacy_signals = [
        "shell_exec", "python_exec", "sandbox",
        "convenience", "shortcut", "helper", "wrapper", "optional",
    ]
    hits = [s for s in primacy_signals if s in head]
    assert hits, (
        f"description head ({head!r}) doesn't signal run_skill's secondary "
        f"status. Include at least one of: {primacy_signals}"
    )


def test_description_does_not_claim_dozens_of_payloads_as_selling_point() -> None:
    """'dozens of payloads tested = one Brain decision' 식 배치는 run_skill 을
    batch 공격기로 포지셔닝한다 → Brain 이 '이걸로 한 방에' 라는 유혹.

    Brain-First 원칙: Brain 이 payload 도 결정한다. run_skill 은 자주 쓰이는
    패턴의 재사용이지, Brain 을 대체하는 배치 공격기가 아니다.
    """
    desc_lower = RunSkillTool.description.lower()
    forbidden_batch_framings = [
        "dozens of payloads tested = one brain decision",
        "one brain decision",
    ]
    for f in forbidden_batch_framings:
        assert f not in desc_lower, (
            f"batch-framing phrase {f!r} demotes Brain. run_skill is a "
            f"wrapper, not a substitute for Brain-driven payload choice."
        )


def test_description_retains_skill_name_list() -> None:
    """15 skill 이름은 남아야 Brain 이 재사용 가능한 wrapper 가 뭐가 있는지 안다.

    primacy 는 sandbox 로 넘기되, skill catalog 는 보존.
    """
    desc = RunSkillTool.description
    # 대표 5개만 검증 — 전체 15개 리스트 변화에 취약한 테스트는 피한다
    core_skills = [
        "enumerate_endpoints", "test_injection", "test_idor",
        "test_ssrf", "test_auth_deep",
    ]
    missing = [s for s in core_skills if s not in desc]
    assert not missing, f"skill catalog pruned too hard — missing: {missing}"


def test_description_size_bounded() -> None:
    """description 이 너무 길면 tool catalog 전체를 잠식. 2000 chars 이하.

    이전 크기 ~1500 chars. 재framing 후에도 크게 늘어나면 안 됨.
    """
    size = len(RunSkillTool.description)
    assert size < 2000, f"run_skill description is {size} chars — too long"
