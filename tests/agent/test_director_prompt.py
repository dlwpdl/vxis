"""Brain-First 프롬프트 불변성 테스트.

DIRECTOR_PROMPT_TEMPLATE 는 Brain 을 "체크리스트 dispatcher" 로 만들면 안 된다.
(1) 8-step MANDATORY PRIORITY ORDER 금지 — evidence-driven 이어야
(2) cargo-cult 예시값 (`/api/Users/2`, `' OR 1=1--`, 구체 sqlmap 커맨드) 금지
(3) Brain 을 "weaker model" 감독 role 로 framing 금지
(4) shell_exec/python_exec 를 primary tool 로 surface
(5) hypothesis/evidence 어휘 포함 (자유 사고 유도)

이 테스트가 박제된 이유: 2026-04-20 Juice Shop 재스캔에서 Brain 이 `run_skill`
만 반복하고 shell_exec 샌드박스를 거의 사용 안 함. 원인은 DIRECTOR_PROMPT 가
Brain 에게 8단 우선순위 리스트 + cargo-cult 예시를 밀어넣어 자유 탐색 공간을
제거한 것. 이 패턴이 재발하지 않도록 프롬프트 invariant 로 고정.

See: wiki/sources/incidents/2026_04_20_brain_prompt_prison.md
"""
from __future__ import annotations

import re

from vxis.agent.scan_loop import DIRECTOR_PROMPT_TEMPLATE


def test_no_mandatory_priority_order() -> None:
    """8단 if-then 플로우차트 금지. Brain 은 evidence 로 결정한다."""
    assert "MANDATORY PRIORITY ORDER" not in DIRECTOR_PROMPT_TEMPLATE
    # if-then 1→N 넘버링 패턴도 금지
    numbered = re.findall(r"^\s*\d+\.\s+If\s+\"", DIRECTOR_PROMPT_TEMPLATE, flags=re.MULTILINE)
    assert len(numbered) == 0, f"if-then numbered list smells like a checklist: {numbered}"


def test_no_hardcoded_target_payloads() -> None:
    """구체 엔드포인트·페이로드 값은 cargo-cult 을 만든다. 구조적 hint 만 허용."""
    forbidden = [
        "/api/Users/2",
        "' OR 1=1--",
        "sqlmap -u 'http://TARGET",
        "nuclei -u http://TARGET",
        "?q=1",
    ]
    for pattern in forbidden:
        assert pattern not in DIRECTOR_PROMPT_TEMPLATE, (
            f"cargo-cult pattern {pattern!r} in DIRECTOR_PROMPT — Brain 은 이 값을 "
            f"실제 타겟에 그대로 복사 붙여넣는다. 구조만 남기고 구체값 제거."
        )


def test_not_weaker_model_framing() -> None:
    """Brain 을 'stuck repeating weaker executor 감독' 으로 캐스팅하지 말 것.

    이렇게 framing 하면 Brain 이 실제로 dispatcher 역할만 한다 (role priming).
    대신 "senior pentester" 같은 행위자 role 을 준다.
    """
    assert "weaker model" not in DIRECTOR_PROMPT_TEMPLATE
    assert "stuck repeating" not in DIRECTOR_PROMPT_TEMPLATE


def test_has_evidence_driven_language() -> None:
    """자유 탐색 어휘 포함 — Brain 이 hypothesis·evidence 기반으로 사고하도록."""
    lowered = DIRECTOR_PROMPT_TEMPLATE.lower()
    assert "evidence" in lowered or "증거" in lowered
    assert "hypothesis" in lowered or "가설" in lowered


def test_sandbox_tools_primary() -> None:
    """shell_exec / python_exec 가 primary tool 로 제시돼야 한다.

    오늘 (2026-04-20) scan 에서 Brain 이 sqlmap·nuclei 샌드박스 두고 run_skill 만
    돌린 이유는 이들이 프롬프트에서 뒤로 밀려나있기 때문. primary 로 올린다.
    """
    assert "shell_exec" in DIRECTOR_PROMPT_TEMPLATE
    assert "python_exec" in DIRECTOR_PROMPT_TEMPLATE


def test_format_placeholders_intact() -> None:
    """format() 깨지면 scan_loop 이 런타임에 KeyError. 필수 placeholder 보존."""
    required = ["{target}", "{iteration}", "{max_iters}", "{finding_count}",
                "{vector_status}", "{recent_actions}", "{findings_list}"]
    for ph in required:
        assert ph in DIRECTOR_PROMPT_TEMPLATE, f"missing format placeholder {ph}"
