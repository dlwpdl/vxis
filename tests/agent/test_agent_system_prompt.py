"""AGENT_SYSTEM_PROMPT Brain-First 불변성 테스트.

이전 AGENT_SYSTEM_PROMPT 는 Brain 을 "OWASP 10+ 체크박스 checker" 로 만들었다:
- MANDATORY Module Usage / MANDATORY Attack Vector Coverage 섹션
- `[ ]` 체크박스 50+ 개 (A01-A10 전부 나열)
- 6-phase 킬체인 이 각 phase 마다 "— REQUIRED" 마커
- "Skipping any module is a failure" 절대주의

결과: Brain 이 evidence 무시하고 체크리스트 순회. 진짜 해커처럼 증거 따라가는
유기적 사고가 억제됨. 이 테스트로 재발 방지.

See: wiki/sources/incidents/2026_04_20_brain_prompt_prison.md
"""
from __future__ import annotations

import re

from vxis.agent.brain import AGENT_SYSTEM_PROMPT


def test_no_mandatory_checklist_sections() -> None:
    """'MANDATORY Module Usage', 'MANDATORY Attack Vector Coverage' 같은
    절대주의 체크리스트 섹션 헤더 금지."""
    forbidden_headers = [
        "MANDATORY Module Usage",
        "MANDATORY Attack Vector Coverage",
    ]
    for h in forbidden_headers:
        assert h not in AGENT_SYSTEM_PROMPT, (
            f"section header {h!r} forces Brain into dispatcher mode. "
            f"Replace with evidence-driven framing."
        )


def test_no_literal_checkboxes() -> None:
    """`- [ ]` 체크박스 토큰 금지 — Brain 이 'fill in the boxes' 모드로 들어감."""
    checkbox_count = AGENT_SYSTEM_PROMPT.count("- [ ]")
    assert checkbox_count == 0, (
        f"{checkbox_count} literal checkboxes remain. "
        f"Brain reads these as a todo list to traverse, not as context."
    )


def test_no_required_phase_markers() -> None:
    """'### Phase N: … — REQUIRED' 패턴 금지. 킬체인 순서는 evidence 가 정한다."""
    required_phases = re.findall(
        r"###\s+Phase\s+\d+:.*?—\s*REQUIRED", AGENT_SYSTEM_PROMPT
    )
    assert not required_phases, (
        f"REQUIRED phase markers found: {required_phases}. "
        f"Remove order enforcement — Brain sequences by evidence."
    )


def test_no_skipping_is_failure_absolutism() -> None:
    """'Skipping any … is a failure' 금지 — Brain 이 실패 회피 위해
    evidence 약한 vector 도 억지로 찌르는 부작용."""
    forbidden_phrases = [
        "Skipping any module is a failure",
        "Skipping any category is a failure",
    ]
    for p in forbidden_phrases:
        assert p not in AGENT_SYSTEM_PROMPT, f"absolutist phrase found: {p!r}"


def test_has_evidence_language() -> None:
    """evidence / hypothesis / 증거 어휘 보존 — 자유 탐색 유도."""
    lowered = AGENT_SYSTEM_PROMPT.lower()
    has_evidence = "evidence" in lowered or "증거" in lowered
    has_hypothesis = "hypothesis" in lowered or "가설" in lowered or "chain" in lowered
    assert has_evidence, "prompt lost evidence-driven language"
    assert has_hypothesis, "prompt lost hypothesis/chain language"


def test_still_references_owasp_universe() -> None:
    """OWASP 10 카테고리 breadth 는 유지 — 단 'checklist' 아니라 'universe' 로.

    Brain 이 어떤 공격 surface 가 존재하는지 알아야 evidence 따라 적절한 tool 을
    고른다. 단 traversal order 를 강제하지 않는다.
    """
    assert "OWASP" in AGENT_SYSTEM_PROMPT
    # A01-A10 중 최소 5개는 언급돼야 breadth 가 산다
    owasp_mentions = sum(
        1 for i in range(1, 11) if f"A{i:02d}" in AGENT_SYSTEM_PROMPT or f"A0{i}" in AGENT_SYSTEM_PROMPT
    )
    assert owasp_mentions >= 5, f"only {owasp_mentions} OWASP categories mentioned"


def test_has_cisa_kev_intel() -> None:
    """CISA KEV 같은 active threat intel 는 유용한 context. 보존."""
    assert "CISA KEV" in AGENT_SYSTEM_PROMPT or "CVE-" in AGENT_SYSTEM_PROMPT


def test_has_dual_use_and_anti_bias() -> None:
    """Dual-Use 원칙과 Anti-Confirmation-Bias 는 유기적 사고 유도 → 보존."""
    assert "Dual-Use" in AGENT_SYSTEM_PROMPT or "dual-use" in AGENT_SYSTEM_PROMPT.lower()
    assert (
        "Anti-Confirmation" in AGENT_SYSTEM_PROMPT
        or "confirmation bias" in AGENT_SYSTEM_PROMPT.lower()
    )


def test_available_tools_placeholder_intact() -> None:
    """brain.py 가 `.format(available_tools=...)` 로 치환 — 이 placeholder 필수."""
    assert "{available_tools}" in AGENT_SYSTEM_PROMPT


def test_prompt_size_reasonable() -> None:
    """프롬프트가 너무 크면 Brain context budget 잠식. 4500 char 이하 목표.

    이전 크기 ~6500 char. 압축 목표: 체크리스트 뜯어내고 mindset 만 남기면
    ~3000-4500 char 가능. Outcome-based DONE 조건 포함 후 목표.
    """
    size = len(AGENT_SYSTEM_PROMPT)
    assert size < 4500, (
        f"AGENT_SYSTEM_PROMPT is {size} chars — too long. "
        f"Each scan iteration this goes into context. Compress to < 4500."
    )


def test_has_outcome_based_done_condition() -> None:
    """끝까지 소진 → admin/crown jewel ethos 는 VXIS 핵심 목표.

    mechanical checklist ([ ] 박스 traversal) 은 제거하되, outcome-based
    완료 조건은 보존해야 Brain 이 조기 종료 안 함. admin / crown jewel /
    exhausted 중 최소 하나 어휘가 DONE 조건 맥락에 등장해야.
    """
    lowered = AGENT_SYSTEM_PROMPT.lower()
    outcome_tokens = ["crown jewel", "admin takeover", "admin 권한", "exhausted", "소진"]
    hits = [t for t in outcome_tokens if t in lowered]
    assert hits, (
        f"no outcome-based DONE vocabulary found. Brain will finish_scan "
        f"early without persistence ethos. Required one of: {outcome_tokens}"
    )


def test_has_persistence_ethos() -> None:
    """Bug bounty / 100+ iterations / persistence 맥락 — 조기 종료 억제용.

    사용자 핵심 피드백: '끝까지 가서 모든 공격 포인트 다 소진해서 어드민 권한'.
    Brain 이 '대충 3-4번 시도했고 안 된다' 로 종료하지 않도록 persistence
    vocabulary 가 프롬프트에 박혀 있어야.
    """
    lowered = AGENT_SYSTEM_PROMPT.lower()
    persistence_tokens = ["100+", "persistence", "끝까지", "bug bounty", "pivot"]
    hits = [t for t in persistence_tokens if t in lowered]
    assert len(hits) >= 2, (
        f"only {len(hits)} persistence tokens found: {hits}. "
        f"Brain needs explicit anti-early-termination language."
    )


def test_has_boundary_confusion_hint_without_checklist() -> None:
    """Technique breadth is a hint, not a forced traversal list."""
    lowered = AGENT_SYSTEM_PROMPT.lower()
    assert "token-boundary" in lowered
    assert "websocket" in lowered
    assert "change auth" in lowered or "data, or execution impact" in lowered


def test_no_mechanical_checklist_but_has_absolutism() -> None:
    """핵심 재정합: (HOW 자유) + (WHAT 절대) 이중축 검증.

    mechanical `[ ]` 체크박스는 금지 (HOW 경직) 하되, outcome-based 'ONE of
    these' / 'ALL credible' 같은 절대 조건은 있어야 (WHAT 절대).
    """
    # HOW 자유: `- [ ]` 없어야
    assert "- [ ]" not in AGENT_SYSTEM_PROMPT
    # WHAT 절대: outcome 절대 조건 문구 존재
    has_absolutism_framing = (
        "ONE of these" in AGENT_SYSTEM_PROMPT
        or "all credible" in AGENT_SYSTEM_PROMPT.lower()
        or "모든 credible" in AGENT_SYSTEM_PROMPT
    )
    assert has_absolutism_framing, (
        "outcome-based absolutism lost. Need 'ONE of these is true' or "
        "'all credible surfaces exhausted' style framing to prevent Brain "
        "from early finish_scan."
    )
