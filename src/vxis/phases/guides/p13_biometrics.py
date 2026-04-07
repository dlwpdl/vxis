"""P13 Behavioral Biometrics — OSINT on humans behind the target."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P13_biometrics",
    name_en="Behavioral Biometrics (OSINT)",
    name_ko="행위 생체인식 (OSINT)",
    stage="recon",
    parallel_group=2,
    depends_on=("P1_director",),
    objective_en=(
        "Profile human operators tied to the target via passive OSINT: "
        "developer GitHub commits, LinkedIn employees, leaked credentials, "
        "writing styles, working hours. Used later to seed phishing and "
        "credential-spray hypotheses."
    ),
    objective_ko=(
        "수동적 OSINT로 타겟과 연결된 인간 운영자를 프로파일링한다: 개발자 "
        "GitHub 커밋, LinkedIn 임직원, 유출 자격증명, 글쓰기 스타일, 근무 "
        "시간대. 이후 피싱과 자격증명 스프레이 가설의 시드로 사용된다."
    ),
    entry_conditions=("Target organization identified",),
    recommended_primitives=(
        "vxis_osint_github",
        "vxis_osint_linkedin",
        "vxis_breach_lookup",
        "vxis_whois",
    ),
    dead_end_criteria=(
        DeadEndCriterion(
            id="people_found",
            description_en="At least one named operator profiled",
            description_ko="최소 1명의 운영자가 프로파일됨",
            check=lambda ctx: len(getattr(ctx, "people", []) or []) > 0,
        ),
        DeadEndCriterion(
            id="osint_sources_exhausted",
            description_en="All configured OSINT sources queried",
            description_ko="설정된 모든 OSINT 소스 쿼리 완료",
            check=lambda ctx: getattr(ctx, "osint_sources_remaining", 0) == 0,
        ),
        DeadEndCriterion(
            id="breach_corpus_checked",
            description_en="Breach corpus searched for target domain",
            description_ko="유출 코퍼스에서 타겟 도메인 검색 완료",
            check=lambda ctx: getattr(ctx, "breach_checked", False),
        ),
    ),
    success_criteria=(
        "People list non-empty",
        "Breach lookup completed",
    ),
    blocking_errors=("osint_api_quota_exceeded",),
    strategic_advice_en=(
        "Stay strictly passive — no probing, no contact. The value here is "
        "feeding P2 with realistic credential and persona seeds."
    ),
    strategic_advice_ko=(
        "철저히 수동적으로 — 프로빙·접촉 금지. 가치는 P2에게 현실적인 "
        "자격증명/페르소나 시드를 공급하는 데 있다."
    ),
    crown_hint_en="A single leaked dev credential often beats any zero-day.",
    crown_hint_ko="유출된 개발자 자격증명 1개가 종종 어떤 제로데이보다 강력하다.",
    max_duration_minutes=30,
    next_phase_hint=("P2_agents",),
)
