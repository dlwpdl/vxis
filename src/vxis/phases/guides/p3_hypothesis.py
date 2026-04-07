"""P3 Hypothesis Engine — pattern matching against historic findings."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P3_hypothesis",
    name_en="Hypothesis Engine — Pattern Matching",
    name_ko="가설 엔진 — 패턴 매칭",
    stage="intelligence",
    parallel_group=3,
    depends_on=("P4_cpr",),
    objective_en=(
        "Match recon results against the knowledge base of historic CVEs, "
        "VXIS prior findings, and OWASP/CWE patterns. Emit ranked hypotheses "
        "to seed P2 agent dispatch."
    ),
    objective_ko=(
        "정찰 결과를 과거 CVE, VXIS 이전 발견, OWASP/CWE 패턴 지식 베이스와 "
        "매칭한다. 순위가 매겨진 가설을 출력해 P2 에이전트 배치의 시드로 "
        "사용한다."
    ),
    entry_conditions=("P4 inventory ready",),
    recommended_primitives=(
        "vxis_kb_query",
        "vxis_pattern_match",
        "vxis_hypothesis_rank",
    ),
    dead_end_criteria=(
        DeadEndCriterion(
            id="kb_queried",
            description_en="Knowledge base queried for tech stack",
            description_ko="기술 스택 기준 KB 쿼리 완료",
            check=lambda ctx: getattr(ctx, "kb_queried", False),
        ),
        DeadEndCriterion(
            id="hypotheses_emitted",
            description_en="At least one hypothesis returned",
            description_ko="최소 1개 가설 반환됨",
            check=lambda ctx: len(getattr(ctx, "hypotheses", []) or []) > 0,
        ),
        DeadEndCriterion(
            id="ranked",
            description_en="Hypotheses scored and sorted",
            description_ko="가설이 점수화되고 정렬됨",
            check=lambda ctx: getattr(ctx, "hypotheses_sorted", False),
        ),
    ),
    success_criteria=("Ranked hypothesis list available to P2",),
    blocking_errors=("kb_unavailable",),
    strategic_advice_en=(
        "This phase is cheap — run it broadly. Better to give P2 too many "
        "hypotheses than to miss a high-value one."
    ),
    strategic_advice_ko=(
        "이 단계는 저비용이다 — 넓게 돌려라. 가치 높은 가설을 놓치는 것보다 "
        "P2에게 너무 많은 가설을 주는 것이 낫다."
    ),
    crown_hint_en="Historic patterns repeat — what worked elsewhere often works here.",
    crown_hint_ko="과거 패턴은 반복된다 — 다른 곳에서 통한 것이 여기서도 통하는 경우가 많다.",
    max_duration_minutes=15,
    next_phase_hint=("P2_agents",),
)
