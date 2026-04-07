"""P12 Self-Evolution — coverage gap analysis & self-improvement."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P12_evolution",
    name_en="Self-Evolving Agent — Coverage Gap Analysis",
    name_ko="자가 진화 에이전트 — 커버리지 갭 분석",
    stage="learning",
    parallel_group=7,
    depends_on=("P11_mutation",),
    objective_en=(
        "Brain inspects what was tried vs what was possible, identifies "
        "coverage gaps, and writes them back to the knowledge base so the "
        "next engagement starts smarter. The growth-loop hook."
    ),
    objective_ko=(
        "Brain이 시도된 것 vs 가능했던 것을 검사하여 커버리지 갭을 식별하고 "
        "지식 베이스에 기록한다. 다음 엔게이지먼트가 더 똑똑하게 시작되도록 "
        "한다. 성장 루프 훅."
    ),
    entry_conditions=("P11 mutation chains stored",),
    recommended_primitives=(
        "vxis_coverage_analyze",
        "vxis_kb_write",
        "vxis_growth_log",
    ),
    dead_end_criteria=(
        DeadEndCriterion(
            id="gaps_listed",
            description_en="Coverage gap list emitted",
            description_ko="커버리지 갭 목록 출력됨",
            check=lambda ctx: len(getattr(ctx, "coverage_gaps", []) or []) > 0,
        ),
        DeadEndCriterion(
            id="kb_updated",
            description_en="Knowledge base updated with lessons",
            description_ko="지식 베이스가 학습 내용으로 업데이트됨",
            check=lambda ctx: getattr(ctx, "kb_updated", False),
        ),
        DeadEndCriterion(
            id="growth_logged",
            description_en="Growth-loop event recorded",
            description_ko="성장 루프 이벤트 기록됨",
            check=lambda ctx: getattr(ctx, "growth_logged", False),
        ),
    ),
    success_criteria=("Lessons committed to KB",),
    blocking_errors=("kb_write_failed",),
    strategic_advice_en=(
        "This phase is the entire reason VXIS gets smarter over time. Be "
        "ruthlessly honest about what failed and why."
    ),
    strategic_advice_ko=(
        "이 단계가 VXIS가 시간이 지남에 따라 똑똑해지는 이유 그 자체다. "
        "무엇이 왜 실패했는지에 대해 가차없이 정직하라."
    ),
    crown_hint_en="Today's gap is tomorrow's first move.",
    crown_hint_ko="오늘의 갭이 내일의 첫 수다.",
    max_duration_minutes=15,
    next_phase_hint=("P6_report",),
)
