"""P18 Collective Intelligence — share lessons across VXIS fleet."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P18_collective",
    name_en="Collective Intelligence Update",
    name_ko="집단 지능 업데이트",
    stage="learning",
    parallel_group=7,
    depends_on=("P11_mutation",),
    objective_en=(
        "Push novel TTPs and findings into the shared VXIS collective KB so "
        "every other VXIS instance benefits. The fleet learns together."
    ),
    objective_ko=(
        "참신한 TTP와 발견을 공유 VXIS 집단 KB에 푸시하여 다른 모든 VXIS "
        "인스턴스가 혜택을 받도록 한다. 플릿이 함께 학습한다."
    ),
    entry_conditions=("Findings & chains finalized",),
    recommended_primitives=(
        "vxis_collective_push",
        "vxis_collective_diff",
        "vxis_growth_log",
    ),
    dead_end_criteria=(
        DeadEndCriterion(
            id="diff_computed",
            description_en="Diff vs collective KB computed",
            description_ko="집단 KB 대비 diff 계산됨",
            check=lambda ctx: getattr(ctx, "collective_diff_done", False),
        ),
        DeadEndCriterion(
            id="novel_pushed",
            description_en="Novel items pushed to collective",
            description_ko="신규 항목이 집단에 푸시됨",
            check=lambda ctx: getattr(ctx, "collective_pushed", False),
        ),
        DeadEndCriterion(
            id="ack_received",
            description_en="Collective acknowledged the push",
            description_ko="집단이 푸시를 ACK함",
            check=lambda ctx: getattr(ctx, "collective_ack", False),
        ),
    ),
    success_criteria=("Push acknowledged",),
    blocking_errors=("collective_unreachable",),
    strategic_advice_en=(
        "Only push truly novel findings — don't pollute the collective with "
        "known patterns."
    ),
    strategic_advice_ko=(
        "정말 새로운 발견만 푸시하라 — 알려진 패턴으로 집단을 오염시키지 "
        "말 것."
    ),
    crown_hint_en="One VXIS finds, all VXIS benefit.",
    crown_hint_ko="한 VXIS가 발견하면 모든 VXIS가 혜택을 본다.",
    max_duration_minutes=10,
    next_phase_hint=("P6_report",),
)
