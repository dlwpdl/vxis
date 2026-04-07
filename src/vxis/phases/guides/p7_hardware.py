"""P7 Hardware Agents — DMA, SS7, cold-boot etc."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P7_hardware",
    name_en="Hardware Agents (DMA / SS7 / Cold Boot)",
    name_ko="하드웨어 에이전트 (DMA / SS7 / 콜드부트)",
    stage="exploitation",
    parallel_group=4,
    depends_on=("P2_agents",),
    objective_en=(
        "Hardware-adjacent attack agents — DMA injection, SS7 signaling abuse, "
        "cold-boot memory extraction. Only run when engagement scope explicitly "
        "permits physical or telco vectors."
    ),
    objective_ko=(
        "하드웨어 인접 공격 에이전트 — DMA 인젝션, SS7 시그널링 악용, "
        "콜드부트 메모리 추출. 엔게이지먼트 스코프가 물리/통신 벡터를 명시적 "
        "으로 허용할 때만 실행."
    ),
    entry_conditions=("Scope allows physical/telco",),
    recommended_primitives=(
        "vxis_hw_dma",
        "vxis_hw_ss7",
        "vxis_hw_coldboot",
    ),
    dead_end_criteria=(
        DeadEndCriterion(
            id="scope_checked",
            description_en="Scope verified as permitting hardware vectors",
            description_ko="스코프가 하드웨어 벡터 허용으로 검증됨",
            check=lambda ctx: getattr(ctx, "hw_scope_ok", False),
        ),
        DeadEndCriterion(
            id="hw_executed_or_skipped",
            description_en="Each hardware agent ran or was explicitly skipped",
            description_ko="각 하드웨어 에이전트가 실행되거나 명시적으로 스킵됨",
            check=lambda ctx: getattr(ctx, "hw_pending", 0) == 0,
        ),
        DeadEndCriterion(
            id="hw_logged",
            description_en="Hardware findings logged or skip-reason recorded",
            description_ko="하드웨어 발견 사항 또는 스킵 사유가 기록됨",
            check=lambda ctx: getattr(ctx, "hw_logged", True),
        ),
    ),
    success_criteria=("Scope decision documented",),
    blocking_errors=("scope_violation_hardware",),
    strategic_advice_en=(
        "Default to skip unless scope explicitly allows. Hardware vectors are "
        "high-impact but high-legal-risk."
    ),
    strategic_advice_ko=(
        "스코프가 명시적으로 허용하지 않는 한 기본 스킵. 하드웨어 벡터는 "
        "고임팩트지만 법적 리스크도 높다."
    ),
    crown_hint_en="Hardware compromise often grants persistent root.",
    crown_hint_ko="하드웨어 침해는 종종 영구적 루트 권한을 제공한다.",
    max_duration_minutes=45,
    next_phase_hint=("P8_synthesis",),
)
