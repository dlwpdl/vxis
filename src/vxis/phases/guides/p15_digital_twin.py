"""P15 Digital Twin — Pre-simulate attacks against a model of the target."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P15_digital_twin",
    name_en="Digital Twin Pre-Simulation",
    name_ko="디지털 트윈 사전 시뮬레이션",
    stage="recon",
    parallel_group=2,
    depends_on=("P1_director",),
    objective_en=(
        "Build a lightweight in-memory model of the target (tech stack, "
        "auth flow, data model) and simulate plausible attack chains BEFORE "
        "touching production. Validates Brain hypotheses cheaply."
    ),
    objective_ko=(
        "타겟의 경량 메모리 모델(기술 스택, 인증 플로우, 데이터 모델)을 "
        "구성하고 프로덕션에 접촉하기 전에 가능성 있는 공격 체인을 시뮬레이션 "
        "한다. Brain 가설을 저비용으로 검증한다."
    ),
    entry_conditions=("P1 strategy available",),
    recommended_primitives=(
        "vxis_twin_build",
        "vxis_twin_simulate",
        "vxis_twin_score_chain",
    ),
    dead_end_criteria=(
        DeadEndCriterion(
            id="twin_built",
            description_en="In-memory twin object instantiated",
            description_ko="메모리 트윈 객체가 생성됨",
            check=lambda ctx: bool(getattr(ctx, "twin", None)),
        ),
        DeadEndCriterion(
            id="chains_simulated",
            description_en="At least one chain simulated",
            description_ko="최소 1개 체인 시뮬레이션 완료",
            check=lambda ctx: len(getattr(ctx, "simulated_chains", []) or []) > 0,
        ),
        DeadEndCriterion(
            id="hypotheses_ranked",
            description_en="Hypotheses ranked by simulated success rate",
            description_ko="시뮬레이션 성공률 기준 가설 순위 매김",
            check=lambda ctx: getattr(ctx, "ranked", False),
        ),
    ),
    success_criteria=(
        "Twin model built",
        "Top-N hypotheses ranked",
    ),
    blocking_errors=("twin_build_failed",),
    strategic_advice_en=(
        "Use the twin to throw away expensive low-probability chains BEFORE "
        "burning real requests against the target. Cheaper to fail in sim."
    ),
    strategic_advice_ko=(
        "타겟에 실제 요청을 낭비하기 전에 트윈으로 비싼 저확률 체인을 "
        "버려라. 시뮬레이션에서 실패하는 것이 훨씬 싸다."
    ),
    crown_hint_en="Sim-validated chains hit production with much higher success rates.",
    crown_hint_ko="시뮬레이션 검증된 체인은 프로덕션에서 훨씬 높은 성공률을 보인다.",
    max_duration_minutes=20,
    next_phase_hint=("P2_agents",),
)
