"""P2 Agents — Brain-directed dispatch of 63 autonomous agents."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P2_agents",
    name_en="63 Autonomous Agents — Brain-Directed Dispatch",
    name_ko="63개 자율 에이전트 — Brain 지휘 배치",
    stage="intelligence",
    parallel_group=3,
    depends_on=("P4_cpr",),
    objective_en=(
        "Brain selects which of the 63 specialized agents to launch against "
        "the recon inventory, what parameters each should use, and in what "
        "order. Brain interprets every result and decides whether to dig "
        "deeper, pivot, or move on."
    ),
    objective_ko=(
        "Brain이 63개 전문 에이전트 중 어떤 것을 정찰 인벤토리에 발사할지, "
        "각 에이전트가 어떤 파라미터를 쓸지, 어떤 순서로 실행할지 결정한다. "
        "Brain이 모든 결과를 해석하고 더 파고들지 / 피벗할지 / 진행할지 결정 "
        "한다."
    ),
    entry_conditions=("P4 endpoint inventory ready",),
    recommended_primitives=(
        "vxis_agent_dispatch",
        "vxis_agent_status",
        "vxis_brain_interpret",
        "vxis_finding_record",
    ),
    mandatory_primitives=("vxis_agent_dispatch", "vxis_brain_interpret"),
    dead_end_criteria=(
        DeadEndCriterion(
            id="agents_dispatched",
            description_en="At least one agent has produced output",
            description_ko="최소 1개 에이전트가 출력을 생성함",
            check=lambda ctx: len(getattr(ctx, "agent_results", []) or []) > 0,
        ),
        DeadEndCriterion(
            id="results_interpreted",
            description_en="Brain interpreted every agent result",
            description_ko="Brain이 모든 에이전트 결과를 해석함",
            check=lambda ctx: getattr(ctx, "uninterpreted_count", 1) == 0,
        ),
        DeadEndCriterion(
            id="no_pending_pivots",
            description_en="No deeper pivots queued by Brain",
            description_ko="Brain이 큐잉한 추가 피벗이 없음",
            check=lambda ctx: len(getattr(ctx, "pending_pivots", []) or []) == 0,
        ),
    ),
    success_criteria=(
        "Findings recorded with evidence",
        "All Brain-queued pivots processed",
    ),
    blocking_errors=("agent_runtime_crash", "brain_unreachable"),
    strategic_advice_en=(
        "Do NOT spray all 63 agents at once. Brain should pick the 5-10 most "
        "relevant for the discovered tech stack and CHAIN their findings."
    ),
    strategic_advice_ko=(
        "63개 에이전트를 한 번에 뿌리지 말 것. Brain은 발견된 기술 스택에 "
        "가장 관련 있는 5-10개를 골라 결과를 체이닝해야 한다."
    ),
    crown_hint_en="Each agent finding is a node — Brain links them into chains.",
    crown_hint_ko="각 에이전트 발견은 노드다 — Brain이 그것들을 체인으로 연결한다.",
    max_duration_minutes=90,
    next_phase_hint=("P5_special", "P7_hardware"),
)
