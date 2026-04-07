"""P5 Special Agents — IoT, VoIP, Web3 specialized exploitation."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P5_special",
    name_en="Special Agents (IoT / VoIP / Web3)",
    name_ko="특수 에이전트 (IoT / VoIP / Web3)",
    stage="exploitation",
    parallel_group=4,
    depends_on=("P2_agents",),
    objective_en=(
        "Run domain-specific exploitation agents (IoT firmware probing, VoIP "
        "SIP enumeration, Web3 contract auditing) when the recon stack "
        "indicates relevance. Brain decides applicability."
    ),
    objective_ko=(
        "정찰 스택이 관련성을 시사할 때 도메인별 익스플로잇 에이전트(IoT "
        "펌웨어 프로빙, VoIP SIP 열거, Web3 컨트랙트 감사)를 실행한다. "
        "Brain이 적용 가능성을 결정한다."
    ),
    entry_conditions=("P2 findings available",),
    recommended_primitives=(
        "vxis_special_iot",
        "vxis_special_voip",
        "vxis_special_web3",
    ),
    dead_end_criteria=(
        DeadEndCriterion(
            id="domain_decision",
            description_en="Brain decided which special agents (if any) apply",
            description_ko="Brain이 어떤 특수 에이전트가 적용되는지 결정함",
            check=lambda ctx: getattr(ctx, "special_decision_made", False),
        ),
        DeadEndCriterion(
            id="executed_or_skipped",
            description_en="Each applicable agent ran or was explicitly skipped",
            description_ko="적용 가능한 각 에이전트가 실행되거나 명시적으로 스킵됨",
            check=lambda ctx: getattr(ctx, "special_pending", 0) == 0,
        ),
        DeadEndCriterion(
            id="findings_recorded",
            description_en="Any findings written to evidence store",
            description_ko="발견 사항이 증거 저장소에 기록됨",
            check=lambda ctx: getattr(ctx, "special_findings_persisted", True),
        ),
    ),
    success_criteria=("Brain decision documented for each special domain",),
    blocking_errors=("special_agent_crash",),
    strategic_advice_en=(
        "If the target is a plain web app, skipping is the right call — "
        "document the skip reason in the graph for the report."
    ),
    strategic_advice_ko=(
        "타겟이 일반 웹앱이면 스킵이 정답이다 — 리포트를 위해 스킵 사유를 "
        "그래프에 기록하라."
    ),
    crown_hint_en="A single Web3 reentrancy bug can drain the whole treasury.",
    crown_hint_ko="단일 Web3 reentrancy 버그가 전체 트레저리를 비울 수 있다.",
    max_duration_minutes=45,
    next_phase_hint=("P8_synthesis",),
)
