"""P8 Cross-Protocol Synthesis — chaining findings into kill chains."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P8_synthesis",
    name_en="Cross-Protocol Synthesis",
    name_ko="크로스 프로토콜 합성",
    stage="chain",
    parallel_group=5,
    depends_on=("P5_special", "P7_hardware"),
    objective_en=(
        "THE chaining phase. Brain reads every finding from P2/P5/P7 and "
        "synthesizes them into multi-step attack chains that reach the crown "
        "jewel. A leaked S3 key + admin subdomain + weak auth = full takeover. "
        "Chains, not isolated findings, are what win engagements."
    ),
    objective_ko=(
        "체이닝 핵심 단계. Brain이 P2/P5/P7의 모든 발견을 읽고 크라운 주얼에 "
        "도달하는 다단계 공격 체인으로 합성한다. 유출된 S3 키 + admin 서브도메인 "
        "+ 약한 인증 = 완전 장악. 고립된 발견이 아닌 체인이 엔게이지먼트를 "
        "승리로 이끈다."
    ),
    entry_conditions=("P5 and P7 complete",),
    recommended_primitives=(
        "vxis_brain_synthesize",
        "vxis_chain_score",
        "vxis_chain_persist",
        "vxis_graph_link",
    ),
    mandatory_primitives=("vxis_brain_synthesize",),
    dead_end_criteria=(
        DeadEndCriterion(
            id="all_findings_considered",
            description_en="Every recorded finding evaluated for chain candidacy",
            description_ko="기록된 모든 발견이 체인 후보로 평가됨",
            check=lambda ctx: getattr(ctx, "unchained_findings", 1) == 0,
        ),
        DeadEndCriterion(
            id="chains_emitted",
            description_en="At least one multi-step chain produced",
            description_ko="최소 1개 다단계 체인 생성됨",
            check=lambda ctx: any(
                len(c) >= 2 for c in (getattr(ctx, "chains", []) or [])
            ),
        ),
        DeadEndCriterion(
            id="crown_path_attempted",
            description_en="Brain attempted at least one crown-jewel reach",
            description_ko="Brain이 크라운 주얼 도달을 최소 1회 시도함",
            check=lambda ctx: getattr(ctx, "crown_attempted", False),
        ),
    ),
    success_criteria=(
        "Chains stored in graph DB",
        "Crown reach status recorded",
    ),
    blocking_errors=("brain_unreachable", "graph_db_failure"),
    strategic_advice_en=(
        "A finding alone is worth 1 point — a 4-step chain reaching the crown "
        "is worth 100. Spend Brain budget here. Look for chains that traverse "
        "auth boundaries (anonymous -> user -> admin -> root)."
    ),
    strategic_advice_ko=(
        "단일 발견은 1점이지만 크라운에 도달하는 4단계 체인은 100점이다. "
        "Brain 예산을 이곳에 써라. 인증 경계(익명 → 사용자 → 관리자 → 루트)를 "
        "넘는 체인을 찾아라."
    ),
    crown_hint_en=(
        "Individual findings rarely reach the crown — chains do. The art of "
        "VXIS is here."
    ),
    crown_hint_ko=(
        "개별 발견은 크라운에 도달하기 어렵다 — 체인이 도달한다. VXIS의 "
        "기예가 여기 있다."
    ),
    max_duration_minutes=45,
    next_phase_hint=("P11_mutation",),
)
