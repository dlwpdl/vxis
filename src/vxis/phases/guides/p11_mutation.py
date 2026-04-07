"""P11 Chain Mutation — generate alternative attack paths."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P11_mutation",
    name_en="Chain Mutation — Alternative Attack Paths",
    name_ko="체인 변이 — 대체 공격 경로",
    stage="chain",
    parallel_group=6,
    depends_on=("P8_synthesis",),
    objective_en=(
        "Mutate the synthesized chains to find resilient alternatives: swap "
        "vulns, replace persistence steps, find chains the blue team would "
        "miss. Strengthens the report with breadth, not just depth."
    ),
    objective_ko=(
        "합성된 체인을 변이시켜 견고한 대체 경로를 찾는다: 취약점 교체, "
        "지속성 단계 변경, 블루팀이 놓칠 체인 발굴. 깊이뿐 아니라 폭으로 "
        "리포트를 강화한다."
    ),
    entry_conditions=("P8 chains exist",),
    recommended_primitives=(
        "vxis_chain_mutate",
        "vxis_chain_score",
        "vxis_chain_dedupe",
    ),
    dead_end_criteria=(
        DeadEndCriterion(
            id="mutations_run",
            description_en="At least one mutation pass executed",
            description_ko="최소 1회 변이 패스 실행됨",
            check=lambda ctx: getattr(ctx, "mutation_passes", 0) > 0,
        ),
        DeadEndCriterion(
            id="alternatives_emitted",
            description_en="At least one alternative chain produced",
            description_ko="최소 1개 대체 체인 생성됨",
            check=lambda ctx: len(getattr(ctx, "alternative_chains", []) or []) > 0,
        ),
        DeadEndCriterion(
            id="dedupe_done",
            description_en="Duplicate chains pruned",
            description_ko="중복 체인 제거됨",
            check=lambda ctx: getattr(ctx, "dedupe_done", False),
        ),
    ),
    success_criteria=("Alternative chains stored",),
    blocking_errors=(),
    strategic_advice_en=(
        "Aim for 2-3 viable alternative chains per primary chain. Defenders "
        "patch one — alternatives prove the systemic weakness."
    ),
    strategic_advice_ko=(
        "기본 체인당 2-3개의 실현 가능한 대체 체인을 목표로 한다. 방어자가 "
        "하나를 패치하면 대체 체인이 시스템적 약점을 입증한다."
    ),
    crown_hint_en="Multiple chains to crown = systemic issue, not bug.",
    crown_hint_ko="크라운으로 가는 다수의 체인 = 버그가 아닌 시스템적 문제.",
    max_duration_minutes=20,
    next_phase_hint=("P12_evolution", "P18_collective"),
)
