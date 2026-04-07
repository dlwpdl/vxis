"""P1 Director — Attack graph initialization & strategy seeding."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P1_director",
    name_en="Director — Attack Graph Initialization",
    name_ko="디렉터 — 공격 그래프 초기화",
    stage="init",
    parallel_group=1,
    depends_on=("P0_foundation",),
    objective_en=(
        "Brain reads target context, decides high-level engagement strategy, "
        "creates the root node of the attack graph, and seeds initial "
        "hypotheses (likely tech stack, asset class, plausible crown jewels)."
    ),
    objective_ko=(
        "Brain이 타겟 컨텍스트를 읽고 상위 수준 전략을 결정한다. 공격 그래프의 "
        "루트 노드를 만들고 초기 가설(예상 기술 스택, 자산 클래스, 가능성 있는 "
        "크라운 주얼)을 시드한다."
    ),
    entry_conditions=("P0_foundation completed", "scan_id available"),
    recommended_primitives=(
        "vxis_graph_create_root",
        "vxis_brain_strategize",
        "vxis_hypothesis_seed",
    ),
    mandatory_primitives=("vxis_graph_create_root",),
    dead_end_criteria=(
        DeadEndCriterion(
            id="root_created",
            description_en="Attack graph root node persisted",
            description_ko="공격 그래프 루트 노드 저장됨",
            check=lambda ctx: bool(getattr(ctx, "graph_root_id", None)),
        ),
        DeadEndCriterion(
            id="strategy_decided",
            description_en="Brain emitted at least one strategic objective",
            description_ko="Brain이 최소 1개 이상의 전략 목표를 출력함",
            check=lambda ctx: bool(getattr(ctx, "strategy", None)),
        ),
        DeadEndCriterion(
            id="hypotheses_seeded",
            description_en="Initial hypothesis set non-empty",
            description_ko="초기 가설 집합이 비어있지 않음",
            check=lambda ctx: len(getattr(ctx, "hypotheses", []) or []) > 0,
        ),
    ),
    success_criteria=(
        "Attack graph root exists",
        "Strategy doc stored on session",
    ),
    blocking_errors=("brain_unreachable", "graph_db_failure"),
    strategic_advice_en=(
        "Spend Brain budget here on strategy, not detail. Detailed enumeration "
        "belongs in P4. Pick 2-3 plausible crown jewels and write them down."
    ),
    strategic_advice_ko=(
        "이 단계에서는 Brain 예산을 디테일이 아닌 전략에 쓴다. 상세 열거는 "
        "P4에서 한다. 가능성 있는 크라운 주얼 2-3개를 골라 기록한다."
    ),
    crown_hint_en="Naming the crown jewel early focuses every later Phase.",
    crown_hint_ko="크라운 주얼을 조기에 명명하면 이후 모든 Phase가 집중된다.",
    max_duration_minutes=10,
    next_phase_hint=("P4_cpr", "P13_biometrics", "P15_digital_twin"),
)
