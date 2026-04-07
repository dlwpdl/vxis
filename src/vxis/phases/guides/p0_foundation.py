"""P0 Foundation — Ghost activation, scope load, session bootstrap.

This is the most safety-critical Phase. Brain MUST NOT touch the target until
Ghost is verified (exit IP differs from origin IP) and scope is loaded.
"""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P0_foundation",
    name_en="Foundation — Ghost, Scope, Session",
    name_ko="기반 — Ghost, 스코프, 세션",
    stage="init",
    parallel_group=0,
    depends_on=(),
    objective_en=(
        "Bring the engagement online safely: activate the Ghost anonymization "
        "layer, verify exit IP rotation, load engagement scope, create scan "
        "session, and initialize the evidence store. NO target traffic before "
        "Ghost verification succeeds."
    ),
    objective_ko=(
        "엔게이지먼트를 안전하게 시작한다: Ghost 익명화 계층 활성화, exit IP "
        "전환 확인, 스코프 로드, 스캔 세션 생성, 증거 저장소 초기화. Ghost "
        "검증 성공 전까지 타겟 트래픽 절대 금지."
    ),
    entry_conditions=(
        "Engagement config file exists",
        "Target URL provided",
        "Ghost credentials available",
    ),
    recommended_primitives=(
        "vxis_db_init",
        "vxis_evidence_init",
        "vxis_log_engagement_start",
    ),
    mandatory_primitives=(
        "vxis_ghost_activate",
        "vxis_ghost_verify",
        "vxis_scope_load",
        "vxis_session_create",
    ),
    dead_end_criteria=(
        DeadEndCriterion(
            id="ghost_verified",
            description_en="Ghost is active AND exit IP differs from origin IP",
            description_ko="Ghost 활성 상태이며 exit IP가 origin IP와 다름",
            check=lambda ctx: bool(getattr(ctx, "ghost_active", False))
            and getattr(ctx, "exit_ip", None) != getattr(ctx, "origin_ip", None),
        ),
        DeadEndCriterion(
            id="scope_loaded",
            description_en="Engagement scope rules loaded into session",
            description_ko="엔게이지먼트 스코프 규칙이 세션에 로드됨",
            check=lambda ctx: bool(getattr(ctx, "scope_rules", None)),
        ),
        DeadEndCriterion(
            id="session_ready",
            description_en="Scan session row created with unique scan_id",
            description_ko="고유 scan_id로 스캔 세션이 생성됨",
            check=lambda ctx: bool(getattr(ctx, "scan_id", None)),
        ),
    ),
    success_criteria=(
        "Ghost exit IP confirmed != origin IP",
        "scan_id created and persisted",
        "Scope rules cached and available to subsequent phases",
    ),
    blocking_errors=(
        "ghost_activation_failed",
        "exit_ip_equals_origin",
        "scope_file_missing",
        "db_init_failed",
    ),
    strategic_advice_en=(
        "NEVER contact the target before Ghost is verified. If Ghost fails, "
        "abort the entire engagement — do not fall back to direct connection. "
        "Treat exit_ip == origin_ip as a hard failure, not a warning."
    ),
    strategic_advice_ko=(
        "Ghost 검증 전에 절대 타겟에 접촉하지 말 것. Ghost 실패 시 전체 "
        "엔게이지먼트를 중단하고 직접 연결로 폴백하지 말 것. exit_ip == "
        "origin_ip는 경고가 아닌 hard failure로 처리한다."
    ),
    crown_hint_en=(
        "A clean foundation makes everything else possible — getting caught "
        "during recon kills the entire engagement before crown jewels exist."
    ),
    crown_hint_ko=(
        "깨끗한 기반이 모든 것을 가능하게 한다 — recon 단계에서 발각되면 "
        "크라운 주얼에 도달할 기회 자체가 사라진다."
    ),
    max_duration_minutes=10,
    next_phase_hint=("P1_director",),
)
