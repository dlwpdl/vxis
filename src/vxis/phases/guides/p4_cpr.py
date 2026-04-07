"""P4 CPR — Crawl, Probe, Recon to dead-end."""

from __future__ import annotations

from vxis.phases.base import DeadEndCriterion, PhaseGuide

PHASE_GUIDE = PhaseGuide(
    id="P4_cpr",
    name_en="CPR — Crawl, Probe, Recon",
    name_ko="CPR — 크롤링, 프로빙, 정찰",
    stage="recon",
    parallel_group=2,
    depends_on=("P1_director",),
    objective_en=(
        "Map the entire attack surface to DEAD END: every reachable URL, every "
        "form, every parameter, every JS bundle, every subdomain, every header. "
        "Brain decides what to crawl next based on what was just discovered. "
        "Continue until no new endpoints surface across multiple iterations."
    ),
    objective_ko=(
        "공격 표면을 DEAD END까지 매핑: 도달 가능한 모든 URL, 폼, 파라미터, JS "
        "번들, 서브도메인, 헤더. Brain이 방금 발견한 것을 기반으로 다음에 "
        "크롤할 곳을 결정한다. 여러 회 반복 시 신규 엔드포인트가 더 이상 "
        "나오지 않을 때까지 계속한다."
    ),
    entry_conditions=("Ghost active", "scope rules loaded", "P1 strategy ready"),
    recommended_primitives=(
        "vxis_crawl",
        "vxis_fingerprint",
        "vxis_subdomain_enum",
        "vxis_parse_forms",
        "vxis_extract_secrets",
        "vxis_parse_openapi",
        "vxis_screenshot",
        "vxis_xray_start",
    ),
    mandatory_primitives=("vxis_crawl", "vxis_fingerprint"),
    dead_end_criteria=(
        DeadEndCriterion(
            id="tech_stack_known",
            description_en="At least one fingerprint result captured",
            description_ko="최소 1개 이상의 fingerprint 결과 수집됨",
            check=lambda ctx: bool(getattr(ctx, "tech_stack", None)),
        ),
        DeadEndCriterion(
            id="endpoints_saturated",
            description_en="Last 2 crawl iterations added zero new endpoints",
            description_ko="최근 2회 크롤이 신규 엔드포인트 0개 추가",
            check=lambda ctx: getattr(ctx, "new_endpoints_last_pass", 1) == 0,
        ),
        DeadEndCriterion(
            id="forms_parsed",
            description_en="All discovered HTML forms parsed",
            description_ko="발견된 모든 HTML 폼 파싱 완료",
            check=lambda ctx: getattr(ctx, "forms_pending", 0) == 0,
        ),
        DeadEndCriterion(
            id="js_bundles_scanned",
            description_en="JS bundles scanned for secrets/endpoints",
            description_ko="JS 번들의 시크릿/엔드포인트 스캔 완료",
            check=lambda ctx: getattr(ctx, "js_scanned", False),
        ),
    ),
    success_criteria=(
        "Endpoint inventory >= 1",
        "Tech stack identified",
        "Forms catalog produced",
    ),
    blocking_errors=("ghost_dropped", "scope_violation", "target_unreachable"),
    strategic_advice_en=(
        "Push recon to TRUE dead end. Most engagements fail because recon "
        "stopped early. JS bundles are gold — they leak API endpoints, AWS "
        "keys, internal hostnames. Subdomains often hide admin/staging panels "
        "with weaker auth than production."
    ),
    strategic_advice_ko=(
        "정찰을 진짜 DEAD END까지 밀어붙인다. 대부분의 엔게이지먼트 실패는 "
        "정찰을 일찍 멈춘 탓이다. JS 번들은 금광이다 — API 엔드포인트, AWS "
        "키, 내부 호스트명이 노출된다. 서브도메인에는 프로덕션보다 인증이 "
        "약한 admin/staging 패널이 숨어있는 경우가 많다."
    ),
    crown_hint_en=(
        "JS bundles often leak secrets directly. Subdomains often expose "
        "admin/staging environments with weaker authentication."
    ),
    crown_hint_ko=(
        "JS 번들에 시크릿이 직접 노출되는 경우가 많다. 서브도메인에 admin/staging "
        "환경이 약한 인증으로 노출되는 경우가 많다."
    ),
    max_duration_minutes=60,
    next_phase_hint=("P2_agents", "P3_hypothesis"),
)
