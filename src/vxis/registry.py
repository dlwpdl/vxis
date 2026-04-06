"""VXIS Registry — Single Source of Truth for all metadata.

모든 Phase, Target, Dimension, Version 정보가 여기서만 정의됨.
pipeline, help, growth_loop, CI check 등은 이 모듈을 import해서 사용.
절대 다른 곳에 하드코딩하지 말 것.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# ── Version ───────────────────────────────────────────────────────

VERSION = "0.2.0"

# ── Phase 정의 ────────────────────────────────────────────────────


@dataclass(frozen=True)
class PhaseInfo:
    """파이프라인 Phase 메타데이터."""
    id: int
    name: str
    name_ko: str
    stage: str           # init, recon, intelligence, exploitation, chain, report, learning, external
    method: str          # pipeline method name (e.g. "_phase0_foundation")
    description: str = ""


# 실행 순서대로 정의 — pipeline.py는 이 순서를 따름
WEB_PHASES: list[PhaseInfo] = [
    # STAGE 1: FOUNDATION
    PhaseInfo(0,  "Foundation — Config & DB Init",            "기반 — 설정 & DB 초기화",         "init",           "_phase0_foundation"),
    PhaseInfo(1,  "Director — Attack Graph Init",             "디렉터 — 공격 그래프 초기화",      "init",           "_phase1_director"),
    # STAGE 2: RECON
    PhaseInfo(4,  "CPR — Hands/Eyes/X-Ray Connect",           "CPR — 크롤링/엔드포인트 수집",     "recon",          "_phase4_cpr"),
    PhaseInfo(15, "Digital Twin Pre-Simulation",               "디지털 트윈 사전 시뮬레이션",      "recon",          "_phase15_digital_twin"),
    PhaseInfo(13, "Behavioral Biometrics (OSINT)",             "행위 생체인식 (OSINT)",            "recon",          "_phase13_biometrics"),
    # STAGE 3: INTELLIGENCE
    PhaseInfo(2,  "63 Autonomous Agents — Brain-Directed Dispatch", "63개 자율 에이전트 — Brain 지휘", "intelligence", "_phase2_agents"),
    PhaseInfo(3,  "Hypothesis Engine — Pattern Matching",      "가설 엔진 — 패턴 매칭",           "intelligence",   "_phase3_hypothesis"),
    # STAGE 4: EXPLOITATION
    PhaseInfo(5,  "Special Agents (IoT/VoIP/Web3)",            "특수 에이전트 (IoT/VoIP/Web3)",    "exploitation",   "_phase5_special"),
    PhaseInfo(7,  "Hardware Agents (DMA/SS7/Cold Boot)",        "하드웨어 에이전트",                "exploitation",   "_phase7_hardware"),
    # STAGE 5: CHAIN ANALYSIS
    PhaseInfo(8,  "Cross-Protocol Synthesis",                   "크로스 프로토콜 합성",             "chain",          "_phase8_synthesis"),
    PhaseInfo(11, "Chain Mutation — Alternative Attack Paths",  "체인 변이 — 대체 공격 경로",       "chain",          "_phase11_mutation"),
    # STAGE 6: REPORT
    PhaseInfo(6,  "Report Generation — NCC Group Style",       "리포트 생성 — NCC Group 스타일",   "report",         "_phase6_report"),
    # STAGE 7: LEARNING
    PhaseInfo(12, "Self-Evolving Agent — Coverage Gap Analysis", "자가 진화 — 커버리지 갭 분석",   "learning",       "_phase12_evolution"),
    PhaseInfo(18, "Collective Intelligence Update",             "집단 지능 업데이트",               "learning",       "_phase18_collective"),
]

# GH Actions 담당 (파이프라인 외부)
EXTERNAL_PHASES: list[PhaseInfo] = [
    PhaseInfo(9,  "CVE Watch — Component Vulnerability Matching", "CVE 감시",                     "external",       "cve-watch.yml"),
    PhaseInfo(14, "Temporal Vulnerability Forecast",               "시간 기반 취약점 예측",         "external",       "domain-intel.yml"),
    PhaseInfo(16, "Industry Intelligence — Sector Risk Heatmap",  "산업 인텔리전스",               "external",       "domain-intel.yml"),
]

# 미래 구현 예정
FUTURE_PHASES: list[PhaseInfo] = [
    PhaseInfo(10, "Red vs Blue — Defense Rule Generation",     "레드 vs 블루 — 방어 규칙 생성",   "future",         "_phase10_red_vs_blue"),
    PhaseInfo(17, "Outreach",                                   "아웃리치",                        "future",         "_phase17_outreach"),
    PhaseInfo(19, "Bug Bounty Submission",                      "버그 바운티 제출",                "future",         "_phase19_bounty"),
]

ALL_PHASES = WEB_PHASES + EXTERNAL_PHASES + FUTURE_PHASES

STAGE_NAMES: dict[str, str] = {
    "init":           "Stage 1: Foundation",
    "recon":          "Stage 2: Recon",
    "intelligence":   "Stage 3: Intelligence",
    "exploitation":   "Stage 4: Exploitation",
    "chain":          "Stage 5: Chain Analysis",
    "report":         "Stage 6: Report",
    "learning":       "Stage 7: Learning",
    "external":       "GH Actions (external)",
    "future":         "Future (not implemented)",
}


# ── Target 정의 ───────────────────────────────────────────────────


@dataclass(frozen=True)
class TargetInfo:
    """벤치마크 타겟 메타데이터."""
    name: str
    url: str
    port: str            # docker port mapping (e.g. "8081:80")
    image: str = ""      # docker image
    compose: str = ""    # docker-compose path (image 대신)
    category: str = ""   # OWASP, GraphQL, API, etc.
    description: str = ""


BENCHMARK_TARGETS: list[TargetInfo] = [
    TargetInfo("dvwa",       "http://localhost:8081",           "8081:80",   image="vulnerables/web-dvwa",    category="OWASP",    description="OWASP Top 10 기본"),
    TargetInfo("juice-shop", "http://localhost:3000",           "3000:3000", image="bkimminich/juice-shop",   category="Modern",   description="현대적 웹앱"),
    TargetInfo("webgoat",    "http://localhost:8888/WebGoat",   "8888:8080", image="webgoat/webgoat",         category="Learning", description="학습용 취약점"),
    TargetInfo("nodegoat",   "http://localhost:4000",           "4000:4000", image="1njected/nodegoat",       category="Node.js",  description="Node.js 취약점"),
    TargetInfo("mutillidae", "http://localhost:8082",           "8082:80",   image="citizenstig/nowasp",      category="OWASP",    description="OWASP Top 10 풀커버"),
    TargetInfo("bwapp",      "http://localhost:8083",           "8083:80",   image="raesene/bwapp",           category="Multi",    description="100+ 취약점"),
    TargetInfo("dvga",       "http://localhost:5013",           "5013:5013", image="dolevf/dvga",             category="GraphQL",  description="GraphQL 특화"),
    TargetInfo("crapi",      "http://localhost:8025",           "8025:8025", compose="tools/targets/crapi",   category="API",      description="API 보안 (OWASP API Top 10)"),
]

# dict 형태 (하위 호환)
TARGETS_DICT: dict[str, dict[str, str]] = {}
for _t in BENCHMARK_TARGETS:
    _d: dict[str, str] = {"url": _t.url, "port": _t.port}
    if _t.image:
        _d["image"] = _t.image
    if _t.compose:
        _d["compose"] = _t.compose
    TARGETS_DICT[_t.name] = _d


# ── Scoring Dimensions ────────────────────────────────────────────

DIMENSIONS: dict[str, dict[str, str | int]] = {
    "vector_coverage":    {"name_ko": "벡터 커버리지",  "max": 250},
    "exploitation_reach": {"name_ko": "공격 깊이",      "max": 300},
    "chain_intelligence": {"name_ko": "체인 지능",      "max": 150},
    "finding_precision":  {"name_ko": "발견 정확도",    "max": 200},
    "completeness":       {"name_ko": "완전성",         "max": 100},
}

DIM_NAMES_KO: dict[str, str] = {k: str(v["name_ko"]) for k, v in DIMENSIONS.items()}
DIM_MAX: dict[str, int] = {k: int(v["max"]) for k, v in DIMENSIONS.items()}
