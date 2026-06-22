"""VXIS Registry - shared metadata used by CLI, benchmarks, and scoring."""

from __future__ import annotations

from dataclasses import dataclass

# ── Version ───────────────────────────────────────────────────────

VERSION = "0.2.0"

# ── Target 정의 ───────────────────────────────────────────────────


@dataclass(frozen=True)
class TargetInfo:
    """벤치마크 타겟 메타데이터."""

    name: str
    url: str
    port: str  # docker port mapping (e.g. "8081:80")
    image: str = ""  # docker image
    compose: str = ""  # docker-compose path (image 대신)
    category: str = ""  # OWASP, GraphQL, API, etc.
    description: str = ""


BENCHMARK_TARGETS: list[TargetInfo] = [
    TargetInfo(
        "dvwa",
        "http://localhost:8081",
        "8081:80",
        image="vulnerables/web-dvwa",
        category="OWASP",
        description="OWASP Top 10 기본",
    ),
    TargetInfo(
        "juice-shop",
        "http://localhost:3000",
        "3000:3000",
        image="bkimminich/juice-shop",
        category="Modern",
        description="현대적 웹앱",
    ),
    TargetInfo(
        "webgoat",
        "http://localhost:8888/WebGoat",
        "8888:8080",
        image="webgoat/webgoat",
        category="Learning",
        description="학습용 취약점",
    ),
    TargetInfo(
        "nodegoat",
        "http://localhost:4000",
        "4000:4000",
        image="1njected/nodegoat",
        category="Node.js",
        description="Node.js 취약점",
    ),
    TargetInfo(
        "mutillidae",
        "http://localhost:8082",
        "8082:80",
        image="citizenstig/nowasp",
        category="OWASP",
        description="OWASP Top 10 풀커버",
    ),
    TargetInfo(
        "bwapp",
        "http://localhost:8083",
        "8083:80",
        image="raesene/bwapp",
        category="Multi",
        description="100+ 취약점",
    ),
    TargetInfo(
        "dvga",
        "http://localhost:5013",
        "5013:5013",
        image="dolevf/dvga",
        category="GraphQL",
        description="GraphQL 특화",
    ),
    TargetInfo(
        "crapi",
        "http://localhost:8025",
        "8025:8025",
        compose="tools/targets/crapi",
        category="API",
        description="API 보안 (OWASP API Top 10)",
    ),
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
    "vector_coverage": {"name_ko": "벡터 커버리지", "max": 250},
    "exploitation_reach": {"name_ko": "공격 깊이", "max": 300},
    "chain_intelligence": {"name_ko": "체인 지능", "max": 150},
    "finding_precision": {"name_ko": "발견 정확도", "max": 200},
    "completeness": {"name_ko": "완전성", "max": 100},
}

DIM_NAMES_KO: dict[str, str] = {k: str(v["name_ko"]) for k, v in DIMENSIONS.items()}
DIM_MAX: dict[str, int] = {k: int(v["max"]) for k, v in DIMENSIONS.items()}
