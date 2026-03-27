"""VXIS Capability Scoring System.

5개 차원으로 펜테스팅 도구의 역량을 정량화하는 벤치마킹 엔진.
CI 기반 회귀 탐지 및 지속적 개선 루프를 지원한다.

Dimensions:
  1. Vector Coverage (25%, max 250pts)    — 공격 벡터 커버리지
  2. Exploitation Reach (30%, max 300pts) — 익스플로잇 도달 깊이
  3. Chain Intelligence (15%, max 150pts) — 공격 체인 지능
  4. Finding Precision (20%, max 200pts)  — 발견 정밀도
  5. Completeness (10%, max 100pts)       — 완성도

Grade Scale:
  S (900-1000): NCC Group 시니어 레벨
  A (750-899):  프로덕션 레디
  B (600-749):  자동 스캐너 이상
  C (400-599):  기본 스캐너 레벨
  D (0-399):    개발 중
"""

from __future__ import annotations

from vxis.scoring.vectors import (
    GAME_VECTORS,
    MOBILE_VECTORS,
    WEB_VECTORS,
    AttackVector,
    get_vectors_for_type,
)
from vxis.scoring.tracker import (
    AttackChain,
    ChainStep,
    PhaseResult,
    PhaseStatus,
    ScoreTracker,
)
from vxis.scoring.engine import (
    DimensionScore,
    ScoringEngine,
    VXISScore,
)
from vxis.scoring.reporter import (
    ScoreComparison,
    ScoreReporter,
)
from vxis.scoring.benchmark import BenchmarkRunner

__all__ = [
    # vectors
    "AttackVector",
    "WEB_VECTORS",
    "GAME_VECTORS",
    "MOBILE_VECTORS",
    "get_vectors_for_type",
    # tracker
    "ScoreTracker",
    "AttackChain",
    "ChainStep",
    "PhaseResult",
    "PhaseStatus",
    # engine
    "ScoringEngine",
    "VXISScore",
    "DimensionScore",
    # reporter
    "ScoreReporter",
    "ScoreComparison",
    # benchmark
    "BenchmarkRunner",
]
