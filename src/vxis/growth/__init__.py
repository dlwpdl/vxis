"""VXIS Growth Layer — Self-Growth Intelligence (Bootstrap Mode).

이 모듈은 외부 시그널(CVE, Threat News, Upstream Watch)을 수집하여
구조화된 인텔리전스로 변환하고, Brain/Phase/KB 업그레이드 제안을 생성한다.

Bootstrap Mode 원칙:
- Dry-run default (처음 30일은 실제 코드 수정 없음)
- Regex pre-filter 후에만 LLM 호출
- SHA256 캐싱으로 재분석 방지
- Trust threshold gating (>= 0.8 만 full LLM)
- 월별 예산 cap

Self-Growth Intelligence Layer that ingests external signals and produces
structured upgrade proposals for Brain / Phases / KB without touching code
during the bootstrap period.
"""

from vxis.growth import (
    analyze,
    apply,
    cache,
    changelog,
    classifier,
    config,
    digest,
    ingest,
    regex_filter,
    rollback,
    schemas,
    trust,
)

__all__ = [
    "analyze",
    "apply",
    "cache",
    "changelog",
    "classifier",
    "config",
    "digest",
    "ingest",
    "regex_filter",
    "rollback",
    "schemas",
    "trust",
]
