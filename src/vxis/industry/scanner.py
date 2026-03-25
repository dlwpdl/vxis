"""산업 전체를 자율적으로 스캔하는 엔진.

:class:`IndustryScanner` 는 :class:`~vxis.core.orchestrator.ScanOrchestrator` 를
재사용하여 :class:`~vxis.industry.discovery.CompanyProfile` 목록을 일괄 스캔하고,
각 기업에 보안 등급(A~F)을 산정한 뒤 :class:`IndustryScanResult` 로 집계합니다.

예시::

    from vxis.industry import IndustryDiscovery, IndustryScanner

    discovery = IndustryDiscovery(industry="fintech")
    companies = discovery.discover_from_csv("companies.csv")

    scanner = IndustryScanner(max_concurrent=5)
    result = await scanner.scan_industry(companies)
    print(result.average_grade)
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable

from vxis.config.schema import VXISConfig
from vxis.core.orchestrator import ScanOrchestrator, ScanResult
from vxis.industry.discovery import CompanyProfile

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 등급 계산 기준 (batch.py의 calculate_risk_grade 와 동일 로직)
# ---------------------------------------------------------------------------

#  A : critical=0, high=0
#  B : critical=0, high 1~3
#  C : critical=0, high 4+  OR  critical=1
#  D : critical 2~3
#  F : critical 4+

_GRADE_ORDER: list[str] = ["A", "B", "C", "D", "F"]

_GRADE_WEIGHTS: dict[str, int] = {"A": 4, "B": 3, "C": 2, "D": 1, "F": 0}


def _weighted_average_grade(grades: list[str]) -> str:
    """등급 목록을 가중 평균하여 대표 등급을 반환합니다."""
    if not grades:
        return "N/A"

    valid = [g for g in grades if g in _GRADE_WEIGHTS]
    if not valid:
        return "N/A"

    avg_weight = sum(_GRADE_WEIGHTS[g] for g in valid) / len(valid)

    # 가장 가까운 등급 찾기
    best_grade = min(
        _GRADE_WEIGHTS.keys(),
        key=lambda g: abs(_GRADE_WEIGHTS[g] - avg_weight),
    )
    return best_grade


# ---------------------------------------------------------------------------
# IndustryScanResult
# ---------------------------------------------------------------------------


@dataclass
class IndustryScanResult:
    """산업 전체 스캔 집계 결과."""

    companies: list[CompanyProfile] = field(default_factory=list)
    total_companies: int = 0
    scanned_companies: int = 0
    failed_companies: int = 0
    average_grade: str = "N/A"
    grade_distribution: dict[str, int] = field(default_factory=dict)
    industry_findings: dict[str, int] = field(default_factory=dict)
    most_common_vulns: list[tuple[str, int]] = field(default_factory=list)
    scan_duration: float = 0.0
    started_at: str = ""
    completed_at: str = ""

    def to_summary_dict(self) -> dict[str, object]:
        """리포트 생성용 요약 dict."""
        return {
            "total_companies": self.total_companies,
            "scanned_companies": self.scanned_companies,
            "failed_companies": self.failed_companies,
            "average_grade": self.average_grade,
            "grade_distribution": self.grade_distribution,
            "industry_findings": self.industry_findings,
            "most_common_vulns": self.most_common_vulns,
            "scan_duration": round(self.scan_duration, 1),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }


# ---------------------------------------------------------------------------
# IndustryScanner
# ---------------------------------------------------------------------------


class IndustryScanner:
    """산업 전체 자율 스캔 엔진.

    Args:
        max_concurrent: 동시 스캔 최대 수 (기본: 5).
        config: VXISConfig 인스턴스. None 이면 기본값으로 생성합니다.
        on_progress: 진행 상황 콜백. ``(completed, total, company)`` 형태로 호출됩니다.
    """

    def __init__(
        self,
        max_concurrent: int = 5,
        config: VXISConfig | None = None,
        on_progress: Callable[[int, int, CompanyProfile], None] | None = None,
    ) -> None:
        self._max_concurrent = max(1, max_concurrent)
        self._config = config or VXISConfig()
        self._orchestrator = ScanOrchestrator(self._config)
        self._on_progress = on_progress

    # ------------------------------------------------------------------
    # 공개 API
    # ------------------------------------------------------------------

    async def scan_industry(
        self,
        companies: list[CompanyProfile],
        profile: str = "standard",
    ) -> IndustryScanResult:
        """전체 기업 목록을 비동기 일괄 스캔합니다.

        스캔은 ``max_concurrent`` 개씩 병렬로 실행되며,
        각 완료 후 보안 등급을 산정합니다. 실패한 스캔은 등급 ''으로 표기됩니다.

        Args:
            companies: 스캔 대상 :class:`~vxis.industry.discovery.CompanyProfile` 목록.
            profile: 스캔 강도 (passive / standard / aggressive).

        Returns:
            :class:`IndustryScanResult` 집계 결과.
        """
        started_at = time.monotonic()
        started_ts = datetime.now(timezone.utc).isoformat()

        total = len(companies)
        logger.info("산업 스캔 시작: %d개 기업, profile=%s", total, profile)

        semaphore = asyncio.Semaphore(self._max_concurrent)
        completed_count = 0

        # vuln 유형 전체 집계
        vuln_counter: Counter[str] = Counter()
        # 심각도별 전체 카운트
        sev_total: dict[str, int] = {
            "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0
        }

        async def _scan_one(company: CompanyProfile, idx: int) -> None:
            nonlocal completed_count

            async with semaphore:
                logger.info(
                    "[%d/%d] 스캔 시작: %s (%s)",
                    idx + 1, total, company.name, company.domain,
                )
                try:
                    scan_result: ScanResult = await self._orchestrator.run_scan(
                        target=company.domain,
                        profile=profile,
                    )
                    self._apply_scan_result(company, scan_result, vuln_counter, sev_total)
                    logger.info(
                        "[%d/%d] 완료: %s → 등급=%s, 발견=%d건",
                        idx + 1, total, company.name,
                        company.security_grade, company.findings_count,
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "[%d/%d] 스캔 실패: %s — %s",
                        idx + 1, total, company.name, exc,
                    )
                    company.security_grade = ""  # 실패 표시

                completed_count += 1

                if self._on_progress is not None:
                    try:
                        self._on_progress(completed_count, total, company)
                    except Exception:  # noqa: BLE001
                        pass

        await asyncio.gather(
            *[_scan_one(c, i) for i, c in enumerate(companies)],
            return_exceptions=True,
        )

        duration = time.monotonic() - started_at
        completed_ts = datetime.now(timezone.utc).isoformat()

        # 집계
        result = self._build_result(
            companies=companies,
            sev_total=sev_total,
            vuln_counter=vuln_counter,
            duration=duration,
            started_at=started_ts,
            completed_at=completed_ts,
        )

        logger.info(
            "산업 스캔 완료: %d개 기업, 평균 등급=%s, %.0f초",
            total, result.average_grade, duration,
        )
        return result

    # ------------------------------------------------------------------
    # 등급 계산
    # ------------------------------------------------------------------

    @staticmethod
    def calculate_grade(findings: object) -> str:
        """findings에서 critical/high 카운트를 기반으로 A~F 등급을 반환합니다.

        Args:
            findings: severity_counts 속성이 있는 ScanResult,
                      또는 {"critical": int, "high": int} dict.

        Returns:
            등급 문자열: 'A', 'B', 'C', 'D', 'F'.
        """
        if hasattr(findings, "severity_counts"):
            counts: dict[str, int] = findings.severity_counts
        elif isinstance(findings, dict):
            counts = findings
        else:
            counts = {}

        critical = counts.get("critical", 0)
        high = counts.get("high", 0)

        if critical >= 4:
            return "F"
        if critical in (2, 3):
            return "D"
        if critical == 1 or high >= 4:
            return "C"
        if 1 <= high <= 3:
            return "B"
        return "A"

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    def _apply_scan_result(
        self,
        company: CompanyProfile,
        scan_result: ScanResult,
        vuln_counter: Counter[str],
        sev_total: dict[str, int],
    ) -> None:
        """ScanResult를 CompanyProfile에 반영하고 집계 카운터를 업데이트합니다."""
        counts = scan_result.severity_counts

        company.security_grade = self.calculate_grade(scan_result)
        company.findings_count = len(scan_result.findings)
        company.critical_count = counts.get("critical", 0)
        company.high_count = counts.get("high", 0)
        company.last_scanned = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")

        # 기술 스택 추론 (finding_type / plugin 정보에서)
        stack_set: set[str] = set()
        for finding in scan_result.findings:
            finding_type = getattr(finding, "finding_type", "") or ""
            if finding_type:
                vuln_counter[finding_type] += 1
            plugin = getattr(finding, "plugin", "") or ""
            if plugin:
                stack_set.add(plugin)
        company.tech_stack = sorted(stack_set)

        # 심각도 전체 집계
        for sev_key in sev_total:
            sev_total[sev_key] += counts.get(sev_key, 0)

    @staticmethod
    def _build_result(
        companies: list[CompanyProfile],
        sev_total: dict[str, int],
        vuln_counter: Counter[str],
        duration: float,
        started_at: str,
        completed_at: str,
    ) -> IndustryScanResult:
        """스캔 완료 후 집계 결과를 빌드합니다."""
        scanned = [c for c in companies if c.security_grade]
        failed = [c for c in companies if not c.security_grade]

        grades = [c.security_grade for c in scanned]
        grade_dist: dict[str, int] = {g: 0 for g in _GRADE_ORDER}
        for g in grades:
            if g in grade_dist:
                grade_dist[g] += 1

        avg_grade = _weighted_average_grade(grades)

        return IndustryScanResult(
            companies=companies,
            total_companies=len(companies),
            scanned_companies=len(scanned),
            failed_companies=len(failed),
            average_grade=avg_grade,
            grade_distribution=grade_dist,
            industry_findings=dict(sev_total),
            most_common_vulns=vuln_counter.most_common(20),
            scan_duration=duration,
            started_at=started_at,
            completed_at=completed_at,
        )
