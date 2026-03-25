"""CVE 엔트리 — 통합 데이터 모델.

GitHub Advisory, NVD, OSV 세 소스에서 수집된 취약점 데이터를
단일 표준 형식으로 정규화한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CVEEntry:
    """취약점 정보 통합 모델.

    모든 소스(GitHub Advisory, NVD, OSV)에서 수집한 데이터를
    동일한 구조로 정규화하여 매칭 및 익스플로잇 테스터에 전달한다.
    """

    # 필수 식별자
    id: str                              # CVE-YYYY-NNNNN 또는 GHSA-XXXX-XXXX-XXXX
    source: str                          # "github", "nvd", "osv"
    title: str
    description: str

    # 심각도
    severity: str = "unknown"            # critical, high, medium, low, unknown
    cvss_score: float = 0.0             # 0.0 ~ 10.0

    # 영향 범위
    affected_products: list[str] = field(default_factory=list)   # CPE 또는 패키지 이름
    affected_versions: list[str] = field(default_factory=list)   # 영향받는 버전 목록

    # 타임스탬프 (ISO 8601)
    published_at: str = ""

    # 참고 URL
    references: list[str] = field(default_factory=list)

    # 익스플로잇 정보
    exploit_available: bool = False
    poc_url: str = ""                    # 알려진 PoC URL

    # 내부 처리용 메타데이터
    ecosystem: str = ""                  # OSV 소스일 때 에코시스템 (npm, PyPI 등)
    raw: dict = field(default_factory=dict)  # 원본 응답 (디버그용)

    def is_critical_or_high(self) -> bool:
        """CVSS 7.0 이상이거나 심각도가 critical/high인지 확인."""
        return self.severity.lower() in ("critical", "high") or self.cvss_score >= 7.0

    def canonical_id(self) -> str:
        """CVE ID가 있으면 반환, 없으면 GHSA ID 사용."""
        if self.id.upper().startswith("CVE-"):
            return self.id.upper()
        return self.id

    def to_dict(self) -> dict:
        """직렬화용 딕셔너리 변환 (raw 필드 제외)."""
        return {
            "id": self.id,
            "source": self.source,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "affected_products": self.affected_products,
            "affected_versions": self.affected_versions,
            "published_at": self.published_at,
            "references": self.references,
            "exploit_available": self.exploit_available,
            "poc_url": self.poc_url,
            "ecosystem": self.ecosystem,
        }
