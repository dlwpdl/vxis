"""NVD REST API v2.0 — 공식 CVSS 점수.

미국 국립표준기술연구소(NIST)의 NVD(National Vulnerability Database)에서
최근 수정된 CVE 항목을 가져온다.

Rate limit:
    - API 키 없음: 5 요청 / 30초 (1 req/6s 유지 권장)
    - API 키 있음: 50 요청 / 30초
    - 환경 변수 NVD_API_KEY 설정 시 자동으로 키 사용

API 참고:
    https://nvd.nist.gov/developers/vulnerabilities
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from ..cve_entry import CVEEntry

logger = logging.getLogger(__name__)

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_USER_AGENT = "VXIS-CVE-Watch/1.0 (security research; contact via GitHub)"

# API 키 없을 때 요청 간 최소 간격 (초)
_RATE_LIMIT_DELAY_NO_KEY = 6.0
# API 키 있을 때 요청 간 최소 간격 (초)
_RATE_LIMIT_DELAY_WITH_KEY = 0.6


def _get_api_key() -> str | None:
    """NVD API 키를 환경 변수에서 가져온다."""
    return os.environ.get("NVD_API_KEY") or None


def _build_url(since_dt: datetime, results_per_page: int = 2000, start_index: int = 0) -> str:
    """NVD API v2 요청 URL을 생성한다."""
    # NVD는 ISO 8601 UTC 형식 필요: yyyy-MM-dd'T'HH:mm:ss.SSS Z
    fmt = "%Y-%m-%dT%H:%M:%S.000 UTC"
    now = datetime.now(timezone.utc)
    params = {
        "lastModStartDate": since_dt.strftime(fmt),
        "lastModEndDate": now.strftime(fmt),
        "resultsPerPage": str(results_per_page),
        "startIndex": str(start_index),
    }
    return f"{_NVD_BASE_URL}?{urllib.parse.urlencode(params)}"


def _fetch_page(url: str, api_key: str | None) -> dict | None:
    """단일 NVD API 페이지를 요청하고 JSON 응답을 반환."""
    headers = {
        "User-Agent": _USER_AGENT,
        "Accept": "application/json",
    }
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
        return json.loads(body)
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            logger.warning("[NVD] 403 Forbidden — API 키가 필요하거나 Rate limit 초과")
        elif exc.code == 503:
            logger.warning("[NVD] 503 Service Unavailable — 잠시 후 재시도")
        else:
            logger.warning("[NVD] HTTP 오류 %d: %s", exc.code, exc.reason)
        return None
    except urllib.error.URLError as exc:
        logger.warning("[NVD] 네트워크 오류: %s", exc.reason)
        return None
    except json.JSONDecodeError as exc:
        logger.warning("[NVD] JSON 파싱 실패: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("[NVD] 예상치 못한 오류: %s", exc)
        return None


def _extract_cvss_score(metrics: dict) -> tuple[float, str]:
    """metrics 딕셔너리에서 최고 버전의 CVSS 점수와 벡터를 추출."""
    # CVSS v4.0 > v3.1 > v3.0 > v2.0 순으로 우선순위
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0]
            if key == "cvssMetricV2":
                cvss_data = data.get("cvssData", {})
                return float(cvss_data.get("baseScore", 0.0)), cvss_data.get("vectorString", "")
            else:
                cvss_data = data.get("cvssData", {})
                return float(cvss_data.get("baseScore", 0.0)), cvss_data.get("vectorString", "")
    return 0.0, ""


def _score_to_severity(score: float) -> str:
    """CVSS 점수를 심각도 문자열로 변환."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "unknown"


def _extract_cpe_products(configurations: list[dict]) -> list[str]:
    """CVE configurations에서 CPE 문자열 목록을 추출."""
    products: list[str] = []
    seen: set[str] = set()

    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe = cpe_match.get("criteria", "")
                if cpe and cpe not in seen:
                    seen.add(cpe)
                    products.append(cpe)

            # 중첩 children 처리
            for child in node.get("children", []):
                for cpe_match in child.get("cpeMatch", []):
                    cpe = cpe_match.get("criteria", "")
                    if cpe and cpe not in seen:
                        seen.add(cpe)
                        products.append(cpe)

    return products


def _extract_version_ranges(configurations: list[dict]) -> list[str]:
    """CPE match 항목에서 버전 범위를 추출."""
    versions: list[str] = []
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if not cpe_match.get("vulnerable", False):
                    continue
                parts = []
                if cpe_match.get("versionStartIncluding"):
                    parts.append(f">={cpe_match['versionStartIncluding']}")
                if cpe_match.get("versionStartExcluding"):
                    parts.append(f">{cpe_match['versionStartExcluding']}")
                if cpe_match.get("versionEndIncluding"):
                    parts.append(f"<={cpe_match['versionEndIncluding']}")
                if cpe_match.get("versionEndExcluding"):
                    parts.append(f"<{cpe_match['versionEndExcluding']}")
                if parts:
                    versions.append(" ".join(parts))
    return versions


def _check_exploit_references(refs: list[dict]) -> tuple[bool, str]:
    """참고 URL에서 exploit 가용 여부를 확인."""
    exploit_keywords = ("exploit", "poc", "proof-of-concept", "exploit-db", "github.com")

    for ref in refs:
        tags = set(ref.get("tags", []))
        url = ref.get("url", "")
        if "Exploit" in tags:
            return True, url
        lower_url = url.lower()
        if any(kw in lower_url for kw in exploit_keywords):
            return True, url

    return False, ""


def _parse_vulnerability(vuln: dict) -> CVEEntry | None:
    """NVD vulnerability 항목을 CVEEntry로 변환."""
    cve_id: str = vuln.get("id", "")
    if not cve_id:
        return None

    # 상태 확인 — REJECTED는 건너뜀
    vuln_status = vuln.get("vulnStatus", "")
    if vuln_status == "Rejected":
        return None

    # 설명 (영어 우선, 없으면 첫 번째)
    descriptions: list[dict] = vuln.get("descriptions", [])
    description = ""
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break
    if not description and descriptions:
        description = descriptions[0].get("value", "")

    # CVSS 점수 추출
    metrics: dict = vuln.get("metrics", {})
    cvss_score, cvss_vector = _extract_cvss_score(metrics)
    severity = _score_to_severity(cvss_score)

    # 발행일
    published_at: str = vuln.get("published", "")

    # CPE 기반 영향 제품
    configurations: list[dict] = vuln.get("configurations", [])
    affected_products = _extract_cpe_products(configurations)
    affected_versions = _extract_version_ranges(configurations)

    # 참고 URL
    references_raw: list[dict] = vuln.get("references", [])
    references = [r.get("url", "") for r in references_raw if r.get("url")]
    exploit_available, poc_url = _check_exploit_references(references_raw)

    return CVEEntry(
        id=cve_id,
        source="nvd",
        title=cve_id,  # NVD에는 별도 title 없음, CVE ID 사용
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        affected_products=affected_products,
        affected_versions=affected_versions,
        published_at=published_at,
        references=references,
        exploit_available=exploit_available,
        poc_url=poc_url,
        raw=vuln,
    )


def fetch_recent(since_hours: int = 1) -> list[CVEEntry]:
    """최근 N시간 이내에 수정된 NVD CVE 항목을 가져온다.

    Args:
        since_hours: 몇 시간 이전부터 조회할지 (기본 1시간).

    Returns:
        CVEEntry 목록. API 오류 시 빈 리스트 반환.

    Note:
        NVD API는 최대 2,000개를 한 번에 반환한다.
        since_hours가 길면 여러 페이지를 순차 요청한다.
        API 키 없을 때 페이지당 6초 대기.
    """
    api_key = _get_api_key()
    delay = _RATE_LIMIT_DELAY_WITH_KEY if api_key else _RATE_LIMIT_DELAY_NO_KEY

    since_dt = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    results: list[CVEEntry] = []
    start_index = 0
    results_per_page = 2000
    total_results: int | None = None
    page = 0

    logger.info(
        "[NVD] %d시간 이내 CVE 조회 시작 (API 키: %s)",
        since_hours,
        "있음" if api_key else "없음",
    )

    while True:
        if page > 0:
            # Rate limit 준수
            logger.debug("[NVD] Rate limit 대기 %.1f초", delay)
            time.sleep(delay)

        url = _build_url(since_dt, results_per_page, start_index)
        logger.debug("[NVD] 요청: startIndex=%d", start_index)

        data = _fetch_page(url, api_key)
        if data is None:
            break

        if total_results is None:
            total_results = data.get("totalResults", 0)
            logger.info("[NVD] 총 %d개 CVE 발견", total_results)

        vulnerabilities: list[dict] = data.get("vulnerabilities", [])
        for item in vulnerabilities:
            vuln_data = item.get("cve", {})
            entry = _parse_vulnerability(vuln_data)
            if entry is not None:
                results.append(entry)

        start_index += len(vulnerabilities)
        page += 1

        if not vulnerabilities or start_index >= (total_results or 0):
            break

        # 너무 많은 결과 방지 (최대 10,000개)
        if start_index >= 10000:
            logger.warning("[NVD] 결과가 너무 많아 10,000개에서 중단")
            break

    logger.info("[NVD] %d개 CVE 수집 완료", len(results))
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    entries = fetch_recent(since_hours=6)
    for e in entries[:20]:
        print(f"{e.id} [CVSS:{e.cvss_score:.1f}] {e.description[:80]}")
    print(f"\n총 {len(entries)}개")
