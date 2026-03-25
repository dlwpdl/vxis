"""OSV.dev API — 에코시스템별 취약점 (npm, PyPI, Maven, Go 등).

Open Source Vulnerability(OSV) 데이터베이스에서 특정 에코시스템의
최근 취약점을 가져온다. 에코시스템별로 별도 쿼리를 수행한다.

지원 에코시스템:
    npm, PyPI, Maven, Go, crates.io, NuGet, RubyGems, Packagist

API 참고:
    https://osv.dev/docs/

Rate limit:
    - 공식 제한 없음, 합리적인 사용 권장
    - 요청 간 최소 0.5초 대기 적용
"""

from __future__ import annotations

import json
import logging
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from ..cve_entry import CVEEntry

logger = logging.getLogger(__name__)

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_USER_AGENT = "VXIS-CVE-Watch/1.0 (security research; contact via GitHub)"

# 지원 에코시스템 목록
SUPPORTED_ECOSYSTEMS = [
    "npm",
    "PyPI",
    "Maven",
    "Go",
    "crates.io",
    "NuGet",
    "RubyGems",
    "Packagist",
]

# 요청 간 최소 대기 (초)
_REQUEST_DELAY = 0.5


def _post_json(url: str, payload: dict) -> dict | None:
    """JSON POST 요청을 수행하고 응답을 반환."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": _USER_AGENT,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        logger.warning("[OSV] HTTP 오류 %d: %s", exc.code, exc.reason)
        return None
    except urllib.error.URLError as exc:
        logger.warning("[OSV] 네트워크 오류: %s", exc.reason)
        return None
    except json.JSONDecodeError as exc:
        logger.warning("[OSV] JSON 파싱 실패: %s", exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("[OSV] 예상치 못한 오류: %s", exc)
        return None


def _extract_cve_id(aliases: list[str]) -> str:
    """aliases 목록에서 CVE ID를 추출."""
    for alias in (aliases or []):
        if alias.upper().startswith("CVE-"):
            return alias.upper()
    return ""


def _extract_severity(severity_list: list[dict], cvss_score: float) -> str:
    """OSV severity 목록 또는 CVSS 점수에서 심각도를 결정."""
    for sev in (severity_list or []):
        score_type = sev.get("type", "")
        score_val = sev.get("score", "")
        if score_type in ("CVSS_V3", "CVSS_V4") and score_val:
            # CVSS 벡터에서 점수 파싱 시도
            # 형식: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (점수는 별도 필드 없음)
            pass

    # CVSS 점수로 fallback
    if cvss_score >= 9.0:
        return "critical"
    if cvss_score >= 7.0:
        return "high"
    if cvss_score >= 4.0:
        return "medium"
    if cvss_score > 0.0:
        return "low"
    return "unknown"


def _extract_cvss_score(severity_list: list[dict]) -> tuple[float, str]:
    """OSV severity에서 CVSS 점수와 벡터를 추출."""
    for sev in (severity_list or []):
        score_str = sev.get("score", "")
        if not score_str:
            continue
        sev_type = sev.get("type", "")

        # CVSS v4: CVSS:4.0/... 형식
        # CVSS v3: CVSS:3.1/... 형식
        # 일부는 숫자만 있는 경우도 있음
        if "CVSS" in sev_type.upper() or score_str.upper().startswith("CVSS"):
            # 숫자 점수는 database_specific에 있는 경우가 많음
            # 여기서는 벡터만 저장, 점수는 0.0으로 초기화
            return 0.0, score_str

    return 0.0, ""


def _parse_affected_packages(affected: list[dict]) -> tuple[list[str], list[str], str]:
    """OSV affected 목록에서 제품명, 버전, 에코시스템을 추출."""
    products: list[str] = []
    versions: list[str] = []
    ecosystems: list[str] = []

    for item in (affected or []):
        pkg = item.get("package") or {}
        ecosystem = pkg.get("ecosystem", "")
        name = pkg.get("name", "")

        if name:
            product = f"{ecosystem}/{name}" if ecosystem else name
            if product not in products:
                products.append(product)

        if ecosystem and ecosystem not in ecosystems:
            ecosystems.append(ecosystem)

        # ranges에서 버전 범위 추출
        for rng in item.get("ranges", []):
            rng_type = rng.get("type", "")
            if rng_type in ("SEMVER", "ECOSYSTEM"):
                for event in rng.get("events", []):
                    if "introduced" in event:
                        versions.append(f">={event['introduced']}")
                    if "fixed" in event:
                        versions.append(f"<{event['fixed']} (fixed)")
                    if "last_affected" in event:
                        versions.append(f"<={event['last_affected']}")

        # versions 필드 (구체적 버전 목록)
        for v in item.get("versions", [])[:10]:  # 최대 10개
            if v not in versions:
                versions.append(v)

    return products, versions, ",".join(ecosystems)


def _check_exploit_refs(refs: list[dict]) -> tuple[bool, str]:
    """참고 URL에서 exploit 가용 여부 확인."""
    exploit_keywords = ("exploit", "poc", "proof-of-concept", "exploit-db")
    for ref in (refs or []):
        url = ref.get("url", "")
        ref_type = ref.get("type", "")
        if ref_type == "FIX":
            continue
        if any(kw in url.lower() for kw in exploit_keywords):
            return True, url
    return False, ""


def _parse_osv_entry(entry: dict, ecosystem: str) -> CVEEntry | None:
    """단일 OSV 항목을 CVEEntry로 변환."""
    osv_id: str = entry.get("id", "")
    if not osv_id:
        return None

    # withdrawn 항목 건너뜀
    if entry.get("withdrawn"):
        return None

    aliases: list[str] = entry.get("aliases", [])
    cve_id = _extract_cve_id(aliases)

    # 식별자 결정: CVE ID > OSV ID
    entry_id = cve_id if cve_id else osv_id

    summary: str = entry.get("summary", "")
    details: str = entry.get("details", "") or summary

    severity_list: list[dict] = entry.get("severity", [])
    cvss_score, cvss_vector = _extract_cvss_score(severity_list)

    # database_specific에 NVD CVSS 점수가 있는 경우
    db_specific = entry.get("database_specific") or {}
    if "cvss" in db_specific and isinstance(db_specific["cvss"], (int, float)):
        cvss_score = float(db_specific["cvss"])
    elif "nvd_published_at" not in db_specific:
        # cvss score from severity
        pass

    severity = _extract_severity(severity_list, cvss_score)

    published_at: str = entry.get("published", "")

    affected: list[dict] = entry.get("affected", [])
    affected_products, affected_versions, ecosystems_str = _parse_affected_packages(affected)

    references: list[dict] = entry.get("references", [])
    ref_urls = [r.get("url", "") for r in references if r.get("url")]
    exploit_available, poc_url = _check_exploit_refs(references)

    return CVEEntry(
        id=entry_id,
        source="osv",
        title=summary or entry_id,
        description=details,
        severity=severity,
        cvss_score=cvss_score,
        affected_products=affected_products,
        affected_versions=affected_versions,
        published_at=published_at,
        references=ref_urls,
        exploit_available=exploit_available,
        poc_url=poc_url,
        ecosystem=ecosystems_str or ecosystem,
        raw=entry,
    )


def fetch_recent(ecosystem: str = "npm", since_hours: int = 1) -> list[CVEEntry]:
    """특정 에코시스템의 최근 N시간 이내 취약점을 가져온다.

    OSV API는 특정 시간 범위 필터를 직접 지원하지 않으므로,
    package 없이 ecosystem으로만 쿼리하면 최신 결과를 가져온 후
    published_at 기준으로 클라이언트 필터링을 수행한다.

    Args:
        ecosystem: 조회할 에코시스템 (npm, PyPI, Maven, Go, crates.io 등).
        since_hours: 몇 시간 이전부터 조회할지 (기본 1시간).

    Returns:
        CVEEntry 목록.
    """
    if ecosystem not in SUPPORTED_ECOSYSTEMS:
        logger.warning("[OSV] 지원하지 않는 에코시스템: %s", ecosystem)
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)

    # OSV v1 query API: package 없이 ecosystem만 넣으면 해당 에코시스템 전체 조회
    # page_token으로 페이지네이션
    results: list[CVEEntry] = []
    page_token: str | None = None
    page = 0
    max_pages = 3  # 에코시스템 전체 조회이므로 결과가 방대할 수 있음

    logger.info("[OSV] %s 에코시스템 %d시간 이내 취약점 조회 시작", ecosystem, since_hours)

    while page < max_pages:
        if page > 0:
            time.sleep(_REQUEST_DELAY)

        payload: dict = {
            "package": {
                "ecosystem": ecosystem,
            },
        }
        if page_token:
            payload["page_token"] = page_token

        response = _post_json(_OSV_QUERY_URL, payload)
        if response is None:
            break

        vulns: list[dict] = response.get("vulns", [])
        next_page_token: str | None = response.get("next_page_token")

        stop_early = False
        for vuln in vulns:
            published_str = vuln.get("published", "")
            if published_str:
                try:
                    pub_dt = datetime.fromisoformat(
                        published_str.replace("Z", "+00:00")
                    )
                    if pub_dt < cutoff:
                        # OSV는 정렬 순서가 보장되지 않으므로 건너뜀
                        continue
                except ValueError:
                    pass

            entry = _parse_osv_entry(vuln, ecosystem)
            if entry is not None:
                results.append(entry)

        page += 1

        if not next_page_token or not vulns:
            break

        page_token = next_page_token

    logger.info("[OSV] %s: %d개 취약점 수집 완료", ecosystem, len(results))
    return results


def fetch_all_ecosystems(since_hours: int = 1) -> list[CVEEntry]:
    """모든 지원 에코시스템에서 취약점을 가져온다.

    각 에코시스템 사이에 rate limit 대기를 적용한다.

    Args:
        since_hours: 몇 시간 이전부터 조회할지.

    Returns:
        중복 제거된 CVEEntry 목록.
    """
    all_entries: list[CVEEntry] = []
    seen_ids: set[str] = set()

    for idx, ecosystem in enumerate(SUPPORTED_ECOSYSTEMS):
        if idx > 0:
            time.sleep(_REQUEST_DELAY)

        entries = fetch_recent(ecosystem=ecosystem, since_hours=since_hours)
        for entry in entries:
            if entry.id not in seen_ids:
                seen_ids.add(entry.id)
                all_entries.append(entry)

    logger.info("[OSV] 전체 에코시스템 합계 %d개 (중복 제거)", len(all_entries))
    return all_entries


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    entries = fetch_recent(ecosystem="npm", since_hours=24)
    for e in entries[:20]:
        print(f"{e.id} [{e.severity.upper()}] {e.title[:80]}")
    print(f"\n총 {len(entries)}개")
