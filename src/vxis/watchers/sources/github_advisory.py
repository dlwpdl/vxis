"""GitHub Security Advisory API — 가장 빠른 CVE 알림 소스.

GitHub GraphQL API를 통해 최근 공개된 보안 공지를 가져온다.
`gh` CLI가 설치되어 있고 인증된 경우 사용 가능하며,
없는 경우 이 소스를 자동으로 건너뛴다.

사용 요구사항:
    - GitHub CLI (`gh`) 설치 및 `gh auth login` 완료
    - 또는 GITHUB_TOKEN 환경 변수 설정

Rate limit:
    - 인증된 요청: 5,000 points/hour
    - GraphQL 요청 1회 기본 비용: ~1 point
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from datetime import datetime, timedelta, timezone

from ..cve_entry import CVEEntry

logger = logging.getLogger(__name__)

# GitHub Advisory GraphQL 쿼리
# securityAdvisories는 PUBLISHED_AT 또는 UPDATED_AT 정렬 지원
_GRAPHQL_QUERY = """
query RecentAdvisories($after: String) {
  securityAdvisories(
    first: 50
    orderBy: {field: PUBLISHED_AT, direction: DESC}
    after: $after
  ) {
    nodes {
      ghsaId
      identifiers {
        type
        value
      }
      summary
      description
      severity
      publishedAt
      withdrawnAt
      references {
        url
      }
      cvss {
        score
        vectorString
      }
      vulnerabilities(first: 20) {
        nodes {
          package {
            ecosystem
            name
          }
          vulnerableVersionRange
          firstPatchedVersion {
            identifier
          }
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""


def _check_gh_available() -> bool:
    """gh CLI가 사용 가능한지 확인."""
    try:
        result = subprocess.run(
            ["gh", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _run_graphql(query: str, variables: dict | None = None) -> dict | None:
    """gh CLI를 통해 GraphQL 쿼리를 실행하고 결과를 반환."""
    payload = json.dumps({
        "query": query,
        "variables": variables or {},
    })

    try:
        result = subprocess.run(
            ["gh", "api", "graphql", "--input", "-"],
            input=payload.encode("utf-8"),
            capture_output=True,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[GitHub Advisory] GraphQL 요청 타임아웃")
        return None
    except FileNotFoundError:
        logger.warning("[GitHub Advisory] gh CLI를 찾을 수 없음. 이 소스를 건너뜁니다.")
        return None

    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        logger.warning("[GitHub Advisory] gh API 오류: %s", stderr[:300])
        return None

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        logger.warning("[GitHub Advisory] JSON 파싱 실패: %s", exc)
        return None


def _severity_normalize(github_severity: str) -> str:
    """GitHub Advisory 심각도를 표준 소문자 문자열로 변환."""
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MODERATE": "medium",
        "LOW": "low",
        "UNKNOWN": "unknown",
    }
    return mapping.get(github_severity.upper(), "unknown")


def _extract_cve_id(identifiers: list[dict]) -> str:
    """identifiers 리스트에서 CVE ID를 추출. 없으면 빈 문자열 반환."""
    for ident in identifiers:
        if ident.get("type") == "CVE":
            return ident.get("value", "")
    return ""


def _parse_node(node: dict) -> CVEEntry | None:
    """단일 GraphQL advisory 노드를 CVEEntry로 변환."""
    ghsa_id: str = node.get("ghsaId", "")
    if not ghsa_id:
        return None

    # 철회된 공지는 건너뜀
    if node.get("withdrawnAt"):
        return None

    identifiers: list[dict] = node.get("identifiers", [])
    cve_id = _extract_cve_id(identifiers)

    # CVE ID가 있으면 사용, 없으면 GHSA ID를 기본 식별자로 사용
    entry_id = cve_id if cve_id else ghsa_id

    summary: str = node.get("summary", "")
    description: str = node.get("description", "") or summary

    severity_raw = node.get("severity", "UNKNOWN")
    severity = _severity_normalize(severity_raw)

    cvss_data = node.get("cvss") or {}
    cvss_score: float = float(cvss_data.get("score") or 0.0)

    published_at: str = node.get("publishedAt", "")

    references: list[str] = [
        ref["url"] for ref in node.get("references", []) if ref.get("url")
    ]

    # 영향받는 패키지 정보 수집
    affected_products: list[str] = []
    affected_versions: list[str] = []
    ecosystems: list[str] = []

    for vuln in (node.get("vulnerabilities") or {}).get("nodes", []):
        pkg = vuln.get("package") or {}
        ecosystem = pkg.get("ecosystem", "")
        name = pkg.get("name", "")

        if name:
            product_str = f"{ecosystem}/{name}" if ecosystem else name
            affected_products.append(product_str)

        version_range = vuln.get("vulnerableVersionRange", "")
        if version_range:
            affected_versions.append(version_range)

        patched = (vuln.get("firstPatchedVersion") or {}).get("identifier", "")
        if patched:
            affected_versions.append(f"fixed:{patched}")

        if ecosystem and ecosystem not in ecosystems:
            ecosystems.append(ecosystem)

    # PoC 여부: references에 exploit-db, github PoC 등이 있는지 확인
    exploit_keywords = ("exploit", "poc", "proof-of-concept", "exploit-db")
    poc_url = ""
    exploit_available = False
    for ref_url in references:
        lower = ref_url.lower()
        if any(kw in lower for kw in exploit_keywords):
            exploit_available = True
            if not poc_url:
                poc_url = ref_url

    return CVEEntry(
        id=entry_id,
        source="github",
        title=summary or entry_id,
        description=description,
        severity=severity,
        cvss_score=cvss_score,
        affected_products=affected_products,
        affected_versions=affected_versions,
        published_at=published_at,
        references=references,
        exploit_available=exploit_available,
        poc_url=poc_url,
        ecosystem=",".join(ecosystems),
        raw=node,
    )


def fetch_recent(since_hours: int = 1) -> list[CVEEntry]:
    """최근 N시간 이내에 발행된 GitHub Security Advisory를 가져온다.

    Args:
        since_hours: 몇 시간 이전부터 조회할지 (기본 1시간).

    Returns:
        CVEEntry 목록. gh CLI 미설치 시 빈 리스트 반환.
    """
    if not _check_gh_available():
        logger.info("[GitHub Advisory] gh CLI 없음. 이 소스를 건너뜁니다.")
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(hours=since_hours)
    results: list[CVEEntry] = []
    cursor: str | None = None
    page = 0
    max_pages = 5  # 최대 250개 (50 * 5)

    logger.info("[GitHub Advisory] %d시간 이내 공지 조회 시작", since_hours)

    while page < max_pages:
        variables: dict = {}
        if cursor:
            variables["after"] = cursor

        response = _run_graphql(_GRAPHQL_QUERY, variables)
        if not response:
            break

        data = response.get("data") or {}
        advisories = data.get("securityAdvisories") or {}
        nodes: list[dict] = advisories.get("nodes") or []
        page_info: dict = advisories.get("pageInfo") or {}

        stop = False
        for node in nodes:
            published_str = node.get("publishedAt", "")
            if published_str:
                try:
                    pub_dt = datetime.fromisoformat(
                        published_str.replace("Z", "+00:00")
                    )
                    if pub_dt < cutoff:
                        # 발행 시간순 내림차순 정렬이므로 여기서 중단
                        stop = True
                        break
                except ValueError:
                    pass

            entry = _parse_node(node)
            if entry is not None:
                results.append(entry)

        if stop or not page_info.get("hasNextPage"):
            break

        cursor = page_info.get("endCursor")
        page += 1

    logger.info("[GitHub Advisory] %d개 공지 수집 완료", len(results))
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    entries = fetch_recent(since_hours=24)
    for e in entries:
        print(f"{e.id} [{e.severity.upper()}] {e.title[:80]}")
    print(f"\n총 {len(entries)}개")
