"""SupplyChainWatcher — 소프트웨어 공급망 감시.

소스:
    - npm (https://registry.npmjs.org): 타이포스쿼팅 패키지 탐지
    - PyPI (https://pypi.org/pypi/{package}/json): 버전 변경 및 취약 버전 탐지
    - GitHub Advisory Database: 에코시스템별 어드바이저리 조회 (GraphQL 없이 REST 활용)

탐지 유형:
    - 타이포스쿼팅 패키지 → high 알림
    - 사용 중인 취약 버전 → medium 알림
    - 새로 발행된 의심 패키지 → medium 알림

동작:
    fetch()  → 타겟의 알려진 의존성을 기반으로 레지스트리 조회
    match()  → 타이포스쿼팅/취약 버전/의심 패키지 분류
    act()    → 영향받는 타겟에 대한 어드바이저리 생성 (로그)
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import BaseWatcher, WatcherAlert, register_watcher

logger = logging.getLogger(__name__)

# agent_memory.json 기본 위치
_MEMORY_PATH = Path(__file__).parent.parent / "data" / "agent_memory.json"

# npm Search API
_NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"

# PyPI JSON API
_PYPI_JSON_URL = "https://pypi.org/pypi/{package}/json"

# GitHub Advisory REST API (GraphQL 없이 사용 가능)
_GHSA_URL = "https://api.github.com/advisories"

# 타이포스쿼팅 탐지: 편집 거리 임계값
_TYPO_EDIT_DISTANCE = 2

# 의심 패키지 패턴 (이름에 포함된 경우)
_SUSPICIOUS_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"evil|malware|hack|steal|inject|payload", re.IGNORECASE),
    re.compile(r"-test$|-dev$|-debug$", re.IGNORECASE),
    re.compile(r"^test-|^debug-|^dev-", re.IGNORECASE),
]

# 어드바이저리 출력 디렉터리
_ADVISORY_DIR = Path("~/.vxis/advisories").expanduser()


# ── 유틸리티 함수 ──────────────────────────────────────────────────────────


def _levenshtein(s1: str, s2: str) -> int:
    """두 문자열 간의 Levenshtein 편집 거리를 계산한다.

    stdlib만 사용하는 단순 DP 구현.
    """
    m, n = len(s1), len(s2)
    # 짧은 문자열 기준 early exit
    if abs(m - n) > _TYPO_EDIT_DISTANCE:
        return abs(m - n)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if s1[i - 1] == s2[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]


def _is_typosquatting(candidate: str, known_packages: list[str]) -> tuple[bool, str]:
    """후보 패키지가 알려진 패키지의 타이포스쿼팅인지 확인한다.

    Returns:
        (is_typo, original_package_name) 튜플.
    """
    c_lower = candidate.lower()
    for pkg in known_packages:
        p_lower = pkg.lower()
        if c_lower == p_lower:
            # 완전 일치 → 타이포스쿼팅 아님
            continue
        # 길이 차이가 너무 크면 건너뜀
        if abs(len(c_lower) - len(p_lower)) > _TYPO_EDIT_DISTANCE:
            continue
        dist = _levenshtein(c_lower, p_lower)
        if 0 < dist <= _TYPO_EDIT_DISTANCE:
            return True, pkg
    return False, ""


def _has_suspicious_pattern(package_name: str) -> bool:
    """패키지 이름이 의심스러운 패턴을 포함하는지 확인한다."""
    return any(p.search(package_name) for p in _SUSPICIOUS_PATTERNS)


def _load_target_packages(ecosystem: str) -> dict[str, list[str]]:
    """agent_memory.json에서 에코시스템별 패키지 목록을 반환한다.

    Returns:
        {target_url: [package_name, ...]} 딕셔너리.
    """
    if not _MEMORY_PATH.exists():
        logger.debug("[SupplyChain] agent_memory.json 없음: %s", _MEMORY_PATH)
        return {}
    try:
        data = json.loads(_MEMORY_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("[SupplyChain] agent_memory.json 로드 실패: %s", exc)
        return {}

    result: dict[str, list[str]] = {}
    targets = data.get("targets", {})
    if not isinstance(targets, dict):
        return result

    eco_lower = ecosystem.lower()
    for target_url, info in targets.items():
        if not isinstance(info, dict):
            continue
        packages_map: dict[str, list[str]] = info.get("packages", {})
        if not isinstance(packages_map, dict):
            continue
        for eco_key, pkgs in packages_map.items():
            if eco_key.lower() == eco_lower:
                result[target_url] = [str(p) for p in pkgs if p]
    return result


def _all_known_packages(ecosystem: str) -> list[str]:
    """에코시스템의 모든 타겟에 걸친 패키지 이름 목록 (중복 제거)."""
    by_target = _load_target_packages(ecosystem)
    seen: set[str] = set()
    result: list[str] = []
    for pkgs in by_target.values():
        for p in pkgs:
            if p not in seen:
                seen.add(p)
                result.append(p)
    return result


@register_watcher
class SupplyChainWatcher(BaseWatcher):
    """소프트웨어 공급망 감시 워처.

    npm, PyPI 레지스트리와 GitHub Advisory를 폴링하여
    타겟의 알려진 의존성에 대한 위협을 탐지한다.
    """

    name = "supply_chain"
    icon = "\U0001f4e6"  # 📦
    poll_interval = 3600  # 1시간

    # ── fetch ─────────────────────────────────────────────────────────

    async def fetch(self) -> list[dict[str, Any]]:
        """npm, PyPI, GitHub Advisory에서 위협 정보를 수집한다."""
        items: list[dict[str, Any]] = []

        loop = asyncio.get_event_loop()

        # 1. npm 타이포스쿼팅 탐지
        npm_items = await loop.run_in_executor(None, self._fetch_npm_typosquats)
        items.extend(npm_items)
        logger.info("[SupplyChain] npm: %d개 후보 수집", len(npm_items))

        # 2. PyPI 버전 및 취약점 확인
        pypi_items = await loop.run_in_executor(None, self._fetch_pypi_advisories)
        items.extend(pypi_items)
        logger.info("[SupplyChain] PyPI: %d개 항목 수집", len(pypi_items))

        # 3. GitHub Advisory
        ghsa_items = await loop.run_in_executor(None, self._fetch_github_advisories)
        items.extend(ghsa_items)
        logger.info("[SupplyChain] GitHub Advisory: %d개 수집", len(ghsa_items))

        return items

    def _fetch_npm_typosquats(self) -> list[dict[str, Any]]:
        """npm Search API를 사용해 타겟 패키지와 유사한 이름의 패키지를 탐지한다.

        각 알려진 패키지에 대해 유사 이름으로 검색하고 편집 거리로 타이포스쿼팅 판별.
        """
        known_packages = _all_known_packages("npm")
        if not known_packages:
            return []

        items: list[dict[str, Any]] = []

        for pkg_name in known_packages[:20]:  # 레이트 리밋 고려, 최대 20개
            params = urllib.parse.urlencode(
                {
                    "text": pkg_name,
                    "size": 10,
                }
            )
            url = f"{_NPM_SEARCH_URL}?{params}"
            resp = self._http_get(url, timeout=15)

            if not isinstance(resp, dict):
                continue

            for obj in resp.get("objects", []):
                pkg = obj.get("package", {})
                candidate_name: str = pkg.get("name", "")
                if not candidate_name or candidate_name == pkg_name:
                    continue

                is_typo, original = _is_typosquatting(candidate_name, known_packages)
                is_suspicious = _has_suspicious_pattern(candidate_name)

                if not is_typo and not is_suspicious:
                    continue

                pkg_version: str = pkg.get("version", "")
                pkg_description: str = pkg.get("description", "")
                pkg_date: str = pkg.get("date", "")
                publisher: str = (pkg.get("publisher") or {}).get("username", "")
                item_id = f"npm_candidate_{candidate_name}"

                items.append(
                    {
                        "id": item_id,
                        "ecosystem": "npm",
                        "candidate_package": candidate_name,
                        "original_package": original,
                        "version": pkg_version,
                        "description": pkg_description,
                        "published_at": pkg_date,
                        "publisher": publisher,
                        "is_typosquatting": is_typo,
                        "is_suspicious_pattern": is_suspicious,
                        "source": "npm_registry",
                        "link": f"https://www.npmjs.com/package/{urllib.parse.quote(candidate_name)}",
                    }
                )

        return items

    def _fetch_pypi_advisories(self) -> list[dict[str, Any]]:
        """PyPI JSON API로 타겟 패키지의 취약 버전 및 변경 사항을 확인한다."""
        known_packages = _all_known_packages("pypi")
        if not known_packages:
            return []

        items: list[dict[str, Any]] = []

        for pkg_name in known_packages[:20]:
            url = _PYPI_JSON_URL.format(package=urllib.parse.quote(pkg_name))
            resp = self._http_get(url, timeout=15)
            if not isinstance(resp, dict):
                continue

            info: dict[str, Any] = resp.get("info", {})
            vulnerabilities: list[dict[str, Any]] = resp.get("vulnerabilities", [])

            if not vulnerabilities:
                continue

            latest_version: str = info.get("version", "")
            pkg_url: str = info.get("package_url", f"https://pypi.org/project/{pkg_name}")

            for vuln in vulnerabilities:
                vuln_id: str = vuln.get("id", "")
                aliases: list[str] = vuln.get("aliases", [])
                details: str = vuln.get("details", "")
                fixed_in: list[str] = vuln.get("fixed_in", [])
                withdrawn: str | None = vuln.get("withdrawn")

                # 철회된 어드바이저리는 건너뜀
                if withdrawn:
                    continue

                item_id = f"pypi_vuln_{pkg_name}_{vuln_id}"
                cve_ids = [a for a in aliases if a.startswith("CVE-")]

                items.append(
                    {
                        "id": item_id,
                        "ecosystem": "pypi",
                        "package": pkg_name,
                        "latest_version": latest_version,
                        "vuln_id": vuln_id,
                        "cve_ids": cve_ids,
                        "details": details[:500],
                        "fixed_in": fixed_in,
                        "source": "pypi_advisory",
                        "link": pkg_url,
                    }
                )

        return items

    def _fetch_github_advisories(self) -> list[dict[str, Any]]:
        """GitHub Advisory REST API에서 최근 어드바이저리를 수집한다.

        npm, PyPI 에코시스템을 대상으로 각 타겟 패키지와 관련된 어드바이저리 조회.
        """
        import os

        github_token = os.environ.get("GITHUB_TOKEN", "")
        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"

        items: list[dict[str, Any]] = []

        for ecosystem in ("npm", "pip"):
            known = _all_known_packages("npm" if ecosystem == "npm" else "pypi")
            if not known:
                continue

            params = urllib.parse.urlencode(
                {
                    "ecosystem": ecosystem,
                    "per_page": 30,
                    "sort": "updated",
                    "direction": "desc",
                }
            )
            url = f"{_GHSA_URL}?{params}"

            resp = self._http_get(url, headers=headers, timeout=20)
            if not isinstance(resp, list):
                continue

            for advisory in resp:
                if not isinstance(advisory, dict):
                    continue

                ghsa_id: str = advisory.get("ghsa_id", "")
                summary: str = advisory.get("summary", "")
                severity: str = advisory.get("severity", "unknown")
                cve_id: str = advisory.get("cve_id") or ""
                published_at: str = advisory.get("published_at", "")
                html_url: str = advisory.get("html_url", "")

                # 영향받는 패키지 목록 추출
                affected_pkgs: list[str] = []
                for vuln in advisory.get("vulnerabilities", []):
                    pkg_info = vuln.get("package", {})
                    pkg_name = pkg_info.get("name", "")
                    if pkg_name:
                        affected_pkgs.append(pkg_name.lower())

                # 타겟 패키지와 교집합 확인
                known_lower = {p.lower() for p in known}
                matched_pkgs = [p for p in affected_pkgs if p in known_lower]
                if not matched_pkgs:
                    continue

                item_id = f"ghsa_{ghsa_id}_{ecosystem}"
                items.append(
                    {
                        "id": item_id,
                        "ecosystem": ecosystem,
                        "ghsa_id": ghsa_id,
                        "cve_id": cve_id,
                        "summary": summary,
                        "severity": severity,
                        "published_at": published_at,
                        "affected_packages": affected_pkgs,
                        "matched_packages": matched_pkgs,
                        "source": "github_advisory",
                        "link": html_url,
                    }
                )

        return items

    # ── match ─────────────────────────────────────────────────────────

    async def match(self, items: list[dict[str, Any]]) -> list[WatcherAlert]:
        """수집된 항목을 분류하여 위협 알림을 생성한다."""
        alerts: list[WatcherAlert] = []

        for item in items:
            source: str = item.get("source", "")
            ecosystem: str = item.get("ecosystem", "")

            if source == "npm_registry":
                alert = self._match_npm_item(item)
            elif source == "pypi_advisory":
                alert = self._match_pypi_item(item, ecosystem)
            elif source == "github_advisory":
                alert = self._match_ghsa_item(item)
            else:
                continue

            if alert:
                alerts.append(alert)

        logger.info("[SupplyChain] 매칭 결과: %d / %d", len(alerts), len(items))
        return alerts

    def _match_npm_item(self, item: dict[str, Any]) -> WatcherAlert | None:
        """npm 타이포스쿼팅/의심 패키지 알림 생성."""
        candidate: str = item.get("candidate_package", "")
        original: str = item.get("original_package", "")
        is_typo: bool = item.get("is_typosquatting", False)
        is_suspicious: bool = item.get("is_suspicious_pattern", False)

        if is_typo:
            severity = "high"
            title = f"[공급망] npm 타이포스쿼팅 탐지: {candidate} (원본: {original})"
            desc_lines = [
                f"의심 패키지: {candidate}",
                f"원본 패키지: {original}",
                f"버전: {item.get('version', '알 수 없음')}",
                f"설명: {item.get('description', '없음')[:200]}",
                f"게시자: {item.get('publisher', '알 수 없음')}",
                f"링크: {item.get('link', '')}",
                "타이포스쿼팅 패키지를 의존성 파일에서 즉시 확인하세요.",
            ]
        elif is_suspicious:
            severity = "medium"
            title = f"[공급망] npm 의심 패키지 탐지: {candidate}"
            desc_lines = [
                f"패키지: {candidate}",
                "의심 사유: 이름 패턴 이상",
                f"버전: {item.get('version', '알 수 없음')}",
                f"링크: {item.get('link', '')}",
            ]
        else:
            return None

        # 영향받는 타겟 URL 조회
        target_pkgs = _load_target_packages("npm")
        affected_targets = [
            url for url, pkgs in target_pkgs.items() if original in pkgs or candidate in pkgs
        ]
        target_display = affected_targets[0] if affected_targets else "npm 생태계"

        return WatcherAlert(
            watcher_name=self.name,
            severity=severity,
            title=title,
            description="\n".join(desc_lines),
            target=target_display,
            source_url=item.get("link", ""),
            data={
                "ecosystem": "npm",
                "candidate_package": candidate,
                "original_package": original,
                "version": item.get("version", ""),
                "publisher": item.get("publisher", ""),
                "affected_targets": affected_targets,
            },
            actionable=True,
        )

    def _match_pypi_item(self, item: dict[str, Any], ecosystem: str) -> WatcherAlert | None:
        """PyPI 취약 버전 알림 생성."""
        pkg_name: str = item.get("package", "")
        vuln_id: str = item.get("vuln_id", "")
        cve_ids: list[str] = item.get("cve_ids", [])
        details: str = item.get("details", "")
        fixed_in: list[str] = item.get("fixed_in", [])
        latest_version: str = item.get("latest_version", "")

        cve_str = ", ".join(cve_ids) if cve_ids else vuln_id or "알 수 없음"
        fixed_str = ", ".join(fixed_in) if fixed_in else "없음 (미패치)"

        target_pkgs = _load_target_packages("pypi")
        affected_targets = [url for url, pkgs in target_pkgs.items() if pkg_name in pkgs]
        target_display = affected_targets[0] if affected_targets else "PyPI 생태계"

        return WatcherAlert(
            watcher_name=self.name,
            severity="medium",
            title=f"[공급망] PyPI 취약 패키지: {pkg_name} ({cve_str})",
            description="\n".join(
                [
                    f"패키지: {pkg_name}",
                    f"현재 버전: {latest_version}",
                    f"취약점 ID: {cve_str}",
                    f"수정 버전: {fixed_str}",
                    f"상세: {details[:300]}",
                    f"링크: {item.get('link', '')}",
                ]
            ),
            target=target_display,
            source_url=item.get("link", ""),
            data={
                "ecosystem": "pypi",
                "package": pkg_name,
                "vuln_id": vuln_id,
                "cve_ids": cve_ids,
                "fixed_in": fixed_in,
                "affected_targets": affected_targets,
            },
            actionable=True,
        )

    def _match_ghsa_item(self, item: dict[str, Any]) -> WatcherAlert | None:
        """GitHub Advisory 알림 생성."""
        ghsa_id: str = item.get("ghsa_id", "")
        cve_id: str = item.get("cve_id", "")
        summary: str = item.get("summary", "")
        severity_raw: str = item.get("severity", "medium")
        matched_pkgs: list[str] = item.get("matched_packages", [])
        ecosystem: str = item.get("ecosystem", "")

        # GitHub Advisory severity를 VXIS severity로 매핑
        severity_map = {
            "critical": "critical",
            "high": "high",
            "moderate": "medium",
            "medium": "medium",
            "low": "low",
        }
        severity = severity_map.get(severity_raw.lower(), "medium")

        id_display = cve_id or ghsa_id
        pkgs_str = ", ".join(matched_pkgs[:5])

        ecosystem_key = "npm" if ecosystem == "npm" else "pypi"
        target_pkgs = _load_target_packages(ecosystem_key)
        affected_targets: list[str] = []
        for url, pkgs in target_pkgs.items():
            pkgs_lower = {p.lower() for p in pkgs}
            if any(mp in pkgs_lower for mp in matched_pkgs):
                affected_targets.append(url)

        target_display = affected_targets[0] if affected_targets else f"{ecosystem} 생태계"

        return WatcherAlert(
            watcher_name=self.name,
            severity=severity,
            title=f"[공급망] {ecosystem} 어드바이저리: {id_display} — {summary[:80]}",
            description="\n".join(
                [
                    f"어드바이저리: {ghsa_id}",
                    f"CVE: {cve_id or '없음'}",
                    f"에코시스템: {ecosystem}",
                    f"영향 패키지: {pkgs_str}",
                    f"요약: {summary[:400]}",
                    f"링크: {item.get('link', '')}",
                ]
            ),
            target=target_display,
            source_url=item.get("link", ""),
            data={
                "ecosystem": ecosystem,
                "ghsa_id": ghsa_id,
                "cve_id": cve_id,
                "matched_packages": matched_pkgs,
                "severity_raw": severity_raw,
                "affected_targets": affected_targets,
            },
            actionable=bool(matched_pkgs),
        )

    # ── act ───────────────────────────────────────────────────────────

    async def act(self, alerts: list[WatcherAlert]) -> int:
        """영향받는 타겟에 대한 어드바이저리 파일을 생성한다.

        ~/.vxis/advisories/{target_host}/{timestamp}_{watcher}.json 형태로 저장.
        """
        _ADVISORY_DIR.mkdir(parents=True, exist_ok=True)
        actions = 0
        now_str = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        for alert in alerts:
            if not alert.actionable:
                continue

            affected_targets: list[str] = alert.data.get("affected_targets", [])
            if not affected_targets:
                # 타겟 특정 불가 시 공통 디렉터리에 저장
                affected_targets = ["_global"]

            for target_url in affected_targets:
                # 파일 시스템 안전한 디렉터리명 생성
                safe_target = re.sub(r"[^\w\-.]", "_", target_url)[:60]
                target_dir = _ADVISORY_DIR / safe_target
                target_dir.mkdir(parents=True, exist_ok=True)

                advisory_file = target_dir / f"{now_str}_supply_chain.json"
                advisory_data = {
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "watcher": self.name,
                    "target": target_url,
                    "severity": alert.severity,
                    "title": alert.title,
                    "description": alert.description,
                    "source_url": alert.source_url,
                    "data": alert.data,
                    "recommendation": _build_recommendation(alert),
                }

                try:
                    advisory_file.write_text(
                        json.dumps(advisory_data, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    logger.info("[SupplyChain] 어드바이저리 생성: %s", advisory_file)
                    actions += 1
                except OSError as exc:
                    logger.warning("[SupplyChain] 어드바이저리 저장 실패: %s", exc)

        return actions


def _build_recommendation(alert: WatcherAlert) -> str:
    """알림 유형에 맞는 권고사항 텍스트를 생성한다."""
    data = alert.data
    ecosystem = data.get("ecosystem", "")

    if data.get("candidate_package"):
        # 타이포스쿼팅
        original = data.get("original_package", "")
        candidate = data.get("candidate_package", "")
        return (
            f"의심 패키지 '{candidate}'를 즉시 확인하세요. "
            f"'{original}'를 정확히 사용 중인지 package.json 또는 requirements.txt를 검토하세요. "
            "CI/CD 파이프라인의 의존성 감사 도구(npm audit, pip-audit)를 실행하세요."
        )
    elif data.get("fixed_in"):
        # PyPI/GHSA 취약 버전
        fixed_in = ", ".join(data.get("fixed_in", []))
        pkg = data.get("package", "")
        return (
            f"'{pkg}'를 수정 버전({fixed_in}) 이상으로 즉시 업그레이드하세요. "
            "의존성 잠금 파일(package-lock.json, poetry.lock 등)도 함께 업데이트하세요."
        )
    elif ecosystem == "npm":
        return "npm audit 명령으로 전체 의존성 취약점 감사를 실행하세요."
    elif ecosystem in ("pypi", "pip"):
        return "pip-audit 또는 safety 명령으로 전체 의존성 취약점 감사를 실행하세요."
    else:
        return "의존성 잠금 파일을 검토하고 취약 버전을 업그레이드하세요."
