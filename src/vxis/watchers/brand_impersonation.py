"""브랜드 사칭 감시 — 유사 도메인, 피싱 인프라, 가짜 저장소를 탐지한다.

감지 소스:
    - dnstwist: 타이포스쿼팅 도메인 탐지 (미설치 시 건너뜀)
    - crt.sh: 유사 도메인에 발급된 SSL 인증서 조회
    - GitHub Search API: 브랜드를 사칭하는 저장소 탐색

심각도 판단:
    - MX 레코드 보유 유사 도메인: critical (이메일 피싱 가능)
    - 활성 웹 콘텐츠 + SSL 유사 도메인: high
    - SSL 인증서만 있는 유사 도메인: high
    - GitHub 사칭 저장소: medium
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import BaseWatcher, WatcherAlert, register_watcher

logger = logging.getLogger(__name__)

# agent_memory.json 위치
_MEMORY_PATH = Path(__file__).parent.parent / "data" / "agent_memory.json"

# dnstwist 실행 타임아웃 (초)
_DNSTWIST_TIMEOUT = 180

# HTTP 확인 타임아웃 (초)
_HTTP_TIMEOUT = 10

# crt.sh API
_CRTSH_API = "https://crt.sh/?q={domain}&output=json"

# GitHub Search API
_GITHUB_SEARCH_API = "https://api.github.com/search/repositories?q={query}&sort=updated&per_page=20"

# 보고서 저장 디렉토리
_REPORT_DIR = Path("~/.vxis/takedown_reports").expanduser()


def _load_brand_targets() -> list[dict[str, str]]:
    """agent_memory.json에서 브랜드/도메인 목록을 반환한다.

    Returns:
        [{"target": "https://example.com", "brand": "example", "domain": "example.com"}, ...]
    """
    if not _MEMORY_PATH.exists():
        logger.debug("[BrandImpersonation] agent_memory.json 없음: %s", _MEMORY_PATH)
        return []

    try:
        data = json.loads(_MEMORY_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("[BrandImpersonation] agent_memory.json 로드 실패: %s", exc)
        return []

    targets: list[dict[str, str]] = []

    # 형식 1: {"targets": {"url": {...}}}
    raw_targets = data.get("targets", {})
    if isinstance(raw_targets, dict):
        for target_url in raw_targets.keys():
            domain = _extract_domain(target_url)
            if domain:
                brand = _extract_brand(domain)
                targets.append({
                    "target": target_url,
                    "domain": domain,
                    "brand": brand,
                })

    # 형식 2: {"scans": [{"target": "..."}]}
    for scan in data.get("scans", []):
        if isinstance(scan, dict) and scan.get("target"):
            domain = _extract_domain(scan["target"])
            if domain:
                brand = _extract_brand(domain)
                targets.append({
                    "target": scan["target"],
                    "domain": domain,
                    "brand": brand,
                })

    # 도메인 기준 중복 제거
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for t in targets:
        if t["domain"] not in seen:
            seen.add(t["domain"])
            unique.append(t)

    return unique


def _extract_domain(url: str) -> str:
    """URL에서 루트 도메인을 추출한다."""
    host = url.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split("?")[0]
    if ":" in host and not host.startswith("["):
        host = host.rsplit(":", 1)[0]
    # www 제거
    if host.startswith("www."):
        host = host[4:]
    return host.lower()


def _extract_brand(domain: str) -> str:
    """도메인에서 브랜드명(SLD)을 추출한다. example.com → example"""
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0] if parts else domain


def _make_item_id(source: str, domain: str) -> str:
    """항목 고유 ID 생성."""
    raw = f"{source}:{domain}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _run_dnstwist(domain: str) -> list[dict[str, Any]]:
    """dnstwist로 타이포스쿼팅 유사 도메인을 탐지한다.

    Returns:
        [{"fuzzer": "...", "domain": "...", "dns_a": [...], "dns_mx": [...], ...}, ...]
    """
    if not shutil.which("dnstwist"):
        logger.debug("[BrandImpersonation] dnstwist 미설치, 건너뜀")
        return []

    cmd = [
        "dnstwist",
        "--format", "json",
        "--registered",   # 등록된 도메인만 출력
        "--threads", "8",
        domain,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_DNSTWIST_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[BrandImpersonation] dnstwist 타임아웃: %s", domain)
        return []
    except Exception as exc:
        logger.warning("[BrandImpersonation] dnstwist 실행 실패 (%s): %s", domain, exc)
        return []

    if not proc.stdout.strip():
        return []

    try:
        results = json.loads(proc.stdout)
        if not isinstance(results, list):
            return []
        # 원본 도메인 자신은 제외
        return [r for r in results if r.get("domain", "") != domain]
    except json.JSONDecodeError:
        logger.debug("[BrandImpersonation] dnstwist JSON 파싱 실패: %s", domain)
        return []


def _check_crtsh(domain: str) -> list[dict[str, Any]]:
    """crt.sh에서 유사 도메인에 발급된 인증서를 조회한다.

    Args:
        domain: 검색할 루트 도메인 (예: example.com)

    Returns:
        [{"name_value": "...", "issuer_name": "...", "not_before": "..."}, ...]
    """
    # 와일드카드 + 유사 패턴 검색: %.example.com 은 서브도메인, %example% 는 유사 도메인
    brand = _extract_brand(domain)
    # brand 포함 모든 도메인 인증서 조회 (원본 제외는 match 단계에서)
    url = _CRTSH_API.format(domain=f"%{brand}%")

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "VXIS-BrandWatch/1.0",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
            data = json.loads(body)
            if not isinstance(data, list):
                return []
            return data
    except Exception as exc:
        logger.debug("[BrandImpersonation] crt.sh 조회 실패 (%s): %s", domain, exc)
        return []


def _check_github(brand: str) -> list[dict[str, Any]]:
    """GitHub에서 브랜드를 사칭하는 저장소를 검색한다."""
    github_token = __import__("os").environ.get("GITHUB_TOKEN", "")
    headers: dict[str, str] = {
        "User-Agent": "VXIS-BrandWatch/1.0",
        "Accept": "application/vnd.github.v3+json",
    }
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"

    # 사칭 패턴 키워드로 검색
    query = f"{brand}+official+OR+{brand}-app+OR+{brand}-login+OR+{brand}-wallet"
    url = _GITHUB_SEARCH_API.format(query=urllib.request.quote(query))

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("items", [])
    except Exception as exc:
        logger.debug("[BrandImpersonation] GitHub 검색 실패 (%s): %s", brand, exc)
        return []


def _has_active_web(domain: str) -> bool:
    """도메인에 활성 웹 서버가 있는지 확인한다."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "VXIS-BrandWatch/1.0"},
            method="HEAD",
        )
        try:
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
                if resp.status < 500:
                    return True
        except urllib.error.HTTPError as e:
            if e.code < 500:
                return True
        except Exception:
            continue
    return False


def _generate_takedown_report(alert: WatcherAlert) -> str:
    """테이크다운 요청 보고서 템플릿을 생성한다."""
    now = datetime.now(timezone.utc).isoformat()
    lookalike = alert.data.get("lookalike_domain", "")
    source = alert.data.get("source", "")

    report = f"""VXIS Brand Impersonation Takedown Report
==========================================
생성일시: {now}
원본 타겟: {alert.target}
유사 도메인: {lookalike}
감지 소스: {source}
심각도: {alert.severity.upper()}
설명: {alert.description}

-- 테이크다운 연락처 --
ICANN Registrar Abuse Contact:
  https://lookup.icann.org/en/lookup?name={lookalike}

Google Safe Browsing 신고:
  https://safebrowsing.google.com/safebrowsing/report_phish/

CERT/KR 피싱 신고:
  https://www.krcert.or.kr/main.do

추가 데이터:
{json.dumps(alert.data, ensure_ascii=False, indent=2)}
"""
    return report


@register_watcher
class BrandImpersonationWatcher(BaseWatcher):
    """브랜드 사칭 감시 워처.

    dnstwist, crt.sh, GitHub을 활용해 타겟 브랜드를 사칭하는
    유사 도메인과 저장소를 탐지한다.
    """

    name = "brand_impersonation"
    icon = "🎭"
    poll_interval = 43200  # 12시간

    async def fetch(self) -> list[dict[str, Any]]:
        """dnstwist, crt.sh, GitHub에서 사칭 후보를 수집한다."""
        brand_targets = _load_brand_targets()
        if not brand_targets:
            logger.info("[BrandImpersonation] 감시 대상 없음. agent_memory.json을 확인하세요.")
            return []

        items: list[dict[str, Any]] = []
        loop = asyncio.get_event_loop()

        for bt in brand_targets:
            domain = bt["domain"]
            brand = bt["brand"]
            target = bt["target"]

            logger.info("[BrandImpersonation] 스캔: %s (브랜드: %s)", domain, brand)

            # ── dnstwist ──────────────────────────────────────────
            try:
                twist_results = await loop.run_in_executor(None, _run_dnstwist, domain)
                for entry in twist_results:
                    lookalike = entry.get("domain", "")
                    if not lookalike or lookalike == domain:
                        continue
                    items.append({
                        "id": _make_item_id("dnstwist", lookalike),
                        "source": "dnstwist",
                        "origin_domain": domain,
                        "origin_target": target,
                        "brand": brand,
                        "lookalike_domain": lookalike,
                        "fuzzer_type": entry.get("fuzzer", ""),
                        "dns_a": entry.get("dns_a", []),
                        "dns_mx": entry.get("dns_mx", []),
                        "dns_ns": entry.get("dns_ns", []),
                    })
            except Exception as exc:
                logger.warning("[BrandImpersonation] dnstwist 처리 실패 (%s): %s", domain, exc)

            # ── crt.sh ────────────────────────────────────────────
            try:
                crt_results = await loop.run_in_executor(None, _check_crtsh, domain)
                seen_crt: set[str] = set()
                for cert in crt_results:
                    name_value = cert.get("name_value", "").lower().strip()
                    # 멀티SAN 인증서: 개행으로 여러 도메인이 있을 수 있음
                    for cert_domain in name_value.splitlines():
                        cert_domain = cert_domain.strip().lstrip("*.")
                        if not cert_domain or cert_domain == domain:
                            continue
                        # 원본 도메인의 합법적 서브도메인은 건너뜀
                        if cert_domain.endswith(f".{domain}"):
                            continue
                        # 브랜드명이 포함된 외부 도메인만
                        if brand not in cert_domain:
                            continue
                        if cert_domain in seen_crt:
                            continue
                        seen_crt.add(cert_domain)
                        items.append({
                            "id": _make_item_id("crtsh", cert_domain),
                            "source": "crtsh",
                            "origin_domain": domain,
                            "origin_target": target,
                            "brand": brand,
                            "lookalike_domain": cert_domain,
                            "issuer": cert.get("issuer_name", ""),
                            "not_before": cert.get("not_before", ""),
                            "cert_id": str(cert.get("id", "")),
                        })
            except Exception as exc:
                logger.warning("[BrandImpersonation] crt.sh 처리 실패 (%s): %s", domain, exc)

            # ── GitHub ────────────────────────────────────────────
            try:
                gh_results = await loop.run_in_executor(None, _check_github, brand)
                for repo in gh_results:
                    repo_name = repo.get("full_name", "")
                    repo_url = repo.get("html_url", "")
                    if not repo_name:
                        continue
                    items.append({
                        "id": _make_item_id("github", repo_name),
                        "source": "github",
                        "origin_domain": domain,
                        "origin_target": target,
                        "brand": brand,
                        "repo_name": repo_name,
                        "repo_url": repo_url,
                        "repo_description": repo.get("description", "") or "",
                        "stars": repo.get("stargazers_count", 0),
                        "pushed_at": repo.get("pushed_at", ""),
                    })
            except Exception as exc:
                logger.warning("[BrandImpersonation] GitHub 처리 실패 (%s): %s", brand, exc)

        logger.info("[BrandImpersonation] 수집 완료: %d개 후보", len(items))
        return items

    async def match(self, items: list[dict[str, Any]]) -> list[WatcherAlert]:
        """수집된 사칭 후보를 분석하여 위험도에 따라 알림을 생성한다."""
        alerts: list[WatcherAlert] = []
        loop = asyncio.get_event_loop()

        for item in items:
            source = item.get("source", "")
            target = item.get("origin_target", "")

            if source in ("dnstwist", "crtsh"):
                lookalike = item.get("lookalike_domain", "")
                if not lookalike:
                    continue

                dns_mx = item.get("dns_mx", [])
                dns_a = item.get("dns_a", [])
                has_ssl = source == "crtsh" or bool(item.get("cert_id"))

                # MX 레코드 보유 = 이메일 피싱 인프라: critical
                if dns_mx:
                    alerts.append(WatcherAlert(
                        watcher_name=self.name,
                        severity="critical",
                        title=f"피싱 이메일 인프라 감지: {lookalike}",
                        description=(
                            f"유사 도메인 '{lookalike}'이 MX 레코드를 보유하고 있습니다. "
                            f"'{target}' 사용자를 대상으로 한 이메일 피싱 인프라일 수 있습니다. "
                            f"MX: {', '.join(dns_mx[:3])}"
                        ),
                        target=target,
                        source_url=f"https://crt.sh/?q={lookalike}",
                        data={
                            "lookalike_domain": lookalike,
                            "source": source,
                            "dns_mx": dns_mx,
                            "dns_a": dns_a,
                        },
                        actionable=True,
                    ))
                    logger.warning("[BrandImpersonation] 피싱 인프라 감지: %s (MX 보유)", lookalike)

                # 활성 웹 + SSL: high
                elif dns_a:
                    # 활성 웹 여부 확인 (블로킹 I/O)
                    try:
                        is_active = await loop.run_in_executor(None, _has_active_web, lookalike)
                    except Exception:
                        is_active = False

                    if is_active and has_ssl:
                        alerts.append(WatcherAlert(
                            watcher_name=self.name,
                            severity="high",
                            title=f"활성 사칭 사이트 감지: {lookalike}",
                            description=(
                                f"유사 도메인 '{lookalike}'이 활성 HTTPS 사이트를 운영 중입니다. "
                                f"'{target}'을 사칭하는 피싱 사이트일 수 있습니다."
                            ),
                            target=target,
                            source_url=f"https://{lookalike}",
                            data={
                                "lookalike_domain": lookalike,
                                "source": source,
                                "has_ssl": has_ssl,
                                "dns_a": dns_a,
                            },
                            actionable=True,
                        ))
                        logger.warning("[BrandImpersonation] 활성 사칭 사이트: %s", lookalike)

                    elif has_ssl:
                        # SSL만 있는 경우: high
                        alerts.append(WatcherAlert(
                            watcher_name=self.name,
                            severity="high",
                            title=f"유사 도메인 SSL 인증서 발급: {lookalike}",
                            description=(
                                f"유사 도메인 '{lookalike}'에 SSL 인증서가 발급되었습니다. "
                                f"사칭 사이트 준비 중일 가능성이 있습니다."
                            ),
                            target=target,
                            source_url=f"https://crt.sh/?q={lookalike}",
                            data={
                                "lookalike_domain": lookalike,
                                "source": source,
                                "issuer": item.get("issuer", ""),
                                "cert_id": item.get("cert_id", ""),
                            },
                            actionable=True,
                        ))

            elif source == "github":
                repo_name = item.get("repo_name", "")
                repo_url = item.get("repo_url", "")
                brand = item.get("brand", "")

                # 브랜드명이 저장소 이름에 포함되고 최근 활동이 있는 경우
                repo_lower = repo_name.lower()
                if brand.lower() in repo_lower:
                    alerts.append(WatcherAlert(
                        watcher_name=self.name,
                        severity="medium",
                        title=f"GitHub 브랜드 사칭 저장소: {repo_name}",
                        description=(
                            f"GitHub에서 '{brand}' 브랜드를 포함한 저장소 '{repo_name}'가 발견되었습니다. "
                            f"설명: {item.get('repo_description', 'N/A')[:100]}"
                        ),
                        target=target,
                        source_url=repo_url,
                        data={
                            "repo_name": repo_name,
                            "repo_url": repo_url,
                            "stars": item.get("stars", 0),
                            "pushed_at": item.get("pushed_at", ""),
                            "source": source,
                        },
                        actionable=False,
                    ))

        return alerts

    async def act(self, alerts: list[WatcherAlert]) -> int:
        """테이크다운 보고서 템플릿을 생성한다."""
        actionable = [a for a in alerts if a.actionable]
        if not actionable:
            return 0

        _REPORT_DIR.mkdir(parents=True, exist_ok=True)
        reports_generated = 0

        for alert in actionable:
            lookalike = alert.data.get("lookalike_domain", "")
            if not lookalike:
                continue

            report_content = _generate_takedown_report(alert)
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            # 파일명에 사용할 수 없는 문자 제거
            safe_domain = lookalike.replace(".", "_").replace("/", "_")
            report_path = _REPORT_DIR / f"takedown_{safe_domain}_{timestamp}.txt"

            try:
                report_path.write_text(report_content, encoding="utf-8")
                logger.info("[BrandImpersonation] 테이크다운 보고서 생성: %s", report_path)
                reports_generated += 1
            except OSError as exc:
                logger.warning("[BrandImpersonation] 보고서 저장 실패: %s", exc)

        return reports_generated
