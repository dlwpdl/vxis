"""CertTransparencyWatcher — 인증서 투명성(CT) 로그 감시.

소스:
    - crt.sh: https://crt.sh/?q=%.{domain}&output=json

탐지 유형:
    - 신규 서브도메인 → info 알림 (타겟 프로파일에 추가)
    - 의심 이름 패턴 (login, admin, vpn 등) → medium 알림
    - 비정상 CA의 와일드카드 인증서 → high 알림

동작:
    fetch()  → crt.sh에서 각 타겟 도메인의 인증서 목록 수집
    match()  → 신규 서브도메인 탐지 및 의심 패턴 분류
    act()    → 신규 서브도메인을 agent_memory.json 타겟 프로파일에 추가
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

# crt.sh API 엔드포인트
_CRTSH_URL = "https://crt.sh/"

# 의심 서브도메인 키워드 (피싱/비인가 접근 포인트 지표)
_SUSPICIOUS_KEYWORDS: list[str] = [
    "login", "signin", "logon", "auth",
    "admin", "administrator", "manage", "management", "portal",
    "vpn", "remote", "rdp", "citrix",
    "pay", "payment", "billing", "invoice", "checkout",
    "api", "dev", "staging", "test", "uat", "preprod",
    "mail", "webmail", "owa", "outlook",
    "backup", "ftp", "sftp", "git", "gitlab", "github",
    "jenkins", "jira", "confluence", "sonar",
    "sso", "saml", "oauth", "idp",
]

# 신뢰할 수 있는 CA 목록 (이 외의 CA가 와일드카드 발급 시 high 알림)
_TRUSTED_CAS: frozenset[str] = frozenset({
    "let's encrypt",
    "letsencrypt",
    "digicert",
    "comodo",
    "sectigo",
    "amazon",
    "cloudflare",
    "globalsign",
    "entrust",
    "geotrust",
    "godaddy",
    "google trust services",
    "microsoft",
    "apple",
})


def _extract_base_domain(url: str) -> str:
    """URL 또는 도메인 문자열에서 베이스 도메인을 추출한다.

    예: "https://sub.example.com/path" → "example.com"
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    netloc = urllib.parse.urlparse(url).netloc.lower()
    # 포트 제거
    netloc = netloc.split(":")[0]
    # IP 주소는 그대로 반환
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", netloc):
        return netloc
    # Public suffix 고려 없이 마지막 두 레이블만 추출 (단순화)
    parts = netloc.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return netloc


def _is_wildcard_cert(common_name: str) -> bool:
    """와일드카드 인증서인지 확인한다."""
    return common_name.strip().startswith("*.")


def _is_suspicious_subdomain(subdomain: str) -> str:
    """서브도메인이 의심스러운 패턴을 포함하는지 확인한다.

    Returns:
        매칭된 키워드 문자열. 의심스럽지 않으면 빈 문자열.
    """
    lower = subdomain.lower()
    for keyword in _SUSPICIOUS_KEYWORDS:
        # 단어 경계 또는 구분자로 분리된 경우만 매칭
        if re.search(r"(?:^|[.\-_])" + re.escape(keyword) + r"(?:[.\-_]|$)", lower):
            return keyword
    return ""


def _load_target_domains() -> dict[str, str]:
    """agent_memory.json에서 타겟 URL → 베이스 도메인 맵을 반환한다."""
    if not _MEMORY_PATH.exists():
        logger.debug("[CertTransparency] agent_memory.json 없음: %s", _MEMORY_PATH)
        return {}
    try:
        data = json.loads(_MEMORY_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("[CertTransparency] agent_memory.json 로드 실패: %s", exc)
        return {}

    result: dict[str, str] = {}
    targets = data.get("targets", {})
    if isinstance(targets, dict):
        for target_url in targets:
            base = _extract_base_domain(str(target_url))
            if base:
                result[target_url] = base
    return result


@register_watcher
class CertTransparencyWatcher(BaseWatcher):
    """인증서 투명성 로그 감시 워처.

    crt.sh를 폴링하여 타겟 도메인에 대해 새로 발급된 인증서를 탐지한다.
    피싱 도메인, 비인가 서브도메인, 의심스러운 와일드카드 인증서를 감지한다.
    """

    name = "cert_transparency"
    icon = "\U0001f4dc"  # 📜
    poll_interval = 3600  # 1시간

    # ── fetch ─────────────────────────────────────────────────────────

    async def fetch(self) -> list[dict[str, Any]]:
        """crt.sh에서 각 타겟 도메인의 인증서 목록을 수집한다."""
        target_domain_map = _load_target_domains()
        if not target_domain_map:
            logger.info("[CertTransparency] 감시할 타겟 도메인 없음")
            return []

        all_items: list[dict[str, Any]] = []

        # 도메인별로 순차 조회 (crt.sh rate limit 고려)
        for target_url, base_domain in target_domain_map.items():
            items = await asyncio.get_event_loop().run_in_executor(
                None, lambda d=base_domain, tu=target_url: self._fetch_crtsh(d, tu)
            )
            all_items.extend(items)
            logger.info(
                "[CertTransparency] %s: %d개 인증서 수집", base_domain, len(items)
            )

        return all_items

    def _fetch_crtsh(self, domain: str, target_url: str) -> list[dict[str, Any]]:
        """crt.sh API를 호출하여 도메인의 인증서 목록을 반환한다.

        와일드카드 서브도메인 검색을 위해 %.{domain} 패턴을 사용한다.
        """
        params = urllib.parse.urlencode({
            "q": f"%.{domain}",
            "output": "json",
        })
        url = f"{_CRTSH_URL}?{params}"

        resp = self._http_get(
            url,
            headers={"Accept": "application/json"},
            timeout=30,
        )
        if not isinstance(resp, list):
            logger.debug("[CertTransparency] crt.sh 응답 비정상: %s", type(resp))
            return []

        items: list[dict[str, Any]] = []
        for entry in resp:
            if not isinstance(entry, dict):
                continue

            cert_id = str(entry.get("id", ""))
            common_name = (entry.get("common_name") or entry.get("name_value") or "").strip()
            issuer_name = (entry.get("issuer_name") or "").strip()
            not_before = (entry.get("not_before") or "").strip()
            not_after = (entry.get("not_after") or "").strip()

            if not cert_id or not common_name:
                continue

            # name_value에는 SAN이 줄바꿈으로 구분되어 있을 수 있음
            # 각 SAN을 개별 항목으로 분리
            all_names = [n.strip() for n in common_name.replace("\n", ",").split(",") if n.strip()]
            if not all_names:
                all_names = [common_name]

            for name in all_names:
                item_id = f"crt_{cert_id}_{name}"
                items.append({
                    "id": item_id,
                    "cert_id": cert_id,
                    "common_name": name,
                    "issuer_name": issuer_name,
                    "not_before": not_before,
                    "not_after": not_after,
                    "target_url": target_url,
                    "base_domain": domain,
                    "source": "crtsh",
                })

        return items

    # ── match ─────────────────────────────────────────────────────────

    async def match(self, items: list[dict[str, Any]]) -> list[WatcherAlert]:
        """수집된 인증서를 분석하여 위협 알림을 생성한다.

        - 신규 서브도메인 (처음 보는 것) → info
        - 의심 키워드 포함 서브도메인 → medium
        - 비정상 CA의 와일드카드 인증서 → high
        """
        alerts: list[WatcherAlert] = []

        for item in items:
            common_name: str = item.get("common_name", "")
            issuer_name: str = item.get("issuer_name", "").lower()
            target_url: str = item.get("target_url", "")
            base_domain: str = item.get("base_domain", "")
            not_before: str = item.get("not_before", "")
            cert_id: str = item.get("cert_id", "")

            crtsh_link = f"https://crt.sh/?id={cert_id}" if cert_id else _CRTSH_URL

            # 1. 와일드카드 + 비정상 CA 조합 → high
            if _is_wildcard_cert(common_name):
                issuer_trusted = any(
                    ca in issuer_name for ca in _TRUSTED_CAS
                )
                if not issuer_trusted:
                    alerts.append(WatcherAlert(
                        watcher_name=self.name,
                        severity="high",
                        title=f"[CT] 비정상 CA 와일드카드 인증서: {common_name}",
                        description=(
                            f"도메인: {base_domain}\n"
                            f"인증서 이름: {common_name}\n"
                            f"발급 CA: {item.get('issuer_name', '알 수 없음')}\n"
                            f"발급일: {not_before}\n"
                            f"신뢰되지 않는 CA가 와일드카드 인증서를 발급했습니다."
                        ),
                        target=target_url,
                        source_url=crtsh_link,
                        data={
                            "cert_id": cert_id,
                            "common_name": common_name,
                            "issuer_name": item.get("issuer_name", ""),
                            "not_before": not_before,
                            "is_wildcard": True,
                        },
                        actionable=False,
                    ))
                    continue

            # 2. 의심 키워드 서브도메인 → medium
            suspicious_kw = _is_suspicious_subdomain(common_name)
            if suspicious_kw:
                alerts.append(WatcherAlert(
                    watcher_name=self.name,
                    severity="medium",
                    title=f"[CT] 의심 서브도메인 인증서: {common_name}",
                    description=(
                        f"도메인: {base_domain}\n"
                        f"인증서 이름: {common_name}\n"
                        f"의심 키워드: {suspicious_kw}\n"
                        f"발급 CA: {item.get('issuer_name', '알 수 없음')}\n"
                        f"발급일: {not_before}\n"
                        f"피싱 또는 비인가 접근 포인트일 수 있습니다."
                    ),
                    target=target_url,
                    source_url=crtsh_link,
                    data={
                        "cert_id": cert_id,
                        "common_name": common_name,
                        "suspicious_keyword": suspicious_kw,
                        "issuer_name": item.get("issuer_name", ""),
                        "not_before": not_before,
                    },
                    actionable=True,  # 서브도메인 스캔 대상으로 추가
                ))
                continue

            # 3. 신규 서브도메인 → info
            # (이미 _filter_seen을 통해 이전 실행에서 본 항목은 제거됨)
            if common_name and not common_name.startswith("*."):
                alerts.append(WatcherAlert(
                    watcher_name=self.name,
                    severity="info",
                    title=f"[CT] 신규 서브도메인 탐지: {common_name}",
                    description=(
                        f"도메인: {base_domain}\n"
                        f"신규 서브도메인: {common_name}\n"
                        f"발급 CA: {item.get('issuer_name', '알 수 없음')}\n"
                        f"발급일: {not_before}\n"
                        f"타겟 프로파일에 추가하여 향후 스캔에 포함합니다."
                    ),
                    target=target_url,
                    source_url=crtsh_link,
                    data={
                        "cert_id": cert_id,
                        "common_name": common_name,
                        "issuer_name": item.get("issuer_name", ""),
                        "not_before": not_before,
                        "new_subdomain": common_name,
                    },
                    actionable=True,  # 타겟 프로파일 업데이트
                ))

        logger.info("[CertTransparency] 매칭 결과: %d / %d", len(alerts), len(items))
        return alerts

    # ── act ───────────────────────────────────────────────────────────

    async def act(self, alerts: list[WatcherAlert]) -> int:
        """신규 서브도메인을 agent_memory.json 타겟 프로파일에 추가한다.

        actionable=True인 알림에서 new_subdomain 값을 추출하여
        해당 타겟의 "subdomains" 필드에 기록한다.
        """
        if not _MEMORY_PATH.exists():
            return 0

        try:
            data = json.loads(_MEMORY_PATH.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("[CertTransparency] agent_memory.json 로드 실패 (act): %s", exc)
            return 0

        targets: dict[str, Any] = data.get("targets", {})
        if not isinstance(targets, dict):
            return 0

        actions = 0
        changed = False

        for alert in alerts:
            if not alert.actionable:
                continue
            new_subdomain: str = alert.data.get("new_subdomain", "")
            if not new_subdomain:
                continue
            target_url = alert.target

            if target_url not in targets:
                continue

            target_info = targets[target_url]
            if not isinstance(target_info, dict):
                continue

            subdomains: list[str] = target_info.setdefault("subdomains", [])
            if new_subdomain not in subdomains:
                subdomains.append(new_subdomain)
                logger.info(
                    "[CertTransparency] 신규 서브도메인 추가: %s → %s",
                    target_url, new_subdomain,
                )
                actions += 1
                changed = True

        if changed:
            try:
                _MEMORY_PATH.write_text(
                    json.dumps(data, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                logger.info("[CertTransparency] agent_memory.json 업데이트 완료 (%d개 추가)", actions)
            except OSError as exc:
                logger.warning("[CertTransparency] agent_memory.json 저장 실패: %s", exc)
                return 0

        return actions
