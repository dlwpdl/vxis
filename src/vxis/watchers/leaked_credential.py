"""유출 자격증명 감시 워처 — HIBP + GitHub 유출 이메일/패스워드 탐지.

감시 소스:
    1. Have I Been Pwned (haveibeenpwned.com/api/v3)
       - GET /breaches         — 최근 전체 침해 사고 목록
       - GET /breachedaccount/{email} — 특정 이메일 침해 확인
    2. GitHub Code Search
       - password + 타겟 도메인 — 노출된 자격증명 코드 탐색

환경 변수:
    HIBP_API_KEY    — Have I Been Pwned API 키 (없으면 HIBP 건너뜀)
    GITHUB_TOKEN    — GitHub PAT (없으면 미인증 요청)

agent_memory.json 구조 (참조):
    {
      "targets": [
        { "domain": "example.com", "emails": ["admin@example.com"] }
      ]
    }
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

from .base import BaseWatcher, WatcherAlert, register_watcher

logger = logging.getLogger(__name__)

_AGENT_MEMORY_PATH = Path("~/.vxis/agent_memory.json").expanduser()

# HIBP 요청 간격 (Rate limit: 1 req/1.5s)
_HIBP_REQUEST_DELAY = 1.6


def _load_target_profiles() -> list[dict[str, Any]]:
    """agent_memory.json에서 타겟 프로파일(도메인 + 이메일) 로드."""
    if not _AGENT_MEMORY_PATH.exists():
        logger.warning("[leaked_credential] agent_memory.json 없음: %s", _AGENT_MEMORY_PATH)
        return []
    try:
        data = json.loads(_AGENT_MEMORY_PATH.read_text(encoding="utf-8"))
        profiles: list[dict[str, Any]] = []
        for t in data.get("targets", []):
            if isinstance(t, dict):
                domain = (t.get("domain", "") or t.get("target", "")).strip()
                domain = domain.lstrip("https://").lstrip("http://").rstrip("/")
                emails = t.get("emails", [])
                if domain:
                    profiles.append({"domain": domain, "emails": emails})
            else:
                domain = str(t).strip().lstrip("https://").lstrip("http://").rstrip("/")
                if domain:
                    profiles.append({"domain": domain, "emails": []})
        return profiles
    except Exception as exc:
        logger.warning("[leaked_credential] agent_memory.json 파싱 오류: %s", exc)
        return []


def _mask_password(value: str) -> str:
    """비밀번호 마스킹: 앞 2자 + *** + 뒤 2자."""
    if not value:
        return "***"
    if len(value) <= 4:
        return "***"
    return value[:2] + "***" + value[-2:]


def _extract_domain_from_email(email: str) -> str:
    """이메일에서 도메인 추출."""
    parts = email.split("@")
    return parts[-1].lower() if len(parts) == 2 else ""


@register_watcher
class LeakedCredentialWatcher(BaseWatcher):
    """HIBP와 GitHub에서 타겟 도메인의 유출 자격증명을 감시한다."""

    name = "leaked_credential"
    icon = "🔑"

    @property
    def poll_interval(self) -> int:
        """3시간마다 폴링 (HIBP 신규 침해 사고 주기 고려)."""
        return 10800

    # ── fetch ────────────────────────────────────────────────────

    async def fetch(self) -> list[dict[str, Any]]:
        """HIBP와 GitHub에서 타겟 관련 유출 항목 수집."""
        profiles = _load_target_profiles()
        if not profiles:
            logger.info("[leaked_credential] 타겟 프로파일 없음. 건너뜁니다.")
            return []

        items: list[dict[str, Any]] = []

        hibp_key = os.environ.get("HIBP_API_KEY", "")
        github_token = os.environ.get("GITHUB_TOKEN", "")

        for profile in profiles:
            domain = profile["domain"]
            emails = profile.get("emails", [])

            if hibp_key:
                # 도메인 수준 침해 확인 (최근 전체 침해 목록 대조)
                items.extend(self._fetch_hibp_domain(domain, hibp_key))

                # 개별 이메일 계정 침해 확인
                for email in emails:
                    items.extend(self._fetch_hibp_account(email, domain, hibp_key))
                    # Rate limit 준수
                    time.sleep(_HIBP_REQUEST_DELAY)

            # GitHub 코드 검색
            items.extend(self._fetch_github_credentials(domain, github_token))

        logger.info("[leaked_credential] 수집 완료: %d건", len(items))
        return items

    def _fetch_hibp_domain(
        self, domain: str, api_key: str
    ) -> list[dict[str, Any]]:
        """HIBP 전체 침해 목록에서 타겟 도메인 관련 침해 사고 필터링.

        /breaches 엔드포인트는 모든 침해 사고의 메타데이터를 반환한다.
        도메인이 침해된 서비스의 이름/타이틀과 일치하는지 확인.
        """
        items: list[dict[str, Any]] = []

        resp = self._http_get(
            "https://haveibeenpwned.com/api/v3/breaches",
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "VXIS-Watcher/1.0",
            },
            timeout=20,
        )

        if not isinstance(resp, list):
            logger.debug("[leaked_credential] HIBP /breaches 응답 오류 (도메인: %s)", domain)
            return items

        domain_lower = domain.lower()
        domain_base = domain_lower.split(".")[0]  # example.com → example

        for breach in resp:
            if not isinstance(breach, dict):
                continue

            breach_domain = breach.get("Domain", "").lower()
            breach_name = breach.get("Name", "").lower()
            breach_title = breach.get("Title", "").lower()

            # 도메인, 이름, 타이틀 중 하나라도 매칭되면 포함
            matched = (
                domain_lower in breach_domain
                or domain_base in breach_name
                or domain_base in breach_title
            )
            if not matched:
                continue

            breach_id = f"hibp:breach:{breach.get('Name', '')}:{domain}"
            data_classes = breach.get("DataClasses", [])

            items.append({
                "id": breach_id,
                "source": "hibp_breach",
                "domain": domain,
                "breach_name": breach.get("Name", ""),
                "breach_title": breach.get("Title", ""),
                "breach_date": breach.get("BreachDate", ""),
                "added_date": breach.get("AddedDate", ""),
                "pwn_count": breach.get("PwnCount", 0),
                "data_classes": data_classes,
                "is_verified": breach.get("IsVerified", False),
                "is_sensitive": breach.get("IsSensitive", False),
                "description": breach.get("Description", ""),
            })

        logger.debug(
            "[leaked_credential] HIBP 도메인 매칭: %d건 (도메인: %s)", len(items), domain
        )
        return items

    def _fetch_hibp_account(
        self, email: str, domain: str, api_key: str
    ) -> list[dict[str, Any]]:
        """특정 이메일 계정이 침해됐는지 HIBP로 확인."""
        items: list[dict[str, Any]] = []

        encoded_email = urllib.parse.quote(email, safe="")
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded_email}?truncateResponse=false"

        resp = self._http_get(
            url,
            headers={
                "hibp-api-key": api_key,
                "User-Agent": "VXIS-Watcher/1.0",
            },
            timeout=15,
        )

        # 404 = 침해 없음 (정상), 응답이 비어있으면 건너뜀
        if not resp or not isinstance(resp, list):
            return items

        for breach in resp:
            if not isinstance(breach, dict):
                continue

            breach_id = f"hibp:account:{email}:{breach.get('Name', '')}"
            items.append({
                "id": breach_id,
                "source": "hibp_account",
                "domain": domain,
                "email": email,
                "breach_name": breach.get("Name", ""),
                "breach_title": breach.get("Title", ""),
                "breach_date": breach.get("BreachDate", ""),
                "data_classes": breach.get("DataClasses", []),
                "is_verified": breach.get("IsVerified", False),
            })

        logger.debug(
            "[leaked_credential] HIBP 계정 침해: %d건 (이메일: %s)", len(items), email
        )
        return items

    def _fetch_github_credentials(
        self, domain: str, token: str
    ) -> list[dict[str, Any]]:
        """GitHub Code Search로 타겟 도메인의 노출된 자격증명 탐색."""
        items: list[dict[str, Any]] = []

        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # 자격증명 패턴 쿼리 (GitHub 코드 검색 문법)
        queries = [
            f'"{domain}" password language:python',
            f'"{domain}" password language:javascript',
            f'"{domain}" DB_PASSWORD',
            f'"{domain}" SECRET_KEY',
        ]

        for query in queries:
            encoded_q = urllib.parse.quote(query)
            url = f"https://api.github.com/search/code?q={encoded_q}&per_page=5&sort=indexed"

            resp = self._http_get(url, headers=headers, timeout=20)

            if not isinstance(resp, dict):
                continue

            for item in resp.get("items", []):
                if not isinstance(item, dict):
                    continue

                sha = item.get("sha", "")
                html_url = item.get("html_url", "")
                item_hash = sha[:12] if sha else hashlib.md5(html_url.encode()).hexdigest()[:12]
                item_id = f"github:cred:{item_hash}:{domain}"

                repo = item.get("repository", {})
                items.append({
                    "id": item_id,
                    "source": "github_cred",
                    "domain": domain,
                    "query": query,
                    "file_name": item.get("name", ""),
                    "repo_full_name": repo.get("full_name", ""),
                    "html_url": html_url,
                    "sha": sha,
                })

        logger.debug(
            "[leaked_credential] GitHub 자격증명 탐색: %d건 (도메인: %s)", len(items), domain
        )
        return items

    # ── match ────────────────────────────────────────────────────

    async def match(
        self, items: list[dict[str, Any]]
    ) -> list[WatcherAlert]:
        """항목별 심각도 판단 및 알림 생성."""
        alerts: list[WatcherAlert] = []

        for item in items:
            source = item.get("source", "")

            if source == "hibp_breach":
                alert = self._match_hibp_breach(item)
            elif source == "hibp_account":
                alert = self._match_hibp_account(item)
            elif source == "github_cred":
                alert = self._match_github_cred(item)
            else:
                continue

            if alert:
                alerts.append(alert)

        return alerts

    def _match_hibp_breach(self, item: dict[str, Any]) -> WatcherAlert | None:
        """HIBP 도메인 침해 항목 분류."""
        data_classes: list[str] = item.get("data_classes", [])
        domain = item.get("domain", "")
        pwn_count = item.get("pwn_count", 0)

        # 심각도: 패스워드/이메일 포함 여부 + 피해 규모
        has_passwords = any(
            "password" in dc.lower() for dc in data_classes
        )
        is_sensitive = item.get("is_sensitive", False)

        if has_passwords or is_sensitive:
            severity = "critical"
        elif pwn_count > 1_000_000:
            severity = "high"
        else:
            severity = "medium"

        data_classes_kr = ", ".join(data_classes[:5]) or "미상"
        breach_date = item.get("breach_date", "날짜 미상")
        pwn_display = f"{pwn_count:,}" if pwn_count else "미상"

        title = f"[HIBP 침해] {domain} — {item.get('breach_title', item.get('breach_name', ''))}"
        description = (
            f"Have I Been Pwned에서 '{domain}' 관련 침해 사고가 확인되었습니다.\n"
            f"침해 서비스: {item.get('breach_title', '')}\n"
            f"침해 날짜: {breach_date}\n"
            f"피해 규모: {pwn_display}개 계정\n"
            f"노출 데이터 유형: {data_classes_kr}\n"
            f"검증된 침해: {'예' if item.get('is_verified') else '아니오'}"
        )

        return WatcherAlert(
            watcher_name=self.name,
            severity=severity,
            title=title,
            description=description,
            target=domain,
            source_url=f"https://haveibeenpwned.com/PwnedWebsites#{item.get('breach_name', '')}",
            data={
                "data_classes": data_classes,
                "pwn_count": pwn_count,
                "breach_date": breach_date,
            },
            actionable=(severity == "critical"),
        )

    def _match_hibp_account(self, item: dict[str, Any]) -> WatcherAlert | None:
        """HIBP 개별 계정 침해 항목 분류."""
        email = item.get("email", "")
        domain = item.get("domain", "")
        data_classes: list[str] = item.get("data_classes", [])

        has_passwords = any("password" in dc.lower() for dc in data_classes)
        severity = "critical" if has_passwords else "high"

        # 이메일 마스킹: user@example.com → u***@example.com
        parts = email.split("@")
        masked_email = _mask_password(parts[0]) + "@" + parts[1] if len(parts) == 2 else "***"

        data_classes_kr = ", ".join(data_classes[:5]) or "미상"
        title = f"[계정 침해] {masked_email} — {item.get('breach_title', '')}"
        description = (
            f"'{domain}' 소속 이메일 계정이 침해 사고에 포함되어 있습니다.\n"
            f"이메일: {masked_email}\n"
            f"침해 서비스: {item.get('breach_title', '')}\n"
            f"침해 날짜: {item.get('breach_date', '날짜 미상')}\n"
            f"노출 데이터: {data_classes_kr}"
        )

        return WatcherAlert(
            watcher_name=self.name,
            severity=severity,
            title=title,
            description=description,
            target=domain,
            source_url=f"https://haveibeenpwned.com/account/{urllib.parse.quote(email, safe='')}",
            data={
                "masked_email": masked_email,
                "data_classes": data_classes,
                "breach_name": item.get("breach_name", ""),
            },
            actionable=True,
        )

    def _match_github_cred(self, item: dict[str, Any]) -> WatcherAlert | None:
        """GitHub 코드에서 발견된 자격증명 항목 분류."""
        domain = item.get("domain", "")
        query = item.get("query", "")
        repo = item.get("repo_full_name", "")
        html_url = item.get("html_url", "")

        # 쿼리 키워드로 심각도 결정
        if "DB_PASSWORD" in query or "SECRET_KEY" in query:
            severity = "critical"
            keyword_kr = "데이터베이스 패스워드/시크릿 키"
        elif "password" in query.lower():
            severity = "high"
            keyword_kr = "패스워드"
        else:
            severity = "medium"
            keyword_kr = "민감 정보"

        title = f"[GitHub 자격증명 노출] {domain} — {keyword_kr} ({repo})"
        description = (
            f"GitHub 공개 저장소에서 '{domain}'의 자격증명이 노출되었을 수 있습니다.\n"
            f"저장소: {repo}\n"
            f"파일: {item.get('file_name', '')}\n"
            f"유형: {keyword_kr}\n"
            f"URL: {html_url}\n"
            f"즉시 해당 자격증명을 교체하고 접근 로그를 확인하세요."
        )

        return WatcherAlert(
            watcher_name=self.name,
            severity=severity,
            title=title,
            description=description,
            target=domain,
            source_url=html_url,
            data={"repo": repo, "file": item.get("file_name", ""), "query": query},
            actionable=(severity in ("critical", "high")),
        )

    # ── act ─────────────────────────────────────────────────────

    async def act(self, alerts: list[WatcherAlert]) -> int:
        """Critical 알림에 대해 침해 계정 목록 리포트 생성."""
        actions = 0
        report_dir = Path("~/.vxis/reports").expanduser()
        report_dir.mkdir(parents=True, exist_ok=True)

        # 도메인별 침해 계정 집계
        domain_accounts: dict[str, list[dict[str, Any]]] = {}

        for alert in alerts:
            if alert.severity not in ("critical", "high"):
                continue

            target = alert.target
            domain_accounts.setdefault(target, []).append({
                "title": alert.title,
                "severity": alert.severity,
                "data": alert.data,
                "timestamp": alert.timestamp,
                "actionable": alert.actionable,
            })

        for domain, entries in domain_accounts.items():
            report_path = report_dir / f"leaked_cred_{domain}.json"
            try:
                existing: list[dict] = []
                if report_path.exists():
                    existing = json.loads(report_path.read_text(encoding="utf-8"))

                # 중복 방지: 타이틀 기준
                existing_titles = {e.get("title") for e in existing}
                new_entries = [e for e in entries if e.get("title") not in existing_titles]
                existing.extend(new_entries)

                report_path.write_text(
                    json.dumps(existing, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                logger.info(
                    "[leaked_credential] 침해 리포트 저장: %s (%d건)",
                    report_path,
                    len(new_entries),
                )
                actions += len(new_entries)
            except Exception as exc:
                logger.warning("[leaked_credential] 리포트 저장 실패 (%s): %s", domain, exc)

        return actions


# ── 문법 자가 검증 ────────────────────────────────────────────────

def _self_verify() -> None:
    """모듈 로드 시 ast.parse로 자신의 소스 문법 검증."""
    source = Path(__file__).read_text(encoding="utf-8")
    try:
        ast.parse(source)
        logger.debug("[leaked_credential] 문법 검증 통과")
    except SyntaxError as exc:
        logger.error("[leaked_credential] 문법 오류 감지: %s", exc)
        raise


_self_verify()
