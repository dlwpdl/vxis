"""다크웹 인텔리전스 워처 — 다크웹/페이스트/GitHub 유출 감시.

감시 소스:
    1. IntelligenceX (intelx.io) — 다크웹/페이스트/유출 검색
    2. GitHub Code Search — 타겟 도메인 언급 코드 검색
    3. Pastebin GCS (Google Custom Search) — 페이스트 덤프 검색 (선택적)

환경 변수:
    INTELX_API_KEY      — IntelligenceX API 키 (없으면 해당 소스 건너뜀)
    GOOGLE_CSE_API_KEY  — Google Custom Search API 키 (선택)
    GOOGLE_CSE_ID       — Google CSE ID (선택)
    GITHUB_TOKEN        — GitHub Personal Access Token (없으면 미인증 요청)
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

from .base import BaseWatcher, WatcherAlert, register_watcher

logger = logging.getLogger(__name__)

_AGENT_MEMORY_PATH = Path("~/.vxis/agent_memory.json").expanduser()

# IntelligenceX 검색 결과 상태 코드
_INTELX_STATUS_SUCCESS = 0
_INTELX_STATUS_NOT_FOUND = 1

# 컨텐츠 타입별 심각도 매핑 (IntelligenceX 버킷 기준)
_BUCKET_SEVERITY: dict[str, str] = {
    "pastes": "high",
    "darkweb": "critical",
    "leaks": "critical",
    "documents": "medium",
    "whois": "low",
    "publicdomain": "low",
}


def _load_target_domains() -> list[str]:
    """agent_memory.json에서 타겟 도메인 목록 로드."""
    if not _AGENT_MEMORY_PATH.exists():
        logger.warning("[dark_web_intel] agent_memory.json 없음: %s", _AGENT_MEMORY_PATH)
        return []
    try:
        data = json.loads(_AGENT_MEMORY_PATH.read_text(encoding="utf-8"))
        targets = data.get("targets", [])
        domains: list[str] = []
        for t in targets:
            if isinstance(t, dict):
                domain = t.get("domain", "") or t.get("target", "")
            else:
                domain = str(t)
            domain = domain.strip().lstrip("https://").lstrip("http://").rstrip("/")
            if domain:
                domains.append(domain)
        return list(dict.fromkeys(domains))  # 중복 제거, 순서 유지
    except Exception as exc:
        logger.warning("[dark_web_intel] agent_memory.json 파싱 오류: %s", exc)
        return []


def _mask_credential(value: str) -> str:
    """자격증명 일부를 마스킹하여 미리보기용 문자열 반환.

    예) "secretpassword123" → "sec***rd123"
    """
    if len(value) <= 6:
        return "***"
    visible = max(2, len(value) // 4)
    return value[:visible] + "***" + value[-visible:]


@register_watcher
class DarkWebIntelWatcher(BaseWatcher):
    """다크웹·페이스트·GitHub에서 타겟 도메인 언급/유출을 감시한다."""

    name = "dark_web_intel"
    icon = "🕸️"

    @property
    def poll_interval(self) -> int:
        """6시간마다 폴링 (다크웹 인덱스 갱신 주기 고려)."""
        return 21600

    # ── fetch ────────────────────────────────────────────────────

    async def fetch(self) -> list[dict[str, Any]]:
        """IntelligenceX + GitHub에서 타겟 도메인 관련 항목 수집."""
        domains = _load_target_domains()
        if not domains:
            logger.info("[dark_web_intel] 타겟 도메인 없음. 건너뜁니다.")
            return []

        items: list[dict[str, Any]] = []

        intelx_key = os.environ.get("INTELX_API_KEY", "")
        github_token = os.environ.get("GITHUB_TOKEN", "")

        for domain in domains:
            if intelx_key:
                items.extend(self._fetch_intelx(domain, intelx_key))
            items.extend(self._fetch_github_code(domain, github_token))

        logger.info("[dark_web_intel] 수집 완료: %d건", len(items))
        return items

    def _fetch_intelx(self, domain: str, api_key: str) -> list[dict[str, Any]]:
        """IntelligenceX API로 도메인 검색.

        흐름:
            1. POST /intelligent/search → search_id 획득
            2. GET /intelligent/search/result?id={search_id} → 결과 수집
        """
        items: list[dict[str, Any]] = []

        # 1단계: 검색 시작
        search_payload = {
            "term": domain,
            "buckets": [],          # 빈 배열 = 전체 소스
            "lookuplevel": 0,
            "maxresults": 20,
            "timeout": 20,
            "datefrom": "",
            "dateto": "",
            "sort": 4,              # 관련도순
            "media": 0,
            "terminate": [],
        }

        search_resp = self._http_post(
            "https://2.intelx.io/intelligent/search",
            data=search_payload,
            headers={"x-key": api_key},
            timeout=25,
        )

        if not isinstance(search_resp, dict):
            return items

        search_id = search_resp.get("id", "")
        if not search_id:
            logger.debug("[dark_web_intel] IntelX: search_id 없음 (도메인: %s)", domain)
            return items

        # 2단계: 결과 수집
        result_url = (
            f"https://2.intelx.io/intelligent/search/result"
            f"?id={urllib.parse.quote(search_id)}&limit=20&offset=0"
        )
        result_resp = self._http_get(
            result_url,
            headers={"x-key": api_key},
            timeout=20,
        )

        if not isinstance(result_resp, dict):
            return items

        status = result_resp.get("status", -1)
        if status not in (_INTELX_STATUS_SUCCESS, _INTELX_STATUS_NOT_FOUND):
            logger.debug("[dark_web_intel] IntelX 상태 코드 %d (도메인: %s)", status, domain)

        for record in result_resp.get("records", []):
            if not isinstance(record, dict):
                continue

            bucket = record.get("bucket", "unknown")
            system_id = record.get("systemid", "")
            record_id = f"intelx:{domain}:{system_id}" if system_id else (
                f"intelx:{domain}:{hashlib.md5(json.dumps(record, sort_keys=True).encode()).hexdigest()[:12]}"
            )

            items.append({
                "id": record_id,
                "source": "intelx",
                "domain": domain,
                "bucket": bucket,
                "name": record.get("name", ""),
                "date": record.get("date", ""),
                "system_id": system_id,
                "size": record.get("size", 0),
                "media": record.get("media", 0),
                "raw": record,
            })

        logger.debug("[dark_web_intel] IntelX: %d건 (도메인: %s)", len(items), domain)
        return items

    def _fetch_github_code(
        self, domain: str, token: str
    ) -> list[dict[str, Any]]:
        """GitHub Code Search API로 도메인 언급 코드 검색.

        키워드: 도메인 + password / secret / api_key 조합
        """
        items: list[dict[str, Any]] = []

        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        # 민감 키워드 조합 검색 (GitHub 검색 제한: 30 req/min 인증, 10/min 미인증)
        queries = [
            f'"{domain}" password',
            f'"{domain}" secret',
            f'"{domain}" api_key',
        ]

        for query in queries:
            encoded_q = urllib.parse.quote(query)
            url = f"https://api.github.com/search/code?q={encoded_q}&per_page=10&sort=indexed"

            resp = self._http_get(url, headers=headers, timeout=20)

            if not isinstance(resp, dict):
                continue

            for item in resp.get("items", []):
                if not isinstance(item, dict):
                    continue

                repo = item.get("repository", {})
                item_id = f"github:code:{item.get('sha', '')[:12]}:{domain}"
                if not item.get("sha"):
                    item_id = (
                        f"github:code:"
                        f"{hashlib.md5(item.get('html_url', '').encode()).hexdigest()[:12]}"
                    )

                items.append({
                    "id": item_id,
                    "source": "github_code",
                    "domain": domain,
                    "query": query,
                    "file_name": item.get("name", ""),
                    "repo_full_name": repo.get("full_name", ""),
                    "repo_private": repo.get("private", False),
                    "html_url": item.get("html_url", ""),
                    "sha": item.get("sha", ""),
                })

        logger.debug("[dark_web_intel] GitHub: %d건 (도메인: %s)", len(items), domain)
        return items

    # ── match ────────────────────────────────────────────────────

    async def match(
        self, items: list[dict[str, Any]]
    ) -> list[WatcherAlert]:
        """수집된 항목을 분류하고 심각도별 알림 생성."""
        alerts: list[WatcherAlert] = []

        for item in items:
            source = item.get("source", "")
            domain = item.get("domain", "")

            if source == "intelx":
                alert = self._match_intelx_item(item, domain)
            elif source == "github_code":
                alert = self._match_github_item(item, domain)
            else:
                continue

            if alert:
                alerts.append(alert)

        return alerts

    def _match_intelx_item(
        self, item: dict[str, Any], domain: str
    ) -> WatcherAlert | None:
        """IntelligenceX 항목 분류."""
        bucket = item.get("bucket", "unknown")
        severity = _BUCKET_SEVERITY.get(bucket, "medium")

        bucket_kr = {
            "pastes": "페이스트 덤프",
            "darkweb": "다크웹",
            "leaks": "유출 데이터",
            "documents": "공개 문서",
            "whois": "WHOIS 기록",
            "publicdomain": "공개 도메인",
        }.get(bucket, bucket)

        name = item.get("name", "이름 없음")
        date_str = item.get("date", "")
        date_display = date_str[:10] if date_str else "날짜 미상"

        title = f"[{bucket_kr}] {domain} — {name}"
        description = (
            f"IntelligenceX에서 '{domain}' 관련 항목이 발견되었습니다.\n"
            f"분류: {bucket_kr}\n"
            f"파일명: {name}\n"
            f"날짜: {date_display}\n"
            f"크기: {item.get('size', 0):,} bytes"
        )

        return WatcherAlert(
            watcher_name=self.name,
            severity=severity,
            title=title,
            description=description,
            target=domain,
            source_url=f"https://intelx.io/?did={item.get('system_id', '')}",
            data={"bucket": bucket, "name": name, "date": date_str},
            actionable=(severity in ("critical", "high")),
        )

    def _match_github_item(
        self, item: dict[str, Any], domain: str
    ) -> WatcherAlert | None:
        """GitHub 코드 검색 항목 분류.

        검색 쿼리에 password/secret/api_key가 포함된 경우 자격증명 노출로 판단.
        """
        query = item.get("query", "")
        repo = item.get("repo_full_name", "알 수 없는 저장소")
        file_name = item.get("file_name", "")
        html_url = item.get("html_url", "")

        # 쿼리 키워드로 심각도 결정
        if "password" in query or "secret" in query:
            severity = "high"
            keyword_kr = "비밀번호/시크릿" if "password" in query else "시크릿 키"
        elif "api_key" in query:
            severity = "medium"
            keyword_kr = "API 키"
        else:
            severity = "low"
            keyword_kr = "코드 언급"

        title = f"[GitHub 코드 노출] {domain} — {keyword_kr} ({repo})"
        description = (
            f"GitHub 공개 저장소에서 '{domain}' 관련 민감 코드가 발견되었습니다.\n"
            f"저장소: {repo}\n"
            f"파일: {file_name}\n"
            f"검색어: {query}\n"
            f"URL: {html_url}"
        )

        return WatcherAlert(
            watcher_name=self.name,
            severity=severity,
            title=title,
            description=description,
            target=domain,
            source_url=html_url,
            data={"repo": repo, "file": file_name, "query": query},
            actionable=(severity == "high"),
        )

    # ── act ─────────────────────────────────────────────────────

    async def act(self, alerts: list[WatcherAlert]) -> int:
        """Critical/High 알림에 대해 상세 리포트를 로컬 파일로 저장."""
        actions = 0
        report_dir = Path("~/.vxis/reports").expanduser()
        report_dir.mkdir(parents=True, exist_ok=True)

        for alert in alerts:
            if alert.severity not in ("critical", "high"):
                continue

            report_path = report_dir / f"dark_web_{alert.data.get('bucket', 'github')}_{alert.target}.json"
            try:
                existing: list[dict] = []
                if report_path.exists():
                    existing = json.loads(report_path.read_text(encoding="utf-8"))
                existing.append({
                    "title": alert.title,
                    "severity": alert.severity,
                    "description": alert.description,
                    "source_url": alert.source_url,
                    "timestamp": alert.timestamp,
                    "data": alert.data,
                })
                report_path.write_text(
                    json.dumps(existing, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                logger.info(
                    "[dark_web_intel] 리포트 저장: %s (심각도: %s)",
                    report_path,
                    alert.severity,
                )
                actions += 1
            except Exception as exc:
                logger.warning("[dark_web_intel] 리포트 저장 실패: %s", exc)

        return actions


# ── 문법 자가 검증 ────────────────────────────────────────────────

def _self_verify() -> None:
    """모듈 로드 시 ast.parse로 자신의 소스 문법 검증."""
    source = Path(__file__).read_text(encoding="utf-8")
    try:
        ast.parse(source)
        logger.debug("[dark_web_intel] 문법 검증 통과")
    except SyntaxError as exc:
        logger.error("[dark_web_intel] 문법 오류 감지: %s", exc)
        raise


_self_verify()
