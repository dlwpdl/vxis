"""랜섬웨어 그룹 감시 워처 — 실시간 랜섬웨어 피해 기업 매칭.

감시 소스:
    1. ransomware.live API — GET /api/victims (최신 랜섬웨어 피해자 목록)
    2. ransomlook.io API   — GET /api/recent  (백업 소스)

두 소스 모두 무료, API 키 불필요.

매칭 로직:
    - 피해자 이름/웹사이트를 agent_memory.json의 타겟과 퍼지 매칭
    - 도메인 정확 매칭 OR 기업명 유사도 매칭 (공통 토큰 비율)

심각도:
    - 타겟 기업이 랜섬웨어 피해자 → CRITICAL (현재 진행 중일 수 있음)
"""

from __future__ import annotations

import ast
import json
import logging
import re
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any

from .base import BaseWatcher, WatcherAlert, register_watcher

logger = logging.getLogger(__name__)

_AGENT_MEMORY_PATH = Path("~/.vxis/agent_memory.json").expanduser()

# 퍼지 매칭 최소 유사도 임계값 (0.0 ~ 1.0)
_FUZZY_THRESHOLD = 0.55

# 각 소스에서 가져올 최대 피해자 수
_MAX_VICTIMS_PER_SOURCE = 200


def _load_target_profiles() -> list[dict[str, Any]]:
    """agent_memory.json에서 타겟 프로파일 로드.

    반환 형식:
        [{"domain": "example.com", "company": "Example Corp", "aliases": [...]}]
    """
    if not _AGENT_MEMORY_PATH.exists():
        logger.warning("[ransomware_gang] agent_memory.json 없음: %s", _AGENT_MEMORY_PATH)
        return []
    try:
        data = json.loads(_AGENT_MEMORY_PATH.read_text(encoding="utf-8"))
        profiles: list[dict[str, Any]] = []
        for t in data.get("targets", []):
            if isinstance(t, dict):
                domain = (t.get("domain", "") or t.get("target", "")).strip()
                domain = domain.lstrip("https://").lstrip("http://").rstrip("/")
                company = t.get("company", "") or t.get("name", "") or domain
                aliases = t.get("aliases", [])
            else:
                domain = str(t).strip().lstrip("https://").lstrip("http://").rstrip("/")
                company = domain
                aliases = []

            if domain:
                profiles.append(
                    {
                        "domain": domain,
                        "company": company,
                        "aliases": aliases,
                    }
                )
        return profiles
    except Exception as exc:
        logger.warning("[ransomware_gang] agent_memory.json 파싱 오류: %s", exc)
        return []


def _normalize_name(name: str) -> str:
    """기업명 정규화: 소문자, 특수문자/법인 접미사 제거."""
    name = name.lower().strip()
    # 법인 유형 접미사 제거
    suffixes = r"\s+(inc\.?|corp\.?|co\.?|ltd\.?|llc\.?|plc\.?|gmbh|ag|sa|bv|nv|oy|ab)$"
    name = re.sub(suffixes, "", name, flags=re.IGNORECASE)
    # 특수문자 → 공백
    name = re.sub(r"[^\w\s]", " ", name)
    return re.sub(r"\s+", " ", name).strip()


def _token_similarity(a: str, b: str) -> float:
    """두 기업명의 토큰 겹침 비율 계산 (Jaccard 유사도 변형).

    짧은 쪽을 기준으로 공통 토큰 비율 반환.
    예) "samsung electronics" vs "samsung" → 1.0 (samsung이 공통)
    """
    tokens_a = set(_normalize_name(a).split())
    tokens_b = set(_normalize_name(b).split())

    if not tokens_a or not tokens_b:
        return 0.0

    # 1글자 토큰 제거 (전치사, 관사 등 노이즈)
    tokens_a = {t for t in tokens_a if len(t) > 1}
    tokens_b = {t for t in tokens_b if len(t) > 1}

    if not tokens_a or not tokens_b:
        return 0.0

    common = tokens_a & tokens_b
    shorter = min(len(tokens_a), len(tokens_b))
    return len(common) / shorter


def _domain_match(victim_website: str, target_domain: str) -> bool:
    """피해자 웹사이트와 타겟 도메인의 정확 매칭.

    URL 정규화 후 비교:
        "https://www.example.com/" → "example.com"
    """
    if not victim_website or not target_domain:
        return False

    # URL 파싱으로 호스트 추출
    try:
        parsed = urllib.parse.urlparse(victim_website)
        host = parsed.hostname or victim_website
    except Exception:
        host = victim_website

    host = host.lower().lstrip("www.").strip()
    target = target_domain.lower().lstrip("www.").strip()

    # 정확 매칭 또는 하위 도메인 매칭
    return host == target or host.endswith(f".{target}")


def _match_victim_to_targets(
    victim: dict[str, Any],
    profiles: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """피해자 항목을 타겟 프로파일과 매칭.

    반환: 매칭된 프로파일 딕셔너리 (매칭 안되면 None).
    """
    victim_name = victim.get("victim_name", "") or victim.get("post_title", "")
    victim_website = victim.get("website", "") or victim.get("url", "")

    for profile in profiles:
        # 1차: 도메인 정확 매칭 (우선순위 높음)
        if victim_website and _domain_match(victim_website, profile["domain"]):
            return profile

        # 2차: 기업명 퍼지 매칭
        company = profile["company"]
        if victim_name:
            similarity = _token_similarity(victim_name, company)
            if similarity >= _FUZZY_THRESHOLD:
                return profile

        # 3차: 별칭 매칭
        for alias in profile.get("aliases", []):
            if victim_name and _token_similarity(victim_name, alias) >= _FUZZY_THRESHOLD:
                return profile

    return None


@register_watcher
class RansomwareGangWatcher(BaseWatcher):
    """실시간 랜섬웨어 피해자 목록을 감시하고 타겟 기업 매칭을 수행한다."""

    name = "ransomware_gang"
    icon = "💀"

    @property
    def poll_interval(self) -> int:
        """30분마다 폴링 (랜섬웨어 그룹은 수시로 피해자 게시)."""
        return 1800

    # ── fetch ────────────────────────────────────────────────────

    async def fetch(self) -> list[dict[str, Any]]:
        """ransomware.live와 ransomlook.io에서 최신 피해자 목록 수집."""
        items: list[dict[str, Any]] = []

        # 소스 1: ransomware.live
        items.extend(self._fetch_ransomware_live())

        # 소스 2: ransomlook.io (백업)
        items.extend(self._fetch_ransomlook())

        # 중복 제거 (id 기준)
        seen_ids: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for item in items:
            if item["id"] not in seen_ids:
                seen_ids.add(item["id"])
                deduped.append(item)

        logger.info("[ransomware_gang] 수집 완료: %d건 (중복 제거 후)", len(deduped))
        return deduped

    def _fetch_ransomware_live(self) -> list[dict[str, Any]]:
        """ransomware.live API: GET /api/victims."""
        items: list[dict[str, Any]] = []

        resp = self._http_get(
            "https://api.ransomware.live/api/victims",
            timeout=20,
        )

        if not isinstance(resp, list):
            # 일부 버전에서 dict 래퍼 사용
            if isinstance(resp, dict):
                resp = resp.get("victims", resp.get("data", []))
            else:
                logger.debug("[ransomware_gang] ransomware.live 응답 형식 오류")
                return items

        for victim in resp[:_MAX_VICTIMS_PER_SOURCE]:
            if not isinstance(victim, dict):
                continue

            # ID 생성: group + victim_name + published 조합
            group = victim.get("group_name", "") or victim.get("gang", "") or "unknown"
            name = victim.get("victim_name", "") or victim.get("post_title", "")
            published = victim.get("published", "") or victim.get("discovered", "")
            raw_id = f"rl:{group}:{name}:{published}"

            # 결정론적 ID (공백/대소문자 정규화)
            normalized_id = re.sub(r"\s+", "_", raw_id.lower().strip())

            items.append(
                {
                    "id": normalized_id,
                    "source": "ransomware_live",
                    "group_name": group,
                    "victim_name": name,
                    "website": victim.get("website", "") or victim.get("url", ""),
                    "country": victim.get("country", ""),
                    "published": published,
                    "description": victim.get("description", ""),
                    "post_url": victim.get("post_url", ""),
                }
            )

        logger.debug("[ransomware_gang] ransomware.live: %d건", len(items))
        return items

    def _fetch_ransomlook(self) -> list[dict[str, Any]]:
        """ransomlook.io API: GET /api/recent."""
        items: list[dict[str, Any]] = []

        resp = self._http_get(
            "https://www.ransomlook.io/api/recent",
            timeout=20,
        )

        # ransomlook은 list 또는 {"posts": [...]} 형태로 반환
        if isinstance(resp, dict):
            resp = resp.get("posts", resp.get("data", []))

        if not isinstance(resp, list):
            logger.debug("[ransomware_gang] ransomlook.io 응답 형식 오류")
            return items

        for post in resp[:_MAX_VICTIMS_PER_SOURCE]:
            if not isinstance(post, dict):
                continue

            group = post.get("group_name", "") or post.get("group", "") or "unknown"
            name = post.get("post_title", "") or post.get("victim", "")
            published = post.get("discovered", "") or post.get("published", "")
            raw_id = f"rlo:{group}:{name}:{published}"
            normalized_id = re.sub(r"\s+", "_", raw_id.lower().strip())

            items.append(
                {
                    "id": normalized_id,
                    "source": "ransomlook",
                    "group_name": group,
                    "victim_name": name,
                    "website": post.get("url", "") or post.get("website", ""),
                    "country": post.get("country", ""),
                    "published": published,
                    "description": post.get("description", ""),
                    "post_url": post.get("post_url", ""),
                }
            )

        logger.debug("[ransomware_gang] ransomlook.io: %d건", len(items))
        return items

    # ── match ────────────────────────────────────────────────────

    async def match(self, items: list[dict[str, Any]]) -> list[WatcherAlert]:
        """피해자 목록과 타겟 프로파일 매칭 → CRITICAL 알림 생성."""
        profiles = _load_target_profiles()
        if not profiles:
            logger.info("[ransomware_gang] 타겟 프로파일 없음. 매칭 건너뜁니다.")
            return []

        alerts: list[WatcherAlert] = []
        # 동일 피해자 중복 알림 방지
        alerted_victims: set[str] = set()

        for item in items:
            victim_key = item.get("victim_name", "").lower().strip()
            if victim_key in alerted_victims:
                continue

            matched_profile = _match_victim_to_targets(item, profiles)
            if matched_profile is None:
                continue

            alerted_victims.add(victim_key)

            alert = self._build_alert(item, matched_profile)
            alerts.append(alert)
            logger.warning(
                "[ransomware_gang] 타겟 매칭! 기업: %s, 그룹: %s, 소스: %s",
                matched_profile["company"],
                item.get("group_name", "unknown"),
                item.get("source", ""),
            )

        return alerts

    def _build_alert(
        self,
        victim: dict[str, Any],
        profile: dict[str, Any],
    ) -> WatcherAlert:
        """매칭된 피해자 항목으로 CRITICAL 알림 생성."""
        group = victim.get("group_name", "알 수 없는 그룹")
        victim_name = victim.get("victim_name", "")
        country = victim.get("country", "")
        published = victim.get("published", "날짜 미상")
        description = victim.get("description", "")
        post_url = victim.get("post_url", "")
        source_name = {
            "ransomware_live": "ransomware.live",
            "ransomlook": "ransomlook.io",
        }.get(victim.get("source", ""), victim.get("source", "unknown"))

        target_domain = profile["domain"]
        company = profile["company"]
        date_display = published[:10] if published else "날짜 미상"
        country_display = f" ({country})" if country else ""

        title = f"[랜섬웨어 피해] {company}{country_display} — {group} 그룹 ({date_display})"
        description_lines = [
            f"랜섬웨어 그룹 '{group}'이 '{company}'을 피해자로 등록했습니다.",
            f"기업: {victim_name}{country_display}",
            f"타겟 도메인: {target_domain}",
            f"랜섬웨어 그룹: {group}",
            f"등록 날짜: {date_display}",
            f"출처: {source_name}",
        ]
        if description:
            description_lines.append(f"설명: {description[:300]}")
        if post_url:
            description_lines.append(f"피해자 게시 URL: {post_url}")
        description_lines.append("즉시 침해 지표(IOC)를 확인하고 인시던트 대응 절차를 개시하세요.")

        return WatcherAlert(
            watcher_name=self.name,
            severity="critical",
            title=title,
            description="\n".join(description_lines),
            target=target_domain,
            source_url=post_url or "https://ransomware.live",
            data={
                "group": group,
                "victim_name": victim_name,
                "country": country,
                "published": published,
                "source": victim.get("source", ""),
                "matched_company": company,
            },
            actionable=True,
        )

    # ── act ─────────────────────────────────────────────────────

    async def act(self, alerts: list[WatcherAlert]) -> int:
        """CRITICAL 알림에 대해 인시던트 리포트 생성 및 그룹 통계 업데이트."""
        actions = 0
        report_dir = Path("~/.vxis/reports").expanduser()
        report_dir.mkdir(parents=True, exist_ok=True)

        for alert in alerts:
            if alert.severity != "critical":
                continue

            # 1. 인시던트 리포트 저장
            target = alert.target
            group = alert.data.get("group", "unknown")
            safe_target = re.sub(r"[^\w\-.]", "_", target)
            safe_group = re.sub(r"[^\w\-.]", "_", group)
            report_path = report_dir / f"ransomware_{safe_target}_{safe_group}.json"

            try:
                existing: list[dict] = []
                if report_path.exists():
                    existing = json.loads(report_path.read_text(encoding="utf-8"))

                incident = {
                    "title": alert.title,
                    "target": target,
                    "group": group,
                    "victim_name": alert.data.get("victim_name", ""),
                    "country": alert.data.get("country", ""),
                    "published": alert.data.get("published", ""),
                    "source": alert.data.get("source", ""),
                    "source_url": alert.source_url,
                    "description": alert.description,
                    "detected_at": alert.timestamp,
                }

                # 중복 인시던트 방지 (published + group 조합)
                dup_key = f"{group}:{alert.data.get('published', '')}"
                if not any(
                    f"{e.get('group', '')}:{e.get('published', '')}" == dup_key for e in existing
                ):
                    existing.append(incident)
                    report_path.write_text(
                        json.dumps(existing, ensure_ascii=False, indent=2),
                        encoding="utf-8",
                    )
                    logger.warning("[ransomware_gang] 인시던트 리포트 저장: %s", report_path)
                    actions += 1

            except Exception as exc:
                logger.warning("[ransomware_gang] 인시던트 리포트 저장 실패 (%s): %s", target, exc)

            # 2. 그룹 통계 업데이트
            stats_path = report_dir / "ransomware_group_stats.json"
            try:
                stats: dict[str, Any] = {}
                if stats_path.exists():
                    stats = json.loads(stats_path.read_text(encoding="utf-8"))

                stats.setdefault(group, {"count": 0, "last_seen": "", "targets": []})
                stats[group]["count"] += 1
                stats[group]["last_seen"] = alert.timestamp
                if target not in stats[group]["targets"]:
                    stats[group]["targets"].append(target)

                stats_path.write_text(
                    json.dumps(stats, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
            except Exception as exc:
                logger.warning("[ransomware_gang] 그룹 통계 업데이트 실패: %s", exc)

        return actions


# ── 문법 자가 검증 ────────────────────────────────────────────────


def _self_verify() -> None:
    """모듈 로드 시 ast.parse로 자신의 소스 문법 검증."""
    source = Path(__file__).read_text(encoding="utf-8")
    try:
        ast.parse(source)
        logger.debug("[ransomware_gang] 문법 검증 통과")
    except SyntaxError as exc:
        logger.error("[ransomware_gang] 문법 오류 감지: %s", exc)
        raise


_self_verify()
