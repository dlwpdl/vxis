"""ThreatNewsWatcher — 보안 뉴스 사이트 실시간 감시.

RSS/Atom 피드를 통해 threat intelligence 뉴스를 수집한다.
각 기사에서 CVE, 위협 행위자, 기술 스택, IoC를 추출하여
agent_memory의 타겟과 매칭되는 경우 알림을 발생시킨다.

감시 소스:
    - Security Affairs (securityaffairs.com)
    - BleepingComputer (bleepingcomputer.com)
    - The Hacker News (thehackernews.com)
    - KrebsOnSecurity (krebsonsecurity.com)
    - Dark Reading (darkreading.com)
    - The Record (therecord.media)

분류:
    - CVE 포함 + 타겟 기술 매칭: critical
    - 위협 행위자 + 산업군 매칭: high
    - 공격 기법/TTP 언급: medium
    - 일반 보안 뉴스: info
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import BaseWatcher, WatcherAlert, register_watcher

logger = logging.getLogger(__name__)

_MEMORY_PATH = Path(__file__).parent.parent / "data" / "agent_memory.json"

# 감시 대상 보안 뉴스 RSS 피드
_NEWS_FEEDS: dict[str, str] = {
    "securityaffairs":   "https://securityaffairs.com/feed",
    "bleepingcomputer":  "https://www.bleepingcomputer.com/feed/",
    "thehackernews":     "https://feeds.feedburner.com/TheHackersNews",
    "krebsonsecurity":   "https://krebsonsecurity.com/feed/",
    "darkreading":       "https://www.darkreading.com/rss.xml",
    "therecord":         "https://therecord.media/feed/",
    "schneier":          "https://www.schneier.com/feed/atom/",
    "threatpost":        "https://threatpost.com/feed/",
    "securityweek":      "https://www.securityweek.com/feed",
}

# 위협 행위자 키워드 (APT, ransomware 그룹 등)
_THREAT_ACTORS = [
    # Nation-state APT
    "apt28", "apt29", "apt33", "apt34", "apt38", "apt40", "apt41",
    "lazarus", "kimsuky", "konni", "scarcruft", "andariel", "bluenoroff",
    "fancy bear", "cozy bear", "sandworm", "fin7", "fin8",
    "mustang panda", "silent chollima", "hidden cobra",
    # Ransomware groups
    "lockbit", "alphv", "blackcat", "cl0p", "clop", "conti",
    "ryuk", "revil", "darkside", "blackbyte", "royal", "play",
    "qilin", "medusa", "rhysida", "akira", "scattered spider",
    # Other threat actors
    "dprk", "chinese apt", "russian apt", "iranian apt",
]

# 공격 기법 / TTP 키워드
_ATTACK_TECHNIQUES = [
    "zero-day", "0-day", "supply chain", "supply-chain",
    "ransomware", "phishing", "spear-phishing", "spear phishing",
    "lnk file", "powershell", "living off the land", "lolbin",
    "github c2", "c2 infrastructure", "command and control",
    "initial access", "lateral movement", "privilege escalation",
    "rce", "remote code execution", "deserialization",
    "prototype pollution", "xxe", "ssrf", "sql injection",
    "bypass", "authentication bypass", "auth bypass",
    "exploitation", "exploit chain", "in-the-wild",
    "data breach", "data leak", "credential dump",
    "backdoor", "rat", "trojan", "infostealer",
    "deepfake", "bec", "business email compromise",
]

# 관심 산업군 키워드
_INDUSTRIES = [
    "fintech", "banking", "financial", "payment",
    "healthcare", "medical", "pharma",
    "government", "public sector", "defense",
    "critical infrastructure", "energy", "utility",
    "telecom", "isp", "cloud provider",
    "e-commerce", "retail", "logistics",
    "saas", "tech company", "software vendor",
]


# ── 헬퍼 함수 ─────────────────────────────────────────────────────


def _make_id(source: str, guid: str) -> str:
    raw = f"{source}:{guid}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _load_target_stack() -> dict[str, Any]:
    """agent_memory에서 타겟 기술 스택/산업군을 로드."""
    result: dict[str, Any] = {
        "technologies": [],
        "industry": "",
        "keywords": [],
    }
    if not _MEMORY_PATH.exists():
        return result
    try:
        data = json.loads(_MEMORY_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return result

    targets = data.get("targets", {})
    if isinstance(targets, dict):
        for info in targets.values():
            if isinstance(info, dict):
                result["technologies"].extend(info.get("technologies", []))
                if not result["industry"]:
                    result["industry"] = info.get("industry", "")
                result["keywords"].extend(info.get("keywords", []))

    meta = data.get("meta", {})
    if isinstance(meta, dict):
        if not result["industry"]:
            result["industry"] = meta.get("industry", "")
        result["keywords"].extend(meta.get("keywords", []))

    result["technologies"] = list(dict.fromkeys(result["technologies"]))
    result["keywords"] = list(dict.fromkeys(result["keywords"]))
    return result


def _parse_rss_items(xml_text: str, source: str) -> list[dict[str, Any]]:
    """RSS/Atom XML → 항목 리스트."""
    items: list[dict[str, Any]] = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        logger.debug("[ThreatNews] %s RSS 파싱 오류: %s", source, exc)
        return items

    # RSS 2.0
    for item in root.findall(".//item"):
        title = (item.findtext("title") or "").strip()
        link = (item.findtext("link") or "").strip()
        description = (item.findtext("description") or "").strip()
        pub_date = (item.findtext("pubDate") or "").strip()
        guid = (item.findtext("guid") or link or title).strip()
        if not guid:
            continue

        # HTML 태그 제거 (description이 HTML일 수 있음)
        description = re.sub(r"<[^>]+>", " ", description)
        description = re.sub(r"\s+", " ", description).strip()

        items.append({
            "id": _make_id(source, guid),
            "source": source,
            "title": title,
            "link": link,
            "description": description[:800],
            "pub_date": pub_date,
        })

    # Atom 1.0
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.findall(".//atom:entry", ns):
        title_el = entry.find("atom:title", ns)
        title = (title_el.text or "").strip() if title_el is not None else ""
        link_el = entry.find("atom:link", ns)
        link = link_el.get("href", "") if link_el is not None else ""
        summary_el = entry.find("atom:summary", ns)
        description = (summary_el.text or "").strip() if summary_el is not None else ""
        updated_el = entry.find("atom:updated", ns)
        pub_date = (updated_el.text or "").strip() if updated_el is not None else ""
        id_el = entry.find("atom:id", ns)
        guid = (id_el.text or link or title).strip() if id_el is not None else (link or title)
        if not guid:
            continue

        description = re.sub(r"<[^>]+>", " ", description)
        description = re.sub(r"\s+", " ", description).strip()

        items.append({
            "id": _make_id(source, guid),
            "source": source,
            "title": title,
            "link": link,
            "description": description[:800],
            "pub_date": pub_date,
        })

    return items


def _extract_cve_ids(text: str) -> list[str]:
    return sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))


def _detect_threat_actors(text: str) -> list[str]:
    t = text.lower()
    return [ta for ta in _THREAT_ACTORS if ta in t]


def _detect_techniques(text: str) -> list[str]:
    t = text.lower()
    return [tech for tech in _ATTACK_TECHNIQUES if tech in t]


def _detect_industries(text: str) -> list[str]:
    t = text.lower()
    return [ind for ind in _INDUSTRIES if ind in t]


def _tech_matches(technologies: list[str], text: str) -> list[str]:
    t = text.lower()
    return [tech for tech in technologies if tech.lower() in t]


# ── Watcher 구현 ──────────────────────────────────────────────────


@register_watcher
class ThreatNewsWatcher(BaseWatcher):
    """보안 뉴스 사이트 감시 워처.

    주기적으로 주요 보안 뉴스 RSS 피드를 폴링하여
    CVE, 위협 행위자, 공격 기법을 추출하고 타겟과 매칭한다.
    """

    name = "threat_news"
    icon = "\U0001F4F0"  # 📰
    poll_interval = 1800  # 30분

    async def fetch(self) -> list[dict[str, Any]]:
        """모든 뉴스 피드에서 새 기사 수집."""
        all_items: list[dict[str, Any]] = []
        for source, feed_url in _NEWS_FEEDS.items():
            try:
                items = await asyncio.get_event_loop().run_in_executor(
                    None, self._fetch_feed, source, feed_url,
                )
                all_items.extend(items)
                logger.info("[ThreatNews] %s: %d개 수집", source, len(items))
            except Exception as exc:
                logger.warning("[ThreatNews] %s 수집 실패: %s", source, exc)
        return all_items

    def _fetch_feed(self, source: str, feed_url: str) -> list[dict[str, Any]]:
        """단일 RSS 피드 요청 → 항목 파싱."""
        req = urllib.request.Request(
            feed_url,
            headers={
                "User-Agent": "VXIS-ThreatNews/1.0 (security research)",
                "Accept": "application/rss+xml, application/xml, text/xml, application/atom+xml, */*",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
        except Exception as exc:
            logger.debug("[ThreatNews] %s 요청 실패: %s", source, exc)
            return []
        return _parse_rss_items(raw, source)

    async def match(self, items: list[dict[str, Any]]) -> list[WatcherAlert]:
        """각 기사에서 CVE/threat actor/technique 추출 후 매칭."""
        target_stack = _load_target_stack()
        techs = target_stack["technologies"]
        industry = target_stack["industry"]

        alerts: list[WatcherAlert] = []
        for item in items:
            combined_text = f"{item['title']} {item['description']}"

            cves = _extract_cve_ids(combined_text)
            actors = _detect_threat_actors(combined_text)
            techniques = _detect_techniques(combined_text)
            industries = _detect_industries(combined_text)
            matched_techs = _tech_matches(techs, combined_text)

            # 관련성 점수 계산
            has_cve = bool(cves)
            has_tech_match = bool(matched_techs)
            has_actor = bool(actors)
            has_technique = bool(techniques)
            industry_match = industry.lower() in [i.lower() for i in industries] if industry else False

            # 심각도 판정
            severity = "info"
            if has_cve and has_tech_match:
                severity = "critical"
            elif has_cve:
                severity = "high"
            elif has_actor and (has_tech_match or industry_match):
                severity = "high"
            elif has_actor or (has_technique and has_tech_match):
                severity = "medium"
            elif has_technique:
                severity = "low"

            # info는 매칭 없이도 저장 (trend 분석용), 알림은 medium+ 부터
            if severity == "info":
                continue

            # Alert 생성
            alert_title = item["title"][:120]
            alert_desc_parts = [item["description"][:400]]

            tags = []
            if cves:
                tags.append(f"CVE: {', '.join(cves[:5])}")
            if matched_techs:
                tags.append(f"Tech match: {', '.join(matched_techs[:5])}")
            if actors:
                tags.append(f"Actors: {', '.join(actors[:3])}")
            if techniques:
                tags.append(f"TTPs: {', '.join(techniques[:5])}")
            if industry_match:
                tags.append(f"Industry match: {industry}")

            if tags:
                alert_desc_parts.append(" | ".join(tags))

            alerts.append(WatcherAlert(
                watcher_name=self.name,
                severity=severity,
                title=f"[{item['source']}] {alert_title}",
                description="\n".join(alert_desc_parts),
                target=", ".join(matched_techs[:3]) if matched_techs else "",
                source_url=item["link"],
                data={
                    "id": item["id"],
                    "source": item["source"],
                    "pub_date": item["pub_date"],
                    "cves": cves,
                    "threat_actors": actors,
                    "techniques": techniques,
                    "industries": industries,
                    "matched_technologies": matched_techs,
                },
                actionable=bool(cves and matched_techs),
            ))

        return alerts

    async def act(self, alerts: list[WatcherAlert]) -> int:
        """알림 처리 — 기본 동작은 BaseWatcher가 수행. 반환: 행동 수."""
        return 0
