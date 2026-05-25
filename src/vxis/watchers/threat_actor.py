"""위협 행위자 추적 — MITRE ATT&CK, CISA KEV, AlienVault OTX를 감시한다.

감시 소스:
    - MITRE ATT&CK: 새로운/업데이트된 공격 기법 탐지
    - CISA KEV: 실제 공격에 활용 중인 취약점 (Known Exploited Vulnerabilities)
    - AlienVault OTX: 위협 인텔리전스 펄스 (API 키 필요: OTX_API_KEY)

심각도 판단:
    - CISA KEV + 타겟 스택 매칭: critical (현재 공격 중)
    - OTX 펄스 + 동일 산업군: medium
    - 새로운 MITRE 기법 추가: medium
    - MITRE 기법 업데이트: info
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import BaseWatcher, WatcherAlert, register_watcher

logger = logging.getLogger(__name__)

# agent_memory.json 위치
_MEMORY_PATH = Path(__file__).parent.parent / "data" / "agent_memory.json"

# MITRE ATT&CK Enterprise JSON
_MITRE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)

# CISA Known Exploited Vulnerabilities
_CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# AlienVault OTX 구독 펄스
_OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


# ── 헬퍼 함수 ──────────────────────────────────────────────────────


def _make_id(source: str, item_id: str) -> str:
    """항목 고유 ID 생성."""
    raw = f"{source}:{item_id}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _load_memory() -> dict[str, Any]:
    """agent_memory.json 전체를 로드한다."""
    if not _MEMORY_PATH.exists():
        return {}
    try:
        return json.loads(_MEMORY_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("[ThreatActor] agent_memory.json 로드 실패: %s", exc)
        return {}


def _load_target_stack() -> dict[str, Any]:
    """감시 대상의 기술 스택, 산업군, 키워드를 반환한다.

    Returns:
        {
            "technologies": ["Next.js", "Node.js", ...],
            "industry": "fintech",
            "keywords": ["payment", "auth", ...],
        }
    """
    data = _load_memory()
    result: dict[str, Any] = {
        "technologies": [],
        "industry": "",
        "keywords": [],
    }

    # 형식 1: {"targets": {"url": {"technologies": [...]}}}
    targets = data.get("targets", {})
    if isinstance(targets, dict):
        for info in targets.values():
            if isinstance(info, dict):
                techs = info.get("technologies", [])
                result["technologies"].extend(techs)
                if not result["industry"]:
                    result["industry"] = info.get("industry", "")
                kws = info.get("keywords", [])
                result["keywords"].extend(kws)

    # 형식 2: {"scans": [...]}
    for scan in data.get("scans", []):
        if isinstance(scan, dict):
            result["technologies"].extend(scan.get("stack", []))

    # 메타 정보
    meta = data.get("meta", {})
    if isinstance(meta, dict):
        if not result["industry"]:
            result["industry"] = meta.get("industry", "")
        result["keywords"].extend(meta.get("keywords", []))

    # 중복 제거
    result["technologies"] = list(dict.fromkeys(result["technologies"]))
    result["keywords"] = list(dict.fromkeys(result["keywords"]))

    return result


def _normalize(text: str) -> str:
    """비교용 소문자 정규화."""
    return text.lower().strip()


def _tech_matches_text(technologies: list[str], text: str) -> list[str]:
    """기술 스택 중 텍스트에 언급된 것들을 반환한다."""
    text_lower = _normalize(text)
    return [t for t in technologies if _normalize(t) in text_lower]


# ── MITRE ATT&CK 수집 ──────────────────────────────────────────────


def _fetch_mitre_techniques(prev_modified: str) -> list[dict[str, Any]]:
    """MITRE ATT&CK에서 새로운/업데이트된 기법을 가져온다.

    Args:
        prev_modified: 마지막 확인 시각 (ISO 8601). 이후 변경된 기법만 반환.

    Returns:
        [{"id": "T1234", "name": "...", "modified": "...", "description": "...", "is_new": bool}, ...]
    """
    logger.info("[ThreatActor] MITRE ATT&CK 조회 중...")

    # MITRE JSON은 크기가 크므로 타임아웃을 넉넉하게
    import urllib.request

    req = urllib.request.Request(
        _MITRE_URL,
        headers={"User-Agent": "VXIS-ThreatWatch/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("[ThreatActor] MITRE 조회 실패: %s", exc)
        return []

    objects = raw.get("objects", [])
    techniques: list[dict[str, Any]] = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("deprecated"):
            continue

        modified = obj.get("modified", "")
        created = obj.get("created", "")

        # 이전 확인 시각 이후 변경된 기법만
        if prev_modified and modified <= prev_modified:
            continue

        # 외부 참조에서 ATT&CK ID (T1234 형식) 추출
        attack_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id", "")
                break

        if not attack_id:
            continue

        # 서브기법 (T1234.001) 포함
        is_subtechnique = "." in attack_id
        name = obj.get("name", "")
        description = obj.get("description", "")[:500]
        platforms = obj.get("x_mitre_platforms", [])
        is_new = created == modified or (prev_modified and created > prev_modified)

        techniques.append(
            {
                "attack_id": attack_id,
                "name": name,
                "description": description,
                "modified": modified,
                "created": created,
                "platforms": platforms,
                "is_new": is_new,
                "is_subtechnique": is_subtechnique,
            }
        )

    logger.info("[ThreatActor] MITRE 기법 %d개 변경 감지", len(techniques))
    return techniques


# ── CISA KEV 수집 ──────────────────────────────────────────────────


def _fetch_cisa_kev(seen_ids: set[str]) -> list[dict[str, Any]]:
    """CISA KEV 목록에서 새로운 항목을 가져온다.

    Returns:
        [{"cveID": "CVE-...", "vendorProject": "...", "product": "...", "dateAdded": "...", ...}, ...]
    """
    logger.info("[ThreatActor] CISA KEV 조회 중...")

    import urllib.request

    req = urllib.request.Request(
        _CISA_KEV_URL,
        headers={"User-Agent": "VXIS-ThreatWatch/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("[ThreatActor] CISA KEV 조회 실패: %s", exc)
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    new_entries: list[dict[str, Any]] = []

    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID", "")
        if cve_id and cve_id not in seen_ids:
            new_entries.append(vuln)

    logger.info("[ThreatActor] CISA KEV 신규 %d개", len(new_entries))
    return new_entries


# ── AlienVault OTX 수집 ────────────────────────────────────────────


def _fetch_otx_pulses(seen_pulse_ids: set[str]) -> list[dict[str, Any]]:
    """AlienVault OTX 구독 펄스에서 새 항목을 가져온다.

    환경 변수: OTX_API_KEY
    """
    api_key = os.environ.get("OTX_API_KEY", "")
    if not api_key:
        logger.debug("[ThreatActor] OTX_API_KEY 미설정, OTX 건너뜀")
        return []

    logger.info("[ThreatActor] AlienVault OTX 조회 중...")

    import urllib.request

    req = urllib.request.Request(
        _OTX_API_URL,
        headers={
            "User-Agent": "VXIS-ThreatWatch/1.0",
            "X-OTX-API-KEY": api_key,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("[ThreatActor] OTX 조회 실패: %s", exc)
        return []

    results = data.get("results", [])
    new_pulses: list[dict[str, Any]] = []

    for pulse in results:
        pulse_id = pulse.get("id", "")
        if pulse_id and pulse_id not in seen_pulse_ids:
            new_pulses.append(pulse)

    logger.info("[ThreatActor] OTX 신규 펄스 %d개", len(new_pulses))
    return new_pulses


# ── 워처 클래스 ────────────────────────────────────────────────────


@register_watcher
class ThreatActorWatcher(BaseWatcher):
    """위협 행위자 추적 워처.

    MITRE ATT&CK 업데이트, CISA KEV 신규 등록, AlienVault OTX 펄스를
    모니터링하여 타겟 스택 및 산업군과의 연관성을 분석한다.
    """

    name = "threat_actor"
    icon = "🎯"
    poll_interval = 86400  # 24시간

    # ── 상태 헬퍼 ─────────────────────────────────────────────────

    def _get_threat_state(self) -> dict[str, Any]:
        """위협 감시 전용 상태를 반환한다."""
        state = self._load_state()
        return state.get(
            "threat",
            {
                "mitre_last_modified": "",
                "cisa_seen_ids": [],
                "otx_seen_pulse_ids": [],
            },
        )

    def _save_threat_state(self, threat_state: dict[str, Any]) -> None:
        """위협 감시 상태를 저장한다."""
        state = self._load_state()
        state["threat"] = threat_state
        state["last_check"] = datetime.now(timezone.utc).isoformat()
        self._save_state(state)

    # ── fetch / match / act ───────────────────────────────────────

    async def fetch(self) -> list[dict[str, Any]]:
        """MITRE, CISA KEV, OTX에서 최신 위협 데이터를 수집한다."""
        threat_state = self._get_threat_state()
        mitre_last_modified: str = threat_state.get("mitre_last_modified", "")
        cisa_seen_ids: set[str] = set(threat_state.get("cisa_seen_ids", []))
        otx_seen_ids: set[str] = set(threat_state.get("otx_seen_pulse_ids", []))

        items: list[dict[str, Any]] = []

        # ── MITRE ATT&CK ──────────────────────────────────────────
        try:
            mitre_techs = _fetch_mitre_techniques(mitre_last_modified)
            for tech in mitre_techs:
                items.append(
                    {
                        "id": _make_id("mitre", tech["attack_id"]),
                        "source": "mitre",
                        "attack_id": tech["attack_id"],
                        "name": tech["name"],
                        "description": tech["description"],
                        "modified": tech["modified"],
                        "platforms": tech["platforms"],
                        "is_new": tech["is_new"],
                        "is_subtechnique": tech["is_subtechnique"],
                    }
                )
        except Exception as exc:
            logger.warning("[ThreatActor] MITRE 처리 실패: %s", exc)

        # ── CISA KEV ──────────────────────────────────────────────
        try:
            kev_entries = _fetch_cisa_kev(cisa_seen_ids)
            for entry in kev_entries:
                cve_id = entry.get("cveID", "")
                items.append(
                    {
                        "id": _make_id("cisa_kev", cve_id),
                        "source": "cisa_kev",
                        "cve_id": cve_id,
                        "vendor": entry.get("vendorProject", ""),
                        "product": entry.get("product", ""),
                        "vulnerability_name": entry.get("vulnerabilityName", ""),
                        "date_added": entry.get("dateAdded", ""),
                        "short_description": entry.get("shortDescription", ""),
                        "required_action": entry.get("requiredAction", ""),
                        "due_date": entry.get("dueDate", ""),
                        "known_ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
                    }
                )
        except Exception as exc:
            logger.warning("[ThreatActor] CISA KEV 처리 실패: %s", exc)

        # ── OTX ───────────────────────────────────────────────────
        try:
            otx_pulses = _fetch_otx_pulses(otx_seen_ids)
            for pulse in otx_pulses:
                pulse_id = pulse.get("id", "")
                tags = pulse.get("tags", [])
                industries = pulse.get("industries", [])
                targeted_countries = pulse.get("targeted_countries", [])
                items.append(
                    {
                        "id": _make_id("otx", pulse_id),
                        "source": "otx",
                        "pulse_id": pulse_id,
                        "name": pulse.get("name", ""),
                        "description": (pulse.get("description", "") or "")[:500],
                        "author": pulse.get("author_name", ""),
                        "tags": tags,
                        "industries": industries,
                        "targeted_countries": targeted_countries,
                        "tlp": pulse.get("tlp", "white"),
                        "adversary": pulse.get("adversary", ""),
                        "malware_families": pulse.get("malware_families", []),
                        "created": pulse.get("created", ""),
                        "indicator_count": pulse.get("indicator_count", 0),
                    }
                )
        except Exception as exc:
            logger.warning("[ThreatActor] OTX 처리 실패: %s", exc)

        logger.info("[ThreatActor] 수집 완료: %d개 항목", len(items))
        return items

    async def match(self, items: list[dict[str, Any]]) -> list[WatcherAlert]:
        """수집된 위협 데이터를 타겟 스택/산업군과 매칭하여 알림을 생성한다."""
        alerts: list[WatcherAlert] = []
        stack_info = _load_target_stack()
        technologies: list[str] = stack_info.get("technologies", [])
        industry: str = stack_info.get("industry", "")
        keywords: list[str] = stack_info.get("keywords", [])

        # 상태 업데이트용 추적
        new_mitre_last_modified = ""
        new_cisa_ids: list[str] = []
        new_otx_ids: list[str] = []

        for item in items:
            source = item.get("source", "")

            # ── MITRE ATT&CK 매칭 ──────────────────────────────────
            if source == "mitre":
                attack_id = item.get("attack_id", "")
                name = item.get("name", "")
                description = item.get("description", "")
                modified = item.get("modified", "")
                is_new = item.get("is_new", False)
                platforms = item.get("platforms", [])

                # MITRE 최신 수정 시각 추적
                if modified > new_mitre_last_modified:
                    new_mitre_last_modified = modified

                # 타겟 스택과의 관련성 판단
                combined_text = f"{name} {description}"
                matched_techs = _tech_matches_text(technologies, combined_text)

                # 플랫폼 관련성 (Windows, Linux, macOS 등)
                platform_relevant = not platforms or any(
                    p.lower() in ("linux", "windows", "macos", "containers", "network")
                    for p in platforms
                )

                if matched_techs or platform_relevant:
                    severity = "medium" if is_new else "info"
                    action_type = "신규 추가" if is_new else "업데이트"
                    mitre_url = (
                        f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/"
                    )

                    alert_description = (
                        f"MITRE ATT&CK 기법 {attack_id} '{name}'이 {action_type}되었습니다."
                    )
                    if matched_techs:
                        alert_description += f" 타겟 스택 관련 기술: {', '.join(matched_techs)}"
                    if platforms:
                        alert_description += f" 대상 플랫폼: {', '.join(platforms[:3])}"

                    alerts.append(
                        WatcherAlert(
                            watcher_name=self.name,
                            severity=severity,
                            title=f"MITRE ATT&CK {action_type}: [{attack_id}] {name}",
                            description=alert_description,
                            target="",
                            source_url=mitre_url,
                            data={
                                "attack_id": attack_id,
                                "name": name,
                                "matched_technologies": matched_techs,
                                "platforms": platforms,
                                "is_new": is_new,
                                "modified": modified,
                            },
                            actionable=False,
                        )
                    )

            # ── CISA KEV 매칭 ──────────────────────────────────────
            elif source == "cisa_kev":
                cve_id = item.get("cve_id", "")
                vendor = item.get("vendor", "")
                product = item.get("product", "")
                description = item.get("short_description", "")
                vuln_name = item.get("vulnerability_name", "")
                known_ransomware = item.get("known_ransomware", "Unknown")

                new_cisa_ids.append(cve_id)

                # 타겟 스택과의 관련성 판단
                combined_text = f"{vendor} {product} {vuln_name} {description}"
                matched_techs = _tech_matches_text(technologies, combined_text)

                # 키워드 매칭
                matched_keywords = [
                    kw for kw in keywords if _normalize(kw) in _normalize(combined_text)
                ]

                if matched_techs or matched_keywords:
                    ransomware_note = ""
                    if known_ransomware and known_ransomware.lower() not in ("unknown", "no"):
                        ransomware_note = f" (랜섬웨어 캠페인 악용: {known_ransomware})"

                    alert_description = (
                        f"CISA KEV에 새로 등록된 취약점 {cve_id}: {vuln_name}. "
                        f"실제 공격에 악용 중인 취약점입니다{ransomware_note}. "
                        f"영향 제품: {vendor} {product}."
                    )
                    if matched_techs:
                        alert_description += f" 타겟 스택 매칭: {', '.join(matched_techs)}"

                    alerts.append(
                        WatcherAlert(
                            watcher_name=self.name,
                            severity="critical",
                            title=f"CISA KEV 신규 등록 (타겟 스택 매칭): {cve_id}",
                            description=alert_description,
                            target="",
                            source_url=_CISA_KEV_URL,
                            data={
                                "cve_id": cve_id,
                                "vendor": vendor,
                                "product": product,
                                "vulnerability_name": vuln_name,
                                "date_added": item.get("date_added", ""),
                                "due_date": item.get("due_date", ""),
                                "required_action": item.get("required_action", ""),
                                "known_ransomware": known_ransomware,
                                "matched_technologies": matched_techs,
                                "matched_keywords": matched_keywords,
                            },
                            actionable=True,
                        )
                    )
                    logger.warning(
                        "[ThreatActor] CISA KEV 타겟 매칭: %s ↔ %s",
                        cve_id,
                        matched_techs or matched_keywords,
                    )
                else:
                    # 매칭 없어도 랜섬웨어 악용 취약점은 medium으로 알림
                    if known_ransomware and known_ransomware.lower() not in ("unknown", "no"):
                        alerts.append(
                            WatcherAlert(
                                watcher_name=self.name,
                                severity="medium",
                                title=f"CISA KEV 랜섬웨어 악용 취약점: {cve_id}",
                                description=(
                                    f"랜섬웨어 캠페인에 악용 중인 취약점 {cve_id}가 CISA KEV에 등록되었습니다. "
                                    f"제품: {vendor} {product}. 캠페인: {known_ransomware}"
                                ),
                                target="",
                                source_url=_CISA_KEV_URL,
                                data={
                                    "cve_id": cve_id,
                                    "vendor": vendor,
                                    "product": product,
                                    "known_ransomware": known_ransomware,
                                    "date_added": item.get("date_added", ""),
                                },
                                actionable=False,
                            )
                        )

            # ── OTX 매칭 ───────────────────────────────────────────
            elif source == "otx":
                pulse_id = item.get("pulse_id", "")
                pulse_name = item.get("name", "")
                description = item.get("description", "")
                tags = item.get("tags", [])
                industries = item.get("industries", [])
                adversary = item.get("adversary", "")
                malware_families = item.get("malware_families", [])

                new_otx_ids.append(pulse_id)

                # 산업군 매칭
                industry_matched = industry and any(
                    _normalize(industry) in _normalize(ind)
                    or _normalize(ind) in _normalize(industry)
                    for ind in industries
                )

                # 기술 스택 매칭
                combined_text = f"{pulse_name} {description} {' '.join(tags)}"
                matched_techs = _tech_matches_text(technologies, combined_text)

                if industry_matched or matched_techs:
                    severity = "medium"
                    alert_description = (
                        f"AlienVault OTX 펄스 '{pulse_name}'이 타겟과 관련된 위협을 포함합니다."
                    )
                    if adversary:
                        alert_description += f" 위협 행위자: {adversary}."
                    if malware_families:
                        fams = [
                            m.get("display_name", "") if isinstance(m, dict) else str(m)
                            for m in malware_families[:3]
                        ]
                        alert_description += f" 악성코드: {', '.join(f for f in fams if f)}."
                    if industry_matched:
                        alert_description += f" 산업군 매칭: {industry}."
                    if matched_techs:
                        alert_description += f" 기술 스택 매칭: {', '.join(matched_techs)}."

                    alerts.append(
                        WatcherAlert(
                            watcher_name=self.name,
                            severity=severity,
                            title=f"OTX 위협 인텔리전스: {pulse_name[:80]}",
                            description=alert_description,
                            target="",
                            source_url=f"https://otx.alienvault.com/pulse/{pulse_id}",
                            data={
                                "pulse_id": pulse_id,
                                "adversary": adversary,
                                "malware_families": [
                                    m.get("display_name", "") if isinstance(m, dict) else str(m)
                                    for m in malware_families[:5]
                                ],
                                "tags": tags[:10],
                                "industries": industries,
                                "indicator_count": item.get("indicator_count", 0),
                                "tlp": item.get("tlp", "white"),
                                "matched_technologies": matched_techs,
                                "industry_matched": industry_matched,
                            },
                            actionable=False,
                        )
                    )

        # ── 상태 업데이트 ────────────────────────────────────────
        threat_state = self._get_threat_state()

        if new_mitre_last_modified:
            threat_state["mitre_last_modified"] = new_mitre_last_modified

        existing_cisa = set(threat_state.get("cisa_seen_ids", []))
        existing_cisa.update(new_cisa_ids)
        # 최대 5,000개 유지
        threat_state["cisa_seen_ids"] = list(existing_cisa)[-5000:]

        existing_otx = set(threat_state.get("otx_seen_pulse_ids", []))
        existing_otx.update(new_otx_ids)
        threat_state["otx_seen_pulse_ids"] = list(existing_otx)[-2000:]

        self._save_threat_state(threat_state)

        return alerts

    async def act(self, alerts: list[WatcherAlert]) -> int:
        """방어 권고사항을 생성하고 에이전트 지식을 업데이트한다."""
        critical_alerts = [a for a in alerts if a.severity == "critical"]
        if not critical_alerts:
            return 0

        actions_taken = 0
        rec_dir = Path("~/.vxis/defense_recommendations").expanduser()
        rec_dir.mkdir(parents=True, exist_ok=True)

        for alert in critical_alerts:
            recommendations = _generate_defense_recommendations(alert)
            if not recommendations:
                continue

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            source_slug = alert.data.get("cve_id", "unknown").replace("-", "_").lower()
            rec_path = rec_dir / f"defense_{source_slug}_{timestamp}.json"

            rec_data = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "alert_title": alert.title,
                "severity": alert.severity,
                "recommendations": recommendations,
                "data": alert.data,
            }

            try:
                rec_path.write_text(
                    json.dumps(rec_data, ensure_ascii=False, indent=2),
                    encoding="utf-8",
                )
                logger.info("[ThreatActor] 방어 권고사항 저장: %s", rec_path)
                actions_taken += 1
            except OSError as exc:
                logger.warning("[ThreatActor] 권고사항 저장 실패: %s", exc)

        return actions_taken


def _generate_defense_recommendations(alert: WatcherAlert) -> list[str]:
    """알림 데이터를 기반으로 방어 권고사항 목록을 생성한다."""
    recommendations: list[str] = []
    data = alert.data

    if "cve_id" in data:
        # CISA KEV 기반 권고사항
        cve_id = data.get("cve_id", "")
        vendor = data.get("vendor", "")
        product = data.get("product", "")
        due_date = data.get("due_date", "")
        required_action = data.get("required_action", "")
        known_ransomware = data.get("known_ransomware", "")

        recommendations.append(f"즉시 {vendor} {product}의 패치 적용 여부를 확인하세요. ({cve_id})")
        if due_date:
            recommendations.append(f"CISA 권고 조치 기한: {due_date} 이내에 완료해야 합니다.")
        if required_action:
            recommendations.append(f"CISA 권고 조치: {required_action}")
        if known_ransomware and known_ransomware.lower() not in ("unknown", "no"):
            recommendations.append(
                f"랜섬웨어 캠페인({known_ransomware})에 악용 중입니다. "
                "네트워크 세그멘테이션 및 백업 상태를 즉시 확인하세요."
            )
        recommendations.append(
            f"NVD에서 영향 버전을 확인하세요: https://nvd.nist.gov/vuln/detail/{cve_id}"
        )

    elif "attack_id" in data:
        # MITRE ATT&CK 기반 권고사항
        attack_id = data.get("attack_id", "")
        name = data.get("name", "")
        recommendations.append(
            f"MITRE ATT&CK {attack_id} '{name}' 기법에 대한 탐지 규칙을 검토하세요."
        )
        recommendations.append(
            f"관련 SIEM/EDR 시그니처 업데이트 필요: "
            f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/"
        )

    return recommendations
