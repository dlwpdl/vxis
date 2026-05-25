"""인프라 변화 감시 — 포트 변화, DNS 변화, HTTP 헤더 변화를 감지한다.

감지 대상:
    - 새로 열린 포트 (nmap --top-ports 100)
    - DNS 레코드 변화 (A, AAAA, MX, NS, TXT)
    - HTTP 응답 헤더/상태 변화
    - 보안 헤더 제거 (X-Frame-Options, CSP 등)

도구 의존성:
    - nmap: 미설치 시 포트 스캔 건너뜀
    - dig: 미설치 시 DNS 조회 건너뜀
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import shutil
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .base import BaseWatcher, WatcherAlert, register_watcher

logger = logging.getLogger(__name__)

# agent_memory.json 위치
_MEMORY_PATH = Path(__file__).parent.parent / "data" / "agent_memory.json"

# 포트 스캔 타임아웃 (초)
_NMAP_TIMEOUT = 120

# HTTP 요청 타임아웃 (초)
_HTTP_TIMEOUT = 15

# 보안 헤더 목록 (제거되면 high 알림)
_SECURITY_HEADERS = [
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-xss-protection",
    "permissions-policy",
    "referrer-policy",
]

# DNS 레코드 타입
_DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT"]


def _load_targets() -> list[str]:
    """agent_memory.json에서 감시 대상 URL/호스트 목록을 반환한다."""
    if not _MEMORY_PATH.exists():
        logger.debug("[InfraDrift] agent_memory.json 없음: %s", _MEMORY_PATH)
        return []

    try:
        data = json.loads(_MEMORY_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("[InfraDrift] agent_memory.json 로드 실패: %s", exc)
        return []

    targets: list[str] = []

    # 형식 1: {"targets": {"url": {...}}}
    raw_targets = data.get("targets", {})
    if isinstance(raw_targets, dict):
        targets.extend(raw_targets.keys())

    # 형식 2: {"scans": [{"target": "..."}]}
    for scan in data.get("scans", []):
        if isinstance(scan, dict) and scan.get("target"):
            targets.append(scan["target"])

    return list(dict.fromkeys(targets))  # 중복 제거, 순서 유지


def _extract_hostname(target: str) -> str:
    """URL 또는 호스트명에서 순수 호스트명을 추출한다."""
    # https://example.com/path → example.com
    host = target.strip()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/")[0].split("?")[0].split("#")[0]
    # 포트 제거: example.com:8080 → example.com
    if ":" in host and not host.startswith("["):
        host = host.rsplit(":", 1)[0]
    return host


def _run_nmap(host: str) -> dict[str, Any]:
    """nmap으로 상위 100개 포트를 스캔한다.

    Returns:
        {"open_ports": [{"port": 80, "service": "http"}, ...], "error": ""}
    """
    result: dict[str, Any] = {"open_ports": [], "error": ""}

    if not shutil.which("nmap"):
        result["error"] = "nmap 미설치"
        logger.debug("[InfraDrift] nmap 미설치, 포트 스캔 건너뜀")
        return result

    cmd = [
        "nmap",
        "--top-ports",
        "100",
        "-T4",
        "--open",
        "-oG",
        "-",  # Grepable 형식으로 stdout 출력
        host,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_NMAP_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        result["error"] = f"nmap 타임아웃 ({_NMAP_TIMEOUT}초)"
        logger.warning("[InfraDrift] nmap 타임아웃: %s", host)
        return result
    except Exception as exc:
        result["error"] = f"nmap 실행 오류: {exc}"
        logger.warning("[InfraDrift] nmap 실행 실패 (%s): %s", host, exc)
        return result

    # Grepable 출력 파싱: "80/open/tcp//http///"
    ports: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        if not line.startswith("Host:"):
            continue
        if "Ports:" not in line:
            continue
        ports_section = line.split("Ports:")[1].strip()
        for port_entry in ports_section.split(","):
            parts = port_entry.strip().split("/")
            if len(parts) >= 3 and parts[1] == "open":
                try:
                    port_num = int(parts[0])
                    service = parts[4] if len(parts) > 4 else ""
                    ports.append({"port": port_num, "service": service})
                except (ValueError, IndexError):
                    continue

    result["open_ports"] = ports
    logger.debug("[InfraDrift] nmap 완료 (%s): %d개 포트 열림", host, len(ports))
    return result


def _run_dig(host: str) -> dict[str, list[str]]:
    """dig으로 DNS 레코드를 조회한다.

    Returns:
        {"A": ["1.2.3.4"], "MX": ["10 mail.example.com"], ...}
    """
    records: dict[str, list[str]] = {rtype: [] for rtype in _DNS_RECORD_TYPES}

    if not shutil.which("dig"):
        logger.debug("[InfraDrift] dig 미설치, DNS 조회 건너뜀")
        return records

    for rtype in _DNS_RECORD_TYPES:
        cmd = ["dig", "+short", rtype, host]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            records[rtype] = sorted(lines)
        except Exception as exc:
            logger.debug("[InfraDrift] dig %s %s 실패: %s", rtype, host, exc)

    return records


def _fetch_http_headers(target: str) -> dict[str, Any]:
    """HTTP(S) 응답 헤더와 상태 코드를 가져온다.

    Returns:
        {"status": 200, "headers": {"server": "nginx", ...}, "error": ""}
    """
    result: dict[str, Any] = {"status": 0, "headers": {}, "error": ""}

    url = target if "://" in target else f"https://{target}"

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "VXIS-InfraDrift/1.0"},
        method="HEAD",
    )
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            result["status"] = resp.status
            result["headers"] = {k.lower(): v for k, v in resp.headers.items()}
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["headers"] = {k.lower(): v for k, v in e.headers.items()}
    except Exception as exc:
        result["error"] = str(exc)
        logger.debug("[InfraDrift] HTTP 헤더 조회 실패 (%s): %s", url, exc)

    return result


def _scan_target(target: str) -> dict[str, Any]:
    """단일 타겟에 대해 포트, DNS, HTTP 헤더를 수집한다."""
    host = _extract_hostname(target)
    return {
        "target": target,
        "host": host,
        "nmap": _run_nmap(host),
        "dns": _run_dig(host),
        "http": _fetch_http_headers(target),
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


def _make_scan_id(target: str, scanned_at: str) -> str:
    """스캔 결과의 고유 ID를 생성한다."""
    raw = f"{target}:{scanned_at}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@register_watcher
class InfraDriftWatcher(BaseWatcher):
    """인프라 변화 감시 워처.

    타겟의 포트, DNS 레코드, HTTP 헤더를 주기적으로 스캔하여
    이전 결과와 비교한다. 변화가 감지되면 알림을 생성한다.
    """

    name = "infra_drift"
    icon = "🔄"
    poll_interval = 21600  # 6시간

    # ── 스캔 결과 상태 관리 ─────────────────────────────────────────

    def _load_scan_state(self) -> dict[str, Any]:
        """이전 스캔 결과를 로드한다."""
        state = self._load_state()
        return state.get("scans", {})

    def _save_scan_state(self, scans: dict[str, Any]) -> None:
        """현재 스캔 결과를 저장한다."""
        state = self._load_state()
        state["scans"] = scans
        state["last_check"] = datetime.now(timezone.utc).isoformat()
        self._save_state(state)

    # ── fetch / match / act ────────────────────────────────────────

    async def fetch(self) -> list[dict[str, Any]]:
        """모든 타겟을 스캔하고 결과를 반환한다."""
        targets = _load_targets()
        if not targets:
            logger.info("[InfraDrift] 감시 대상 없음. agent_memory.json을 확인하세요.")
            return []

        logger.info("[InfraDrift] %d개 타겟 스캔 시작", len(targets))

        items: list[dict[str, Any]] = []
        loop = asyncio.get_event_loop()

        for target in targets:
            try:
                # 블로킹 I/O를 이벤트 루프 스레드풀에서 실행
                scan = await loop.run_in_executor(None, _scan_target, target)
                scan["id"] = _make_scan_id(target, scan["scanned_at"])
                items.append(scan)
                logger.debug("[InfraDrift] 스캔 완료: %s", target)
            except Exception as exc:
                logger.warning("[InfraDrift] 스캔 실패 (%s): %s", target, exc)

        return items

    async def match(self, items: list[dict[str, Any]]) -> list[WatcherAlert]:
        """현재 스캔 결과를 이전 결과와 비교하여 변화를 감지한다."""
        alerts: list[WatcherAlert] = []
        prev_scans = self._load_scan_state()
        new_scans: dict[str, Any] = {}

        for item in items:
            target = item["target"]
            prev = prev_scans.get(target)
            current = item

            # 현재 스캔을 다음 비교를 위해 저장
            new_scans[target] = {
                "nmap": current["nmap"],
                "dns": current["dns"],
                "http": current["http"],
                "scanned_at": current["scanned_at"],
            }

            if prev is None:
                # 최초 스캔: 기준선만 저장
                logger.info("[InfraDrift] 최초 스캔 기준선 저장: %s", target)
                continue

            # ── 포트 변화 감지 ──────────────────────────────────────
            prev_ports = {p["port"] for p in prev.get("nmap", {}).get("open_ports", [])}
            curr_ports = {p["port"] for p in current["nmap"].get("open_ports", [])}

            new_ports = curr_ports - prev_ports
            closed_ports = prev_ports - curr_ports

            for port in new_ports:
                service = next(
                    (p["service"] for p in current["nmap"]["open_ports"] if p["port"] == port),
                    "",
                )
                alerts.append(
                    WatcherAlert(
                        watcher_name=self.name,
                        severity="medium",
                        title=f"새 포트 열림: {port}/{service or 'unknown'}",
                        description=f"타겟 {target}에서 포트 {port}({service})가 새로 열렸습니다.",
                        target=target,
                        data={"port": port, "service": service},
                        actionable=True,
                    )
                )
                logger.info("[InfraDrift] 새 포트 감지: %s → %d/%s", target, port, service)

            for port in closed_ports:
                logger.debug("[InfraDrift] 포트 닫힘 (알림 없음): %s → %d", target, port)

            # ── DNS 변화 감지 ──────────────────────────────────────
            prev_dns: dict[str, list[str]] = prev.get("dns", {})
            curr_dns: dict[str, list[str]] = current["dns"]

            for rtype in _DNS_RECORD_TYPES:
                prev_records = set(prev_dns.get(rtype, []))
                curr_records = set(curr_dns.get(rtype, []))

                new_records = curr_records - prev_records
                removed_records = prev_records - curr_records

                if new_records or removed_records:
                    severity = "info" if rtype in ("TXT",) else "medium"
                    title = f"DNS {rtype} 레코드 변경"
                    description = (
                        f"타겟 {target}의 DNS {rtype} 레코드가 변경되었습니다. "
                        f"추가: {sorted(new_records)}, 제거: {sorted(removed_records)}"
                    )
                    alerts.append(
                        WatcherAlert(
                            watcher_name=self.name,
                            severity=severity,
                            title=title,
                            description=description,
                            target=target,
                            data={
                                "record_type": rtype,
                                "added": sorted(new_records),
                                "removed": sorted(removed_records),
                            },
                            actionable=False,
                        )
                    )
                    logger.info("[InfraDrift] DNS %s 변화: %s", rtype, target)

            # ── HTTP 헤더 / 보안 헤더 변화 감지 ─────────────────────
            prev_http = prev.get("http", {})
            curr_http = current["http"]

            prev_status = prev_http.get("status", 0)
            curr_status = curr_http.get("status", 0)

            if prev_status != curr_status and curr_status != 0 and prev_status != 0:
                alerts.append(
                    WatcherAlert(
                        watcher_name=self.name,
                        severity="medium",
                        title=f"HTTP 상태 코드 변경: {prev_status} → {curr_status}",
                        description=(
                            f"타겟 {target}의 HTTP 응답 코드가 "
                            f"{prev_status}에서 {curr_status}로 변경되었습니다."
                        ),
                        target=target,
                        data={"prev_status": prev_status, "curr_status": curr_status},
                        actionable=False,
                    )
                )

            # 보안 헤더 제거 감지
            prev_headers = prev_http.get("headers", {})
            curr_headers = curr_http.get("headers", {})

            for sec_header in _SECURITY_HEADERS:
                was_present = sec_header in prev_headers
                is_present = sec_header in curr_headers
                if was_present and not is_present:
                    alerts.append(
                        WatcherAlert(
                            watcher_name=self.name,
                            severity="high",
                            title=f"보안 헤더 제거됨: {sec_header}",
                            description=(
                                f"타겟 {target}에서 보안 헤더 '{sec_header}'가 제거되었습니다. "
                                f"이전 값: {prev_headers.get(sec_header, 'N/A')}"
                            ),
                            target=target,
                            data={
                                "header": sec_header,
                                "prev_value": prev_headers.get(sec_header, ""),
                            },
                            actionable=True,
                        )
                    )
                    logger.warning("[InfraDrift] 보안 헤더 제거: %s ← %s", sec_header, target)

        # 스캔 결과 저장 (기준선 업데이트)
        # 이미 있는 타겟 데이터는 새 스캔으로 갱신하되, 신규 타겟은 추가
        merged = dict(prev_scans)
        merged.update(new_scans)
        self._save_scan_state(merged)

        return alerts

    async def act(self, alerts: list[WatcherAlert]) -> int:
        """중요한 변화가 감지된 타겟을 재스캔 큐에 등록한다.

        현재 구현: 로그에 재스캔 필요 타겟을 기록하고 카운트를 반환한다.
        """
        actionable = [a for a in alerts if a.actionable]
        if not actionable:
            return 0

        # 타겟별로 그룹화하여 중복 재스캔 방지
        rescan_targets = list({a.target for a in actionable})

        for target in rescan_targets:
            logger.warning("[InfraDrift] 재스캔 필요 타겟: %s (변화 감지)", target)

        return len(rescan_targets)
