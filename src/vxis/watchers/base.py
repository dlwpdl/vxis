"""VXIS Watcher Framework — 11개 워처의 공통 기반.

모든 워처는 같은 패턴:
    fetch() → match() → act() → notify()

BaseWatcher를 상속하고 3개 메서드만 구현하면 새 워처 완성.

Architecture:
    ┌─────────────────────────────────────────┐
    │  WatcherOrchestrator                     │
    │  (모든 워처를 병렬 실행 + 통합 알림)       │
    └────────────┬────────────────────────────┘
                 │
    ┌────────────▼────────────────────────────┐
    │  BaseWatcher                             │
    │  fetch() → match() → act() → notify()  │
    └─────────────────────────────────────────┘
                 │
    ┌────┬───┬───┼───┬───┬───┬───┬───┬───┬───┐
    │ 1  │ 2 │ 3 │ 4 │ 5 │ 6 │ 7 │ 8 │ 9 │10│11│
    └────┴───┴───┴───┴───┴───┴───┴───┴───┴───┘
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.request
import urllib.error
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

STATE_DIR = Path("~/.vxis/watchers").expanduser()


# ── Common data models ──────────────────────────────────────────

@dataclass
class WatcherAlert:
    """워처가 생성하는 알림."""

    watcher_name: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    target: str = ""  # 매칭된 타겟 (있으면)
    source_url: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    actionable: bool = False  # 자동 행동이 가능한 알림인가


@dataclass
class WatcherResult:
    """워처 1회 실행 결과."""

    watcher_name: str
    alerts: list[WatcherAlert] = field(default_factory=list)
    items_fetched: int = 0
    items_matched: int = 0
    actions_taken: int = 0
    duration_seconds: float = 0.0
    error: str = ""


# ── Base Watcher ────────────────────────────────────────────────

class BaseWatcher(ABC):
    """모든 워처의 기반 클래스.

    구현 필요:
        - name: str (워처 이름)
        - fetch(): 외부 소스에서 데이터 수집
        - match(): 타겟 프로파일과 매칭
        - act(): 매칭된 항목에 대해 행동

    자동 제공:
        - notify(): Telegram 알림 전송
        - run(): fetch → match → act → notify 루프
        - state 관리: 마지막 체크 시점 저장/로드
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """워처 고유 이름."""
        ...

    @property
    def poll_interval(self) -> int:
        """폴링 간격 (초). 기본 15분."""
        return 900

    @property
    def icon(self) -> str:
        """Telegram 알림용 아이콘."""
        return "\U0001f50d"

    @abstractmethod
    async def fetch(self) -> list[dict[str, Any]]:
        """외부 소스에서 데이터 수집. 새 항목 리스트 반환."""
        ...

    @abstractmethod
    async def match(
        self, items: list[dict[str, Any]]
    ) -> list[WatcherAlert]:
        """수집된 항목을 타겟 프로파일과 매칭. 알림 리스트 반환."""
        ...

    async def act(self, alerts: list[WatcherAlert]) -> int:
        """매칭된 알림에 대해 자동 행동. 기본: 아무것도 안 함. 반환: 행동 수."""
        return 0

    # ── Run loop ────────────────────────────────────────────────

    async def run_once(self) -> WatcherResult:
        """1회 실행: fetch → match → act → notify."""
        start = time.monotonic()
        result = WatcherResult(watcher_name=self.name)

        try:
            # Fetch
            items = await self.fetch()
            result.items_fetched = len(items)

            if not items:
                result.duration_seconds = time.monotonic() - start
                return result

            # Filter already-seen items
            items = self._filter_seen(items)

            # Match
            alerts = await self.match(items)
            result.items_matched = len(alerts)
            result.alerts = alerts

            # Act
            if alerts:
                actions = await self.act(alerts)
                result.actions_taken = actions

            # Mark as seen
            self._mark_seen(items)

        except Exception as exc:
            result.error = str(exc)
            logger.exception("워처 %s 실행 실패", self.name)

        result.duration_seconds = time.monotonic() - start

        logger.info(
            "[%s] 완료: %d 수집, %d 매칭, %d 행동, %.1f초",
            self.name,
            result.items_fetched,
            result.items_matched,
            result.actions_taken,
            result.duration_seconds,
        )

        return result

    async def run_loop(self) -> None:
        """무한 루프: run_once → sleep → repeat."""
        logger.info("[%s] 워처 시작 (간격: %d초)", self.name, self.poll_interval)
        while True:
            await self.run_once()
            await asyncio.sleep(self.poll_interval)

    # ── State management ────────────────────────────────────────

    def _get_state_path(self) -> Path:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        return STATE_DIR / f"{self.name}_state.json"

    def _load_state(self) -> dict[str, Any]:
        path = self._get_state_path()
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                pass
        return {"seen_ids": [], "last_check": ""}

    def _save_state(self, state: dict[str, Any]) -> None:
        path = self._get_state_path()
        path.write_text(json.dumps(state, ensure_ascii=False, indent=2))

    def _filter_seen(self, items: list[dict]) -> list[dict]:
        """이미 처리한 항목 필터링."""
        state = self._load_state()
        seen = set(state.get("seen_ids", []))
        return [i for i in items if i.get("id", "") not in seen]

    def _mark_seen(self, items: list[dict]) -> None:
        """처리한 항목 ID를 저장."""
        state = self._load_state()
        seen = state.get("seen_ids", [])
        for item in items:
            item_id = item.get("id", "")
            if item_id and item_id not in seen:
                seen.append(item_id)
        # 최대 10,000개 유지
        state["seen_ids"] = seen[-10000:]
        state["last_check"] = datetime.now(timezone.utc).isoformat()
        self._save_state(state)

    # ── HTTP helpers ────────────────────────────────────────────

    @staticmethod
    def _http_get(url: str, headers: dict | None = None, timeout: int = 30) -> dict | list | str:
        """urllib GET 요청. JSON 자동 파싱."""
        req_headers = {
            "User-Agent": "VXIS-Watcher/1.0",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)

        req = urllib.request.Request(url, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode("utf-8")
                try:
                    return json.loads(body)
                except json.JSONDecodeError:
                    return body
        except urllib.error.HTTPError as e:
            logger.debug("HTTP %d from %s", e.code, url)
            return {}
        except Exception as e:
            logger.debug("HTTP error from %s: %s", url, e)
            return {}

    @staticmethod
    def _http_post(url: str, data: dict, headers: dict | None = None, timeout: int = 30) -> dict | list:
        """urllib POST 요청."""
        req_headers = {
            "User-Agent": "VXIS-Watcher/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)

        payload = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(url, data=payload, headers=req_headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            logger.debug("HTTP POST error from %s: %s", url, e)
            return {}


# ── Watcher Registry ────────────────────────────────────────────

_REGISTRY: dict[str, type[BaseWatcher]] = {}


def register_watcher(cls: type[BaseWatcher]) -> type[BaseWatcher]:
    """워처 등록 데코레이터."""
    instance = cls()
    _REGISTRY[instance.name] = cls
    return cls


def get_all_watchers() -> list[BaseWatcher]:
    """등록된 모든 워처 인스턴스 반환."""
    return [cls() for cls in _REGISTRY.values()]


def get_watcher(name: str) -> BaseWatcher | None:
    """이름으로 워처 인스턴스 반환."""
    cls = _REGISTRY.get(name)
    return cls() if cls else None


# ── Watcher Orchestrator ────────────────────────────────────────

class WatcherOrchestrator:
    """모든 워처를 병렬 실행하고 통합 알림을 보내는 오케스트레이터."""

    def __init__(self, watchers: list[BaseWatcher] | None = None) -> None:
        self._watchers = watchers or get_all_watchers()

    async def run_all_once(self) -> list[WatcherResult]:
        """모든 워처를 병렬로 1회 실행."""
        tasks = [w.run_once() for w in self._watchers]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        final = []
        for r in results:
            if isinstance(r, WatcherResult):
                final.append(r)
            elif isinstance(r, Exception):
                final.append(WatcherResult(
                    watcher_name="unknown",
                    error=str(r),
                ))

        # 통합 알림
        all_alerts = [a for r in final for a in r.alerts]
        if all_alerts:
            await self._send_telegram_digest(all_alerts)

        return final

    async def run_loop(self) -> None:
        """모든 워처를 독립적으로 무한 루프 실행."""
        tasks = [w.run_loop() for w in self._watchers]
        await asyncio.gather(*tasks)

    async def _send_telegram_digest(self, alerts: list[WatcherAlert]) -> None:
        """통합 Telegram 알림."""
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
        if not token or not chat_id:
            return

        now = datetime.now(timezone.utc)
        kst_hour = (now.hour + 9) % 24
        time_str = f"{now.strftime('%Y-%m-%d')} {kst_hour:02d}:{now.strftime('%M')} KST"

        severity_icon = {
            "critical": "\U0001f534",
            "high": "\U0001f7e0",
            "medium": "\U0001f7e1",
            "low": "\U0001f7e2",
            "info": "\u26aa",
        }

        lines = [
            f"\U0001f6e1 <b>VXIS Intelligence Network</b>",
            f"\U0001f4c5 {time_str}",
            f"\U0001f4ca {len(alerts)}건 감지\n",
        ]

        # Group by watcher
        by_watcher: dict[str, list[WatcherAlert]] = {}
        for a in alerts:
            by_watcher.setdefault(a.watcher_name, []).append(a)

        for watcher_name, watcher_alerts in by_watcher.items():
            lines.append(f"<b>{watcher_name}</b> ({len(watcher_alerts)}건)")
            for a in watcher_alerts[:5]:
                icon = severity_icon.get(a.severity, "\u2022")
                target_str = f" \u2014 {a.target}" if a.target else ""
                lines.append(f"  {icon} {a.title}{target_str}")
            if len(watcher_alerts) > 5:
                lines.append(f"  <i>+{len(watcher_alerts) - 5}건 더</i>")
            lines.append("")

        text = "\n".join(lines)

        # Send (reuse pattern from upstream_watch)
        payload = json.dumps({
            "chat_id": chat_id,
            "text": text[:4000],
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }).encode("utf-8")

        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=15)
        except Exception:
            pass
