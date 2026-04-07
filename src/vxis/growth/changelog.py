"""Append-only growth change log|||Append-only 변경 이력."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path


class ChangeLog:
    """JSONL-backed event log|||JSONL 기반 이벤트 로그."""

    def __init__(self, log_path: Path | None = None) -> None:
        self.log_path = log_path or Path(".vxis/growth_log.jsonl")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event_type: str, data: dict) -> None:
        """Append an event|||이벤트 기록."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            **data,
        }
        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def read_since(self, since_iso: str) -> list[dict]:
        """Return events newer than given ISO timestamp|||이후 이벤트 반환."""
        if not self.log_path.exists():
            return []
        events: list[dict] = []
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("timestamp", "") >= since_iso:
                    events.append(event)
        return events

    def summary(self, days: int = 7) -> dict:
        """Summarize recent events|||최근 이벤트 요약."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=days)
        ).isoformat()
        events = self.read_since(cutoff)
        types = {e.get("event_type", "unknown") for e in events}
        return {
            "total_events": len(events),
            "by_type": {
                t: sum(1 for e in events if e.get("event_type") == t)
                for t in types
            },
            "since": cutoff,
        }
