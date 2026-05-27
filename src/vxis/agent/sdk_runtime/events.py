from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SDKRuntimeEvent:
    sequence: int
    event_type: str
    agent_id: str
    payload: dict[str, Any]
    created_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "event_type": self.event_type,
            "agent_id": self.agent_id,
            "payload": dict(self.payload),
            "created_at": self.created_at,
        }


class SDKEventJournal:
    """Append-only runtime event stream for resume, replay, and TUI drilldown."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = asyncio.Lock()
        self._next_sequence = self._load_next_sequence()

    async def append(
        self,
        event_type: str,
        *,
        agent_id: str = "",
        payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            event = SDKRuntimeEvent(
                sequence=self._next_sequence,
                event_type=str(event_type),
                agent_id=str(agent_id or ""),
                payload=dict(payload or {}),
                created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )
            self._next_sequence += 1
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.to_dict(), ensure_ascii=False, default=str))
                fh.write("\n")
            return event.to_dict()

    def load_events(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    events.append(item)
        if limit is not None and limit >= 0:
            return events[-limit:]
        return events

    def _load_next_sequence(self) -> int:
        max_seen = 0
        for event in self.load_events():
            try:
                max_seen = max(max_seen, int(event.get("sequence") or 0))
            except (TypeError, ValueError):
                continue
        return max_seen + 1
