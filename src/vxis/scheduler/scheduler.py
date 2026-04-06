"""Scan schedule store and cron parsing|||스캔 스케줄 저장소 및 cron 파싱."""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

SCHEDULE_PATH = Path.home() / ".vxis" / "schedules.json"


@dataclass
class ScanSchedule:
    """Scheduled scan entry|||예약된 스캔 항목."""

    id: str
    target: str
    cron_expr: str
    profile: str = "standard"
    last_run: Optional[str] = None  # ISO8601
    next_run: Optional[str] = None  # ISO8601
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanSchedule":
        return cls(**data)


def _try_croniter(cron_expr: str, from_time: datetime) -> Optional[datetime]:
    try:
        from croniter import croniter  # type: ignore

        itr = croniter(cron_expr, from_time)
        return itr.get_next(datetime)
    except Exception:
        return None


def calculate_next_run(cron_expr: str, from_time: Optional[datetime] = None) -> datetime:
    """Compute next run time. Uses croniter if available, else simple parser.

    |||다음 실행 시각 계산. croniter 사용 가능하면 사용, 아니면 단순 파서.

    Supported simple patterns when croniter unavailable:
      - "@hourly"           -> +1h
      - "@daily" / "@midnight" -> next midnight UTC
      - "@weekly"           -> +7d
      - "*/N * * * *"       -> +N minutes
      - "0 */N * * *"       -> +N hours
      - "M H * * *"         -> next daily at H:M UTC
    """
    now = from_time or datetime.utcnow()

    cr = _try_croniter(cron_expr, now)
    if cr is not None:
        return cr

    expr = cron_expr.strip()
    if expr in ("@hourly",):
        return now + timedelta(hours=1)
    if expr in ("@daily", "@midnight"):
        nxt = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        return nxt
    if expr == "@weekly":
        return now + timedelta(days=7)

    parts = expr.split()
    if len(parts) == 5:
        minute, hour, dom, mon, dow = parts
        # */N * * * *
        if minute.startswith("*/") and hour == "*" and dom == "*" and mon == "*" and dow == "*":
            try:
                n = int(minute[2:])
                return now + timedelta(minutes=max(1, n))
            except ValueError:
                pass
        # 0 */N * * *
        if minute == "0" and hour.startswith("*/") and dom == "*" and mon == "*" and dow == "*":
            try:
                n = int(hour[2:])
                return now + timedelta(hours=max(1, n))
            except ValueError:
                pass
        # M H * * * (daily at fixed time)
        if dom == "*" and mon == "*" and dow == "*":
            try:
                m = int(minute)
                h = int(hour)
                candidate = now.replace(hour=h, minute=m, second=0, microsecond=0)
                if candidate <= now:
                    candidate += timedelta(days=1)
                return candidate
            except ValueError:
                pass

    # Fallback: 1 hour from now
    return now + timedelta(hours=1)


class ScheduleStore:
    """JSON-backed schedule storage|||JSON 기반 스케줄 저장소."""

    def __init__(self, path: Path = SCHEDULE_PATH) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._schedules: dict[str, ScanSchedule] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            self._schedules = {}
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self._schedules = {
                sid: ScanSchedule.from_dict(data) for sid, data in raw.items()
            }
        except (json.JSONDecodeError, OSError, TypeError):
            self._schedules = {}

    def _save(self) -> None:
        data = {sid: s.to_dict() for sid, s in self._schedules.items()}
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def add_schedule(
        self,
        target: str,
        cron_expr: str,
        profile: str = "standard",
    ) -> ScanSchedule:
        sid = uuid.uuid4().hex[:8]
        next_run = calculate_next_run(cron_expr).isoformat()
        sched = ScanSchedule(
            id=sid,
            target=target,
            cron_expr=cron_expr,
            profile=profile,
            next_run=next_run,
        )
        self._schedules[sid] = sched
        self._save()
        return sched

    def remove_schedule(self, schedule_id: str) -> bool:
        if schedule_id in self._schedules:
            del self._schedules[schedule_id]
            self._save()
            return True
        return False

    def list_schedules(self) -> list[ScanSchedule]:
        return list(self._schedules.values())

    def get(self, schedule_id: str) -> Optional[ScanSchedule]:
        return self._schedules.get(schedule_id)

    def enable(self, schedule_id: str) -> bool:
        s = self._schedules.get(schedule_id)
        if not s:
            return False
        s.enabled = True
        self._save()
        return True

    def disable(self, schedule_id: str) -> bool:
        s = self._schedules.get(schedule_id)
        if not s:
            return False
        s.enabled = False
        self._save()
        return True

    def mark_ran(self, schedule_id: str, ran_at: Optional[datetime] = None) -> None:
        s = self._schedules.get(schedule_id)
        if not s:
            return
        ran = ran_at or datetime.utcnow()
        s.last_run = ran.isoformat()
        s.next_run = calculate_next_run(s.cron_expr, ran).isoformat()
        self._save()

    def due_schedules(self, now: Optional[datetime] = None) -> list[ScanSchedule]:
        cur = now or datetime.utcnow()
        out: list[ScanSchedule] = []
        for s in self._schedules.values():
            if not s.enabled or not s.next_run:
                continue
            try:
                nxt = datetime.fromisoformat(s.next_run)
            except ValueError:
                continue
            if nxt <= cur:
                out.append(s)
        return out
