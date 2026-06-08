from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, time, timezone
from enum import Enum


class State(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    EXPIRED = "expired"
    CLOSED = "closed"


@dataclass
class Scope:
    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)


@dataclass
class Window:
    start: str
    expiry: str


@dataclass
class Policy:
    techniques: list[str] = field(default_factory=list)
    intensity: str = "stealth"
    destructive: bool = False


@dataclass
class Engagement:
    id: str
    name: str
    operator: str
    scope: Scope
    window: Window
    policy: Policy
    state: State = State.DRAFT
    attested: bool = False
    authorization_ref: str = ""
    operator_subject: str = ""
    beacons: list[str] = field(default_factory=list)


def parse_utc_datetime(value: str | datetime, *, end_of_day: bool = False) -> datetime:
    """Parse date or ISO datetime strings into timezone-aware UTC datetimes."""
    if isinstance(value, datetime):
        dt = value
    else:
        raw = str(value or "").strip()
        if not raw:
            raise ValueError("datetime value is empty")
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        if "T" in raw:
            dt = datetime.fromisoformat(raw)
        else:
            day = date.fromisoformat(raw)
            dt = datetime.combine(day, time.max if end_of_day else time.min)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
