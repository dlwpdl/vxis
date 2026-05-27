from __future__ import annotations

import asyncio
import json
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

from vxis.agent.sdk_runtime.events import SDKEventJournal

if TYPE_CHECKING:
    from agents.items import TResponseInputItem
    from agents.memory import Session


AgentStatus = Literal["running", "waiting", "completed", "blocked", "failed", "crashed", "stopped"]
ACTIVE_AGENT_STATUSES = {"running", "waiting"}
TERMINAL_AGENT_STATUSES = {"completed", "blocked", "failed", "crashed", "stopped"}


@dataclass(slots=True)
class SDKAgentRuntime:
    session: "Session | None" = None
    task: asyncio.Task[Any] | None = None
    wake: asyncio.Event = field(default_factory=asyncio.Event)


@dataclass(slots=True)
class SDKAgentRecord:
    agent_id: str
    name: str
    role: str
    task: str
    status: AgentStatus
    parent_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    pending_count: int = 0
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "role": self.role,
            "task": self.task,
            "status": self.status,
            "parent_id": self.parent_id,
            "metadata": dict(self.metadata),
            "pending_count": self.pending_count,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SDKAgentRecord":
        return cls(
            agent_id=str(value.get("agent_id") or value.get("id") or ""),
            name=str(value.get("name") or value.get("agent_id") or ""),
            role=str(value.get("role") or "worker"),
            task=str(value.get("task") or ""),
            status=_coerce_status(value.get("status")),
            parent_id=str(value["parent_id"]) if value.get("parent_id") is not None else None,
            metadata=dict(value.get("metadata") or {}),
            pending_count=max(0, int(value.get("pending_count") or 0)),
            created_at=str(value.get("created_at") or ""),
            updated_at=str(value.get("updated_at") or ""),
        )


class SDKAgentCoordinator:
    """Single owner for VXIS SDK agent graph state and parent/child messaging."""

    def __init__(
        self,
        *,
        snapshot_path: str | Path | None = None,
        event_journal: SDKEventJournal | None = None,
    ) -> None:
        self._records: dict[str, SDKAgentRecord] = {}
        self._runtimes: dict[str, SDKAgentRuntime] = {}
        self._lock = asyncio.Lock()
        self.snapshot_path = Path(snapshot_path) if snapshot_path is not None else None
        self.event_journal = event_journal

    async def register(
        self,
        agent_id: str,
        *,
        name: str,
        role: str,
        task: str,
        parent_id: str | None = None,
        metadata: dict[str, Any] | None = None,
        status: AgentStatus | str = "running",
    ) -> SDKAgentRecord:
        clean_id = str(agent_id).strip()
        if not clean_id:
            raise ValueError("agent_id is required")
        now = _now_iso()
        async with self._lock:
            record = SDKAgentRecord(
                agent_id=clean_id,
                name=str(name or clean_id),
                role=str(role or "worker"),
                task=str(task or ""),
                status=_coerce_status(status),
                parent_id=str(parent_id) if parent_id else None,
                metadata=dict(metadata or {}),
                created_at=now,
                updated_at=now,
            )
            self._records[clean_id] = record
            self._runtimes.setdefault(clean_id, SDKAgentRuntime())
        await self._record_event("agent_registered", clean_id, record.to_dict())
        await self._save_snapshot()
        return record

    async def attach_session(self, agent_id: str, session: "Session") -> None:
        async with self._lock:
            self._require_record(agent_id)
            self._runtimes.setdefault(agent_id, SDKAgentRuntime()).session = session
        await self._record_event("session_attached", agent_id, {})

    async def attach_task(self, agent_id: str, task: asyncio.Task[Any]) -> None:
        async with self._lock:
            self._require_record(agent_id)
            self._runtimes.setdefault(agent_id, SDKAgentRuntime()).task = task
        await self._record_event("task_attached", agent_id, {})

    async def set_status(self, agent_id: str, status: AgentStatus | str) -> bool:
        coerced = _coerce_status(status)
        async with self._lock:
            record = self._records.get(agent_id)
            if record is None:
                return False
            record.status = coerced
            record.updated_at = _now_iso()
            self._runtimes.setdefault(agent_id, SDKAgentRuntime()).wake.set()
        await self._record_event("agent_status", agent_id, {"status": coerced})
        await self._save_snapshot()
        return True

    async def send(
        self,
        sender_id: str,
        recipient_id: str,
        content: str,
        *,
        message_type: str = "information",
        priority: str = "normal",
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        message = {
            "from": str(sender_id or "unknown"),
            "to": str(recipient_id or ""),
            "type": str(message_type or "information"),
            "priority": str(priority or "normal"),
            "content": str(content or ""),
            "metadata": dict(metadata or {}),
        }
        async with self._lock:
            recipient = self._records.get(recipient_id)
            runtime = self._runtimes.setdefault(recipient_id, SDKAgentRuntime())
            session = runtime.session
            if recipient is None or session is None:
                return False

        await session.add_items([self._message_to_session_item(message)])
        async with self._lock:
            recipient = self._records.get(recipient_id)
            if recipient is None:
                return False
            recipient.pending_count += 1
            recipient.updated_at = _now_iso()
            self._runtimes.setdefault(recipient_id, SDKAgentRuntime()).wake.set()
        await self._record_event(
            "message_sent",
            recipient_id,
            {
                "from": sender_id,
                "to": recipient_id,
                "type": message["type"],
                "priority": message["priority"],
                "metadata": message["metadata"],
            },
        )
        await self._save_snapshot()
        return True

    async def complete_agent(
        self,
        agent_id: str,
        *,
        result_summary: str,
        status: AgentStatus | str = "completed",
        findings: list[dict[str, Any]] | None = None,
        evidence_artifact: dict[str, Any] | None = None,
        report_to_parent: bool = True,
    ) -> bool:
        coerced = _coerce_terminal_status(status)
        async with self._lock:
            record = self._records.get(agent_id)
            if record is None:
                return False
            parent_id = record.parent_id
            record.status = coerced
            record.updated_at = _now_iso()
            self._runtimes.setdefault(agent_id, SDKAgentRuntime()).wake.set()
            report = {
                "type": "agent_completion",
                "agent_id": agent_id,
                "name": record.name,
                "role": record.role,
                "status": coerced,
                "result_summary": str(result_summary or ""),
                "findings": list(findings or []),
                "evidence_artifact": dict(evidence_artifact or {}),
            }
        await self._record_event("agent_completed", agent_id, report)
        if report_to_parent and parent_id:
            await self.send(
                agent_id,
                parent_id,
                json.dumps(report, ensure_ascii=False, default=str),
                message_type="completion",
                priority="high",
                metadata={"agent_id": agent_id, "status": coerced},
            )
        await self._save_snapshot()
        return True

    async def wait_for_message(self, agent_id: str, *, timeout_seconds: float | None = None) -> bool:
        while True:
            async with self._lock:
                record = self._records.get(agent_id)
                if record is None:
                    return False
                if record.pending_count > 0:
                    return True
                wake = self._runtimes.setdefault(agent_id, SDKAgentRuntime()).wake
                wake.clear()
            try:
                if timeout_seconds is None:
                    await wake.wait()
                else:
                    await asyncio.wait_for(wake.wait(), timeout_seconds)
            except TimeoutError:
                return False

    async def consume_pending(
        self,
        agent_id: str,
        *,
        include_items: bool = False,
    ) -> tuple[int, list[Any]]:
        async with self._lock:
            record = self._records.get(agent_id)
            if record is None:
                return 0, []
            count = record.pending_count
            record.pending_count = 0
            record.updated_at = _now_iso()
            session = self._runtimes.setdefault(agent_id, SDKAgentRuntime()).session
        await self._save_snapshot()
        if not include_items or session is None or count <= 0:
            return count, []
        items = await session.get_items()
        return count, list(items[-count:])

    async def active_agents_except(self, agent_id: str) -> list[dict[str, Any]]:
        async with self._lock:
            return [
                record.to_dict()
                for record in self._records.values()
                if record.agent_id != agent_id and record.status in ACTIVE_AGENT_STATUSES
            ]

    async def get_record(self, agent_id: str) -> SDKAgentRecord | None:
        async with self._lock:
            record = self._records.get(agent_id)
            if record is None:
                return None
            return SDKAgentRecord.from_dict(record.to_dict())

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "agents": {
                    agent_id: record.to_dict() for agent_id, record in self._records.items()
                },
                "parent_of": {
                    agent_id: record.parent_id for agent_id, record in self._records.items()
                },
                "statuses": {
                    agent_id: record.status for agent_id, record in self._records.items()
                },
            }

    async def restore(self, snapshot: dict[str, Any]) -> None:
        raw_agents = snapshot.get("agents") if isinstance(snapshot, dict) else {}
        records: dict[str, SDKAgentRecord] = {}
        if isinstance(raw_agents, dict):
            for agent_id, value in raw_agents.items():
                if not isinstance(value, dict):
                    continue
                record = SDKAgentRecord.from_dict({"agent_id": agent_id, **value})
                if record.agent_id:
                    records[record.agent_id] = record
        async with self._lock:
            self._records = records
            for agent_id in records:
                self._runtimes.setdefault(agent_id, SDKAgentRuntime())

    async def restore_from_path(self, path: str | Path | None = None) -> bool:
        source = Path(path) if path is not None else self.snapshot_path
        if source is None or not source.exists():
            return False
        data = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return False
        await self.restore(data)
        return True

    async def close_sessions(self) -> None:
        async with self._lock:
            sessions = [
                runtime.session for runtime in self._runtimes.values() if runtime.session is not None
            ]
        for session in sessions:
            close = getattr(session, "close", None)
            if callable(close):
                close()

    def _require_record(self, agent_id: str) -> SDKAgentRecord:
        record = self._records.get(agent_id)
        if record is None:
            raise KeyError(f"unknown SDK agent: {agent_id}")
        return record

    async def _record_event(
        self,
        event_type: str,
        agent_id: str,
        payload: dict[str, Any],
    ) -> None:
        if self.event_journal is not None:
            await self.event_journal.append(event_type, agent_id=agent_id, payload=payload)

    async def _save_snapshot(self) -> None:
        if self.snapshot_path is None:
            return
        snapshot = await self.snapshot()
        payload = json.dumps(snapshot, ensure_ascii=False, default=str)
        self.snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(self.snapshot_path.parent),
            prefix=f".{self.snapshot_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(self.snapshot_path)

    def _message_to_session_item(self, message: dict[str, Any]) -> "TResponseInputItem":
        sender = str(message.get("from") or "unknown")
        content = str(message.get("content") or "")
        if sender == "user":
            return cast("TResponseInputItem", {"role": "user", "content": content})
        sender_name = self._records.get(sender).name if sender in self._records else sender
        return cast(
            "TResponseInputItem",
            {
                "role": "user",
                "content": (
                    f"[VXIS message from {sender_name} ({sender}) "
                    f"type={message.get('type', 'information')} "
                    f"priority={message.get('priority', 'normal')}]\n{content}"
                ),
            },
        )


def _coerce_status(value: Any) -> AgentStatus:
    text = str(value or "running").strip().lower()
    if text in ACTIVE_AGENT_STATUSES or text in TERMINAL_AGENT_STATUSES:
        return cast("AgentStatus", text)
    return "running"


def _coerce_terminal_status(value: Any) -> AgentStatus:
    status = _coerce_status(value)
    if status in TERMINAL_AGENT_STATUSES:
        return status
    return "completed"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
