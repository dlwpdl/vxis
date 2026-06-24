from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agents.memory import SQLiteSession


@dataclass(frozen=True)
class SDKRunPaths:
    run_dir: Path
    runtime_dir: Path
    agents_db_path: Path
    agents_snapshot_path: Path
    events_path: Path

    @classmethod
    def for_run_dir(cls, run_dir: str | Path) -> "SDKRunPaths":
        root = Path(run_dir)
        runtime = root / "runtime"
        return cls(
            run_dir=root,
            runtime_dir=runtime,
            agents_db_path=runtime / "agents.db",
            agents_snapshot_path=runtime / "agents.json",
            events_path=runtime / "events.jsonl",
        )


def open_sdk_agent_session(agent_id: str, db_path: str | Path) -> SQLiteSession:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return SQLiteSession(session_id=str(agent_id), db_path=path)
