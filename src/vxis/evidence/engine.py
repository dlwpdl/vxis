from __future__ import annotations
import sqlite3
from pathlib import Path
from .schema import Evidence, Severity


class EvidenceEngine:
    def __init__(self, db_path: str = "evidence.db"):
        self.db_path = db_path

    async def init(self) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                evidence_type TEXT NOT NULL,
                description TEXT NOT NULL,
                chained_from TEXT,
                hash TEXT NOT NULL,
                raw_json TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    async def save(self, ev: Evidence) -> None:
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """INSERT OR REPLACE INTO evidence
               (id, timestamp, agent_id, title, severity,
                evidence_type, description, chained_from, hash, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ev.id,
                ev.timestamp.isoformat(),
                ev.agent_id,
                ev.title,
                ev.severity.value,
                ev.evidence_type.value,
                ev.description,
                ev.chained_from,
                ev.hash,
                ev.model_dump_json(),
            ),
        )
        conn.commit()
        conn.close()

    async def get_by_severity(self, severity: Severity) -> list[Evidence]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT raw_json FROM evidence WHERE severity = ?",
            (severity.value,),
        ).fetchall()
        conn.close()
        return [Evidence.model_validate_json(r[0]) for r in rows]

    async def get_chain(self, parent_id: str) -> list[Evidence]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT raw_json FROM evidence WHERE chained_from = ?",
            (parent_id,),
        ).fetchall()
        conn.close()
        return [Evidence.model_validate_json(r[0]) for r in rows]

    async def get_all(self) -> list[Evidence]:
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute(
            "SELECT raw_json FROM evidence ORDER BY timestamp"
        ).fetchall()
        conn.close()
        return [Evidence.model_validate_json(r[0]) for r in rows]
