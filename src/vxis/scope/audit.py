"""Audit log | 감사 로그 (JSONL append-only)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, scan_id: str, audit_dir: Path | None = None) -> None:
        self.scan_id = scan_id or "unknown"
        self.audit_dir = audit_dir or (Path.home() / ".vxis" / "audit")
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.audit_dir / f"{self.scan_id}.jsonl"

    def _append(self, entry: dict) -> None:
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def log_action(
        self,
        action: str,
        url: str,
        result: str,
        concerns: list[str] | None = None,
    ) -> None:
        self._append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": self.scan_id,
            "type": "action",
            "action": action,
            "url": url,
            "result": result,
            "concerns": concerns or [],
        })

    def log_violation(self, attempted_action: str, reason: str, risk: str) -> None:
        self._append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": self.scan_id,
            "type": "violation",
            "action": attempted_action,
            "reason": reason,
            "risk": risk,
        })

    def log_pii(self, url: str, types: list[str], count: int) -> None:
        self._append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scan_id": self.scan_id,
            "type": "pii_detected",
            "url": url,
            "pii_types": types,
            "count": count,
        })

    def summary(self) -> dict:
        if not self.log_file.exists():
            return {"total": 0, "violations": 0, "pii_detected": 0, "actions": 0}
        total = 0
        violations = 0
        pii_detected = 0
        actions = 0
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                total += 1
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                etype = entry.get("type", "")
                if etype == "violation":
                    violations += 1
                elif etype == "pii_detected":
                    pii_detected += 1
                elif etype == "action":
                    actions += 1
        return {
            "total": total,
            "violations": violations,
            "pii_detected": pii_detected,
            "actions": actions,
        }
