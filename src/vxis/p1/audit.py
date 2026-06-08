from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, **fields: Any) -> dict[str, Any]:
        previous = self.head_hash()
        record = _canonical_record(fields)
        entry = {**record, "prev_hash": previous, "hash": _digest(previous, record)}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
        return entry

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        lines = [line for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return [json.loads(line) for line in lines]

    def head_hash(self) -> str:
        entries = self.read()
        if not entries:
            return GENESIS
        return str(entries[-1].get("hash") or GENESIS)

    def seal(self) -> dict[str, Any]:
        entries = self.read()
        return {"entries": len(entries), "head_hash": self.head_hash()}

    def verify(self) -> bool:
        previous = GENESIS
        try:
            entries = self.read()
        except (OSError, json.JSONDecodeError):
            return False
        for entry in entries:
            if entry.get("prev_hash") != previous:
                return False
            actual = entry.get("hash")
            record = {k: v for k, v in entry.items() if k not in {"hash", "prev_hash"}}
            if actual != _digest(previous, _canonical_record(record)):
                return False
            previous = str(actual)
        return True


def _canonical_record(fields: dict[str, Any]) -> dict[str, Any]:
    return {str(k): v for k, v in sorted(fields.items()) if v not in (None, "")}


def _digest(previous: str, record: dict[str, Any]) -> str:
    payload = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(f"{previous}\n{payload}".encode("utf-8")).hexdigest()
