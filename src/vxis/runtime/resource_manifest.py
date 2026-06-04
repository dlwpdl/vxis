from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vxis.evidence.receipts import file_sha256


_SCHEMA = "vxis.resource_manifest.v1"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(slots=True)
class ResourceRecord:
    resource_id: str
    kind: str
    path: str
    sha256: str
    size_bytes: int
    created_at: str
    metadata: dict[str, Any] = field(default_factory=dict)
    receipt_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resource_id": self.resource_id,
            "kind": self.kind,
            "path": self.path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "created_at": self.created_at,
            "metadata": dict(self.metadata),
            "receipt_ids": list(self.receipt_ids),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ResourceRecord":
        return cls(
            resource_id=str(value.get("resource_id") or ""),
            kind=str(value.get("kind") or ""),
            path=str(value.get("path") or ""),
            sha256=str(value.get("sha256") or ""),
            size_bytes=int(value.get("size_bytes") or 0),
            created_at=str(value.get("created_at") or ""),
            metadata=dict(value.get("metadata") or {}),
            receipt_ids=[str(item) for item in list(value.get("receipt_ids") or [])],
        )


class ResourceManifest:
    """Sidecar manifest for files/resources produced by one VXIS scan."""

    def __init__(self, *, scan_id: str) -> None:
        self.scan_id = str(scan_id or "")
        self.resources: list[ResourceRecord] = []

    def add_file(
        self,
        path: str | Path,
        *,
        kind: str = "artifact",
        metadata: dict[str, Any] | None = None,
        receipt_ids: list[str] | None = None,
    ) -> ResourceRecord:
        p = Path(path)
        stat = p.stat()
        record = ResourceRecord(
            resource_id="res_" + uuid.uuid4().hex[:16],
            kind=str(kind or "artifact"),
            path=str(p),
            sha256=file_sha256(p),
            size_bytes=int(stat.st_size),
            created_at=_now_iso(),
            metadata=dict(metadata or {}),
            receipt_ids=list(receipt_ids or []),
        )
        self.resources.append(record)
        return record

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": _SCHEMA,
            "scan_id": self.scan_id,
            "generated_at": _now_iso(),
            "resources": [record.to_dict() for record in self.resources],
        }

    def write(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(self.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
        return out

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ResourceManifest":
        manifest = cls(scan_id=str(value.get("scan_id") or ""))
        manifest.resources = [
            ResourceRecord.from_dict(item)
            for item in list(value.get("resources") or [])
            if isinstance(item, dict)
        ]
        return manifest

    def verify(self) -> list[str]:
        issues: list[str] = []
        ids: set[str] = set()
        for record in self.resources:
            if record.resource_id in ids:
                issues.append(f"duplicate resource_id: {record.resource_id}")
            ids.add(record.resource_id)
            path = Path(record.path)
            if not path.exists():
                issues.append(f"{record.resource_id}: missing file {record.path}")
                continue
            if file_sha256(path) != record.sha256:
                issues.append(f"{record.resource_id}: sha256 mismatch")
        return issues
