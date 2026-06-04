from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_RECEIPT_SCHEMA = "vxis.evidence.receipt.v1"
_MANIFEST_SCHEMA = "vxis.evidence.manifest.v1"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def sha256_digest(value: Any) -> str:
    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def file_sha256(path: str | Path) -> str:
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sign(payload: dict[str, Any], *, key: str, key_id: str) -> tuple[str, str]:
    mac = hmac.new(key.encode("utf-8"), canonical_json(payload).encode("utf-8"), hashlib.sha256)
    return "hmac-sha256:" + mac.hexdigest(), key_id


@dataclass(slots=True)
class EvidenceReceipt:
    receipt_id: str
    parent_receipt_ids: list[str]
    event_type: str
    actor_type: str
    created_at: str
    tool_name: str = ""
    input_hash: str = ""
    output_hash: str = ""
    artifact_hashes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    parent_hash: str = ""
    receipt_hash: str = ""
    signature: str = ""
    public_key_id: str = ""
    schema: str = _RECEIPT_SCHEMA

    def signed_payload(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "receipt_id": self.receipt_id,
            "parent_receipt_ids": list(self.parent_receipt_ids),
            "event_type": self.event_type,
            "actor_type": self.actor_type,
            "created_at": self.created_at,
            "tool_name": self.tool_name,
            "input_hash": self.input_hash,
            "output_hash": self.output_hash,
            "artifact_hashes": list(self.artifact_hashes),
            "metadata": dict(self.metadata),
            "parent_hash": self.parent_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.signed_payload()
        payload["receipt_hash"] = self.receipt_hash
        payload["signature"] = self.signature
        payload["public_key_id"] = self.public_key_id
        return payload

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EvidenceReceipt":
        return cls(
            receipt_id=str(value.get("receipt_id") or ""),
            parent_receipt_ids=[str(item) for item in list(value.get("parent_receipt_ids") or [])],
            event_type=str(value.get("event_type") or ""),
            actor_type=str(value.get("actor_type") or ""),
            created_at=str(value.get("created_at") or ""),
            tool_name=str(value.get("tool_name") or ""),
            input_hash=str(value.get("input_hash") or ""),
            output_hash=str(value.get("output_hash") or ""),
            artifact_hashes=[str(item) for item in list(value.get("artifact_hashes") or [])],
            metadata=dict(value.get("metadata") or {}),
            parent_hash=str(value.get("parent_hash") or ""),
            receipt_hash=str(value.get("receipt_hash") or ""),
            signature=str(value.get("signature") or ""),
            public_key_id=str(value.get("public_key_id") or ""),
            schema=str(value.get("schema") or _RECEIPT_SCHEMA),
        )


class EvidenceManifest:
    """Hash-linked receipt manifest for VXIS scan evidence.

    The default signer uses HMAC-SHA256 from ``VXIS_EVIDENCE_SIGNING_KEY``.
    This keeps the first milestone dependency-free while preserving the same
    canonical payload and verification flow a future Ed25519 signer can reuse.
    """

    def __init__(
        self,
        *,
        scan_id: str,
        signing_key: str | None = None,
        public_key_id: str | None = None,
    ) -> None:
        self.scan_id = str(scan_id or "")
        self.signing_key = (
            signing_key
            if signing_key is not None
            else os.environ.get("VXIS_EVIDENCE_SIGNING_KEY", "")
        )
        self.public_key_id = public_key_id or os.environ.get(
            "VXIS_EVIDENCE_PUBLIC_KEY_ID", "vxis-local-hmac"
        )
        self.receipts: list[EvidenceReceipt] = []

    def add_event(
        self,
        *,
        event_type: str,
        actor_type: str = "system",
        tool_name: str = "",
        input_data: Any = None,
        output_data: Any = None,
        artifact_paths: list[str | Path] | None = None,
        artifact_hashes: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        parent_receipt_ids: list[str] | None = None,
    ) -> EvidenceReceipt:
        parents = parent_receipt_ids if parent_receipt_ids is not None else self.tail_ids()
        by_id = {receipt.receipt_id: receipt for receipt in self.receipts}
        parent_hash = sha256_digest(
            [by_id[parent_id].to_dict() for parent_id in parents if parent_id in by_id]
        )
        hashes = list(artifact_hashes or [])
        for path in artifact_paths or []:
            hashes.append(file_sha256(path))
        receipt = EvidenceReceipt(
            receipt_id="receipt_" + uuid.uuid4().hex[:16],
            parent_receipt_ids=list(parents),
            event_type=str(event_type),
            actor_type=str(actor_type),
            created_at=_now_iso(),
            tool_name=str(tool_name or ""),
            input_hash=sha256_digest(input_data) if input_data is not None else "",
            output_hash=sha256_digest(output_data) if output_data is not None else "",
            artifact_hashes=hashes,
            metadata={"scan_id": self.scan_id, **dict(metadata or {})},
            parent_hash=parent_hash,
        )
        receipt.receipt_hash = sha256_digest(receipt.signed_payload())
        if self.signing_key:
            receipt.signature, receipt.public_key_id = _sign(
                receipt.signed_payload(),
                key=self.signing_key,
                key_id=self.public_key_id,
            )
        self.receipts.append(receipt)
        return receipt

    def tail_ids(self) -> list[str]:
        if not self.receipts:
            return []
        return [self.receipts[-1].receipt_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": _MANIFEST_SCHEMA,
            "scan_id": self.scan_id,
            "generated_at": _now_iso(),
            "receipts": [receipt.to_dict() for receipt in self.receipts],
        }

    def write(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(self.to_dict(), ensure_ascii=False, indent=2, default=str), encoding="utf-8"
        )
        return out

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
        *,
        signing_key: str | None = None,
    ) -> "EvidenceManifest":
        manifest = cls(scan_id=str(value.get("scan_id") or ""), signing_key=signing_key)
        manifest.receipts = [
            EvidenceReceipt.from_dict(item)
            for item in list(value.get("receipts") or [])
            if isinstance(item, dict)
        ]
        return manifest

    def verify(self) -> list[str]:
        issues: list[str] = []
        by_id = {receipt.receipt_id: receipt for receipt in self.receipts}
        seen: set[str] = set()
        for receipt in self.receipts:
            if receipt.receipt_id in seen:
                issues.append(f"duplicate receipt_id: {receipt.receipt_id}")
            seen.add(receipt.receipt_id)
            if receipt.schema != _RECEIPT_SCHEMA:
                issues.append(f"{receipt.receipt_id}: unexpected schema {receipt.schema}")
            for parent_id in receipt.parent_receipt_ids:
                if parent_id not in by_id:
                    issues.append(f"{receipt.receipt_id}: missing parent {parent_id}")
            expected_parent_hash = sha256_digest(
                [
                    by_id[parent_id].to_dict()
                    for parent_id in receipt.parent_receipt_ids
                    if parent_id in by_id
                ]
            )
            if receipt.parent_hash != expected_parent_hash:
                issues.append(f"{receipt.receipt_id}: parent_hash mismatch")
            expected_hash = sha256_digest(receipt.signed_payload())
            if receipt.receipt_hash != expected_hash:
                issues.append(f"{receipt.receipt_id}: receipt_hash mismatch")
            if self.signing_key and receipt.signature:
                expected_sig, _ = _sign(
                    receipt.signed_payload(),
                    key=self.signing_key,
                    key_id=receipt.public_key_id or self.public_key_id,
                )
                if not hmac.compare_digest(receipt.signature, expected_sig):
                    issues.append(f"{receipt.receipt_id}: signature mismatch")
            elif self.signing_key and not receipt.signature:
                issues.append(f"{receipt.receipt_id}: missing signature")
        return issues
