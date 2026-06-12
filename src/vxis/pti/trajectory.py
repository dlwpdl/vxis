"""JSONL trajectory persistence for PTI distillation records."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from vxis.pti.hashing import hash_text, validate_target_hash
from vxis.pti.models import OutcomeStatus, TrajectoryRecord

STRICT_PRIVACY_MODE = "strict"
URL_RE = re.compile(r"https?://[^\s\"'<>]+")
TRAILING_URL_PUNCTUATION = ".,);]"
SENSITIVE_HOST_KEYS = {"host", "hostname", "domain", "netloc", "target_host"}
SENSITIVE_QUERY_KEYS = {"query", "query_string", "qs"}
SENSITIVE_URL_KEYS = {"url", "target_url", "request_url", "endpoint"}


class TrajectoryStore:
    """Append and update distillation-ready trajectory JSONL records."""

    def __init__(self, target_dir: Path | str) -> None:
        self.target_dir = Path(target_dir)

    @property
    def trajectories_dir(self) -> Path:
        return self.target_dir / "trajectories"

    def path_for_scan(self, scan_id: str) -> Path:
        return self.trajectories_dir / f"{_safe_scan_id(scan_id)}.jsonl"

    def append(
        self,
        record: TrajectoryRecord,
        *,
        privacy_mode: str | None = None,
    ) -> Path:
        self._ensure_record_matches_target(record)
        path = self.path_for_scan(record.scan_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        record_to_write = apply_privacy(record, privacy_mode=privacy_mode)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(record_to_write.model_dump_json())
            handle.write("\n")
        return path

    def load(self, scan_id: str) -> list[TrajectoryRecord]:
        path = self.path_for_scan(scan_id)
        if not path.exists():
            return []
        records: list[TrajectoryRecord] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                records.append(TrajectoryRecord.model_validate_json(line))
        return records

    def writeback_outcome(
        self,
        scan_id: str,
        *,
        iter: int,
        outcome_status: OutcomeStatus,
        outcome_evidence: str | None = None,
        led_to_finding_id: str | None = None,
        led_to_refutation: bool = False,
    ) -> TrajectoryRecord:
        path = self.path_for_scan(scan_id)
        if not path.exists():
            raise FileNotFoundError(path)

        records = self.load(scan_id)
        updated_record: TrajectoryRecord | None = None
        updated_records: list[TrajectoryRecord] = []
        for record in records:
            if record.iter == iter and updated_record is None:
                updated_record = record.model_copy(
                    update={
                        "outcome_status": outcome_status,
                        "outcome_evidence": outcome_evidence,
                        "led_to_finding_id": led_to_finding_id,
                        "led_to_refutation": led_to_refutation,
                    }
                )
                updated_records.append(updated_record)
            else:
                updated_records.append(record)

        if updated_record is None:
            raise ValueError(f"no trajectory record found for scan_id={scan_id!r} iter={iter}")

        _rewrite_jsonl(path, updated_records)
        return updated_record

    def _ensure_record_matches_target(self, record: TrajectoryRecord) -> None:
        target_dir_name = self.target_dir.name
        if _looks_like_target_hash(target_dir_name) and target_dir_name != record.target_hash:
            raise ValueError("trajectory record target_hash does not match target directory")


def apply_privacy(
    record: TrajectoryRecord,
    *,
    privacy_mode: str | None = None,
) -> TrajectoryRecord:
    mode = (privacy_mode or os.getenv("VXIS_TRAJECTORY_PRIVACY", "")).strip().lower()
    if mode != STRICT_PRIVACY_MODE:
        return record
    return record.model_copy(update={"input_context": hash_sensitive_context(record.input_context)})


def hash_sensitive_context(value: Any) -> Any:
    """Hash target host and query-string data inside trajectory input context."""

    if isinstance(value, dict):
        scrubbed: dict[Any, Any] = {}
        for key, item in value.items():
            normalized_key = str(key).lower()
            if normalized_key in SENSITIVE_HOST_KEYS and isinstance(item, str):
                scrubbed[key] = f"sha256:{hash_text(item.lower())}"
            elif normalized_key in SENSITIVE_QUERY_KEYS and isinstance(item, str):
                scrubbed[key] = f"sha256:{hash_text(item)}"
            elif normalized_key in SENSITIVE_URL_KEYS and isinstance(item, str):
                scrubbed[key] = _hash_urls_in_text(item)
            else:
                scrubbed[key] = hash_sensitive_context(item)
        return scrubbed
    if isinstance(value, list):
        return [hash_sensitive_context(item) for item in value]
    if isinstance(value, tuple):
        return tuple(hash_sensitive_context(item) for item in value)
    if isinstance(value, str):
        return _hash_urls_in_text(value)
    return value


def _rewrite_jsonl(path: Path, records: list[TrajectoryRecord]) -> None:
    tmp_path = path.with_name(f".{path.name}.tmp")
    with tmp_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(record.model_dump_json())
            handle.write("\n")
    tmp_path.replace(path)


def _hash_urls_in_text(value: str) -> str:
    return URL_RE.sub(lambda match: _hash_url_token(match.group(0)), value)


def _hash_url_token(token: str) -> str:
    suffix = ""
    while token and token[-1] in TRAILING_URL_PUNCTUATION:
        suffix = f"{token[-1]}{suffix}"
        token = token[:-1]
    return f"{_hash_url_parts(token)}{suffix}"


def _hash_url_parts(url: str) -> str:
    parsed = urlsplit(url)
    if not parsed.hostname:
        return f"sha256:{hash_text(url)}"

    host = parsed.hostname.rstrip(".").lower()
    host_hash = hash_text(host)
    netloc = f"host_sha256_{host_hash}"
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"

    query = f"query_sha256={hash_text(parsed.query)}" if parsed.query else ""
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, ""))


def _safe_scan_id(scan_id: str) -> str:
    """Sanitize a scan_id into a path-safe file stem without raising.

    Replaces any run of characters that are not alphanumeric, underscore,
    dot, or hyphen with a single hyphen, then strips leading/trailing
    dots and hyphens. Returns "scan" for inputs that reduce to empty.
    This matches scan_loop_v3._safe_scan_id so both call sites are
    consistent and trajectory writes are never silently swallowed.
    """
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", scan_id.strip())
    normalized = normalized.strip(".-")
    return normalized or "scan"


def _looks_like_target_hash(value: str) -> bool:
    try:
        validate_target_hash(value)
    except ValueError:
        return False
    return True
