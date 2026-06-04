"""Idempotent migrator: legacy AgentMemory JSON + scan_kb JSON -> PTI."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from vxis.agent.memory import ScanMemory
from vxis.pti.hashing import target_hash_for_url
from vxis.pti.memory_bridge import persist_scan_memory_to_pti


def migrate(
    legacy_path: Path,
    pti_root: Path,
    dry_run: bool = False,
    kb_path: Path | None = None,
) -> dict[str, int]:
    """Migrate legacy memory sources into PTI.

    Returns a stable manifest: {migrated, skipped, failed}. Re-running after a
    successful migration skips entries whose content checksum is unchanged.
    """
    pti_root.mkdir(parents=True, exist_ok=True)
    marker_path = pti_root / "migrated.json"
    markers = _load_markers(marker_path)
    counts = {"migrated": 0, "skipped": 0, "failed": 0}

    for source_id, entry in _iter_legacy_entries(legacy_path, kb_path):
        try:
            scan = _entry_to_scan_memory(entry)
            target_hash = target_hash_for_url(scan.target)
            checksum = _checksum({"source": source_id, "entry": entry})
            marker_key = f"{target_hash}:{source_id}"
            if markers.get(marker_key) == checksum:
                counts["skipped"] += 1
                continue
            if not dry_run:
                persist_scan_memory_to_pti(scan, root=pti_root, scan_id=_scan_id(source_id, scan))
                markers[marker_key] = checksum
            counts["migrated"] += 1
        except Exception:  # noqa: BLE001 - migrator must continue and report
            counts["failed"] += 1

    if not dry_run:
        marker_path.write_text(json.dumps(markers, indent=2, sort_keys=True), encoding="utf-8")
    return counts


def _iter_legacy_entries(
    legacy_path: Path,
    kb_path: Path | None,
) -> list[tuple[str, dict[str, Any]]]:
    entries: list[tuple[str, dict[str, Any]]] = []
    if legacy_path.exists():
        raw = json.loads(legacy_path.read_text(encoding="utf-8"))
        memories = raw.get("memories", raw) if isinstance(raw, dict) else raw
        if isinstance(memories, list):
            for index, item in enumerate(memories):
                if isinstance(item, dict):
                    entries.append((f"agent-memory-{index}", item))

    if kb_path is not None and kb_path.exists():
        raw_kb = json.loads(kb_path.read_text(encoding="utf-8"))
        targets = raw_kb.get("targets", {}) if isinstance(raw_kb, dict) else {}
        if isinstance(targets, dict):
            for target_key, target_entry in targets.items():
                if not isinstance(target_entry, dict):
                    continue
                for index, scan in enumerate(target_entry.get("scans", []) or []):
                    if isinstance(scan, dict):
                        entries.append(
                            (
                                f"scan-kb-{target_key}-{index}",
                                _scan_kb_scan_to_agent_memory_entry(target_key, scan),
                            )
                        )
    return entries


def _entry_to_scan_memory(entry: dict[str, Any]) -> ScanMemory:
    return ScanMemory.from_dict(entry)


def _scan_kb_scan_to_agent_memory_entry(target_key: str, scan: dict[str, Any]) -> dict[str, Any]:
    fingerprint = scan.get("fingerprint") if isinstance(scan.get("fingerprint"), dict) else {}
    tech_stack = list(fingerprint.get("recommended_playbooks") or [])
    findings_summary = []
    for item in list(scan.get("finding_summaries") or scan.get("findings_snapshot") or []):
        if not isinstance(item, dict):
            continue
        findings_summary.append(
            {
                "severity": str(item.get("severity") or ""),
                "type": str(item.get("finding_type") or item.get("raw_finding_type") or "unknown"),
                "title": str(item.get("title") or "")[:120],
            }
        )
    return {
        "target": str(scan.get("target") or target_key),
        "tech_stack": tech_stack,
        "findings_summary": findings_summary,
        "effective_tools": [],
        "ineffective_tools": [],
        "scan_date": str(scan.get("timestamp") or ""),
        "total_findings": int(scan.get("findings_count") or len(findings_summary)),
    }


def _load_markers(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return {str(key): str(value) for key, value in raw.items()} if isinstance(raw, dict) else {}


def _checksum(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


def _scan_id(source_id: str, scan: ScanMemory) -> str:
    raw = f"{source_id}-{scan.scan_date}-{scan.target}"
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in raw)
    return safe.strip(".-")[:120] or "legacy-import"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--legacy", default="~/.vxis/agent_memory.json")
    parser.add_argument("--kb", default="data/scan_kb.json")
    parser.add_argument("--pti-root", default="data/pti")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    manifest = migrate(
        legacy_path=Path(args.legacy).expanduser(),
        kb_path=Path(args.kb).expanduser(),
        pti_root=Path(args.pti_root).expanduser(),
        dry_run=args.dry_run,
    )
    print(json.dumps(manifest, sort_keys=True))


if __name__ == "__main__":
    main()
