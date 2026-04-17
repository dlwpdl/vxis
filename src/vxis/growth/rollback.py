"""Rollback applied proposals|||적용된 제안 롤백."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from vxis.growth.changelog import ChangeLog

APPLIED_DIR = Path(".vxis/signals/applied")
REJECTED_DIR = Path(".vxis/signals/rejected")


def rollback_proposal(proposal_id: str, reason: str = "") -> bool:
    """Rollback a proposal by id|||ID로 제안 롤백."""
    applied_path = APPLIED_DIR / f"{proposal_id}.json"
    if not applied_path.exists():
        return False

    REJECTED_DIR.mkdir(parents=True, exist_ok=True)
    rejected_path = REJECTED_DIR / f"{proposal_id}.json"

    try:
        data = json.loads(applied_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False

    data["status"] = "rolled_back"
    data["rolled_back_at"] = datetime.now(timezone.utc).isoformat()
    data["rollback_reason"] = reason

    # If this was a skill_payload_add, remove the payload from the skill file
    if data.get("change_type") == "skill_payload_add":
        _revert_skill_payload(data)

    rejected_path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    applied_path.unlink()

    ChangeLog().record(
        "proposal_rolled_back",
        {"proposal_id": proposal_id, "reason": reason},
    )
    return True


def _revert_skill_payload(proposal_data: dict) -> bool:
    """Remove an auto-added payload entry from the skill's JSON data file.

    ADR-007 Phase 10: mirrors `_apply_skill_payload`'s JSON append.
    Matches by the sanitized payload string across rounds + datasets,
    and strips the first matching entry from each bucket where it
    appears. Safe because apply dedup guarantees at most one occurrence.
    """
    target_file = Path(proposal_data.get("target_file", ""))
    change_data = proposal_data.get("change_data", {})
    payload = (
        change_data.get("payload", "")
        if isinstance(change_data, dict) else ""
    )

    if not target_file.exists() or not payload:
        return False

    if target_file.suffix != ".json":
        # Legacy .py targets are no longer written to (ADR-007 Phase 10).
        # Stay silent so old applied/ entries that predate the rewire
        # don't spam errors on replay.
        return False

    try:
        content = json.loads(target_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return False

    needle = payload.replace("\n", " ").replace("\r", "").strip()
    if len(needle) > 200:
        needle = needle[:200]

    removed = False

    for round_key, entries in list(content.get("rounds", {}).items()):
        kept = [
            e for e in entries
            if not (isinstance(e, dict) and e.get("payload") == needle)
        ]
        if len(kept) != len(entries):
            content["rounds"][round_key] = kept
            removed = True

    for ds_key, entries in list(content.get("datasets", {}).items()):
        kept: list = []
        for e in entries:
            if isinstance(e, str) and e == needle:
                continue
            if isinstance(e, list) and e and e[0] == needle:
                continue
            kept.append(e)
        if len(kept) != len(entries):
            content["datasets"][ds_key] = kept
            removed = True

    if not removed:
        return False

    target_file.write_text(
        json.dumps(content, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    try:
        from vxis.agent.skills._payload_loader import clear_cache
        clear_cache()
    except ImportError:
        pass

    return True


def rollback_since(timestamp_iso: str) -> int:
    """Rollback all proposals applied since timestamp|||시점 이후 일괄 롤백."""
    if not APPLIED_DIR.exists():
        return 0
    count = 0
    for path in APPLIED_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        if data.get("applied_at", "") >= timestamp_iso:
            if rollback_proposal(
                data.get("proposal_id", ""), reason="batch_rollback"
            ):
                count += 1
    return count
