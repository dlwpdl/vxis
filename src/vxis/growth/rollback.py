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
    """Remove an auto-added payload line from a skill file."""
    target_file = Path(proposal_data.get("target_file", ""))
    change_data = proposal_data.get("change_data", {})
    payload = change_data.get("payload", "") if isinstance(change_data, dict) else ""

    if not target_file.exists() or not payload:
        return False

    content = target_file.read_text(encoding="utf-8")
    lines = content.split("\n")
    new_lines = [
        line for line in lines
        if not (payload in line and "# auto-added" in line)
    ]

    if len(new_lines) < len(lines):
        target_file.write_text("\n".join(new_lines), encoding="utf-8")
        return True
    return False


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
