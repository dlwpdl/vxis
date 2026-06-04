from __future__ import annotations

import json

from scripts.migrate_agent_memory_to_pti import migrate


def test_migrate_is_idempotent(tmp_path) -> None:
    legacy = tmp_path / "agent_memory.json"
    legacy.write_text(
        json.dumps(
            {
                "memories": [
                    {
                        "target": "http://example.com:80",
                        "tech_stack": ["nginx"],
                        "findings_summary": [],
                        "effective_tools": [],
                        "ineffective_tools": [],
                        "scan_date": "2026-01-01T00:00:00+00:00",
                        "total_findings": 0,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    pti_root = tmp_path / "pti"

    first = migrate(legacy_path=legacy, pti_root=pti_root, dry_run=False)
    second = migrate(legacy_path=legacy, pti_root=pti_root, dry_run=False)

    assert first["migrated"] == 1
    assert first["failed"] == 0
    assert second["migrated"] == 0
    assert second["skipped"] == 1
