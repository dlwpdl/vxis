from __future__ import annotations

import json
from pathlib import Path

from vxis.growth import apply as growth_apply


def test_reviewable_pending_excludes_test_and_below_threshold(tmp_path: Path, monkeypatch) -> None:
    pending = tmp_path / "pending"
    pending.mkdir()
    monkeypatch.setattr(growth_apply, "PENDING_DIR", pending)
    monkeypatch.setattr(growth_apply, "REJECTED_DIR", tmp_path / "rejected")
    monkeypatch.setattr(growth_apply, "TEST_PENDING_DIR", tmp_path / "test-pending")

    (pending / "test-001.json").write_text(json.dumps({
        "proposal_id": "test-001",
        "source_signal_id": "test-v2-001",
        "confidence": 0.95,
        "change_type": "vector_add",
    }), encoding="utf-8")
    (pending / "low.json").write_text(json.dumps({
        "proposal_id": "low",
        "source_signal_id": "sig-low",
        "confidence": 0.68,
        "change_type": "kb_pattern_add",
    }), encoding="utf-8")
    (pending / "real.json").write_text(json.dumps({
        "proposal_id": "real",
        "source_signal_id": "sig-real",
        "confidence": 0.76,
        "change_type": "guide_advice_append",
    }), encoding="utf-8")

    config = {
        "apply": {
            "pr_review_threshold": 0.7,
        }
    }
    reviewable = growth_apply.list_reviewable_pending_proposals(config)
    assert [item["proposal_id"] for item in reviewable] == ["real"]
    assert growth_apply.count_reviewable_pending_proposals(config) == 1


def test_prune_pending_moves_test_and_stale_proposals(tmp_path: Path, monkeypatch) -> None:
    pending = tmp_path / "pending"
    rejected = tmp_path / "rejected"
    test_pending = tmp_path / "test-pending"
    pending.mkdir()
    monkeypatch.setattr(growth_apply, "PENDING_DIR", pending)
    monkeypatch.setattr(growth_apply, "REJECTED_DIR", rejected)
    monkeypatch.setattr(growth_apply, "TEST_PENDING_DIR", test_pending)

    (pending / "test-001.json").write_text(json.dumps({
        "proposal_id": "test-001",
        "source_signal_id": "test-v2-001",
        "confidence": 0.95,
        "change_type": "vector_add",
    }), encoding="utf-8")
    (pending / "low.json").write_text(json.dumps({
        "proposal_id": "low",
        "source_signal_id": "sig-low",
        "confidence": 0.68,
        "change_type": "kb_pattern_add",
    }), encoding="utf-8")
    (pending / "real.json").write_text(json.dumps({
        "proposal_id": "real",
        "source_signal_id": "sig-real",
        "confidence": 0.76,
        "change_type": "guide_advice_append",
    }), encoding="utf-8")

    result = growth_apply.prune_pending_proposals({
        "apply": {
            "pr_review_threshold": 0.7,
        }
    })
    assert result["moved_test_artifacts"] == 1
    assert result["moved_rejected"] == 1
    assert result["pending_reviewable"] == 1
    assert (test_pending / "test-001.json").exists()
    assert (rejected / "low.json").exists()
    assert (pending / "real.json").exists()
