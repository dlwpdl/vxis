from __future__ import annotations

import json

from vxis.growth import scan_retrospective as retro


def test_record_scan_retrospective_writes_local_json(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(retro, "_RETRO_DIR", tmp_path / "retros")
    monkeypatch.setattr(retro, "_RETRO_INDEX", tmp_path / "retros" / "index.jsonl")

    path = retro.record_scan_retrospective(
        scan_id="scan-123",
        target="http://localhost:3000",
        findings=[
            {
                "id": "VXIS-0001",
                "finding_type": "error_oracle",
                "severity": "medium",
                "affected_component": "/api/x",
                "title": "HTTP 500 on /api/x",
            },
            {
                "id": "VXIS-0002",
                "finding_type": "error_oracle",
                "severity": "medium",
                "affected_component": "/api/y",
                "title": "HTTP 500 on /api/y",
            },
            {
                "id": "VXIS-0003",
                "finding_type": "error_oracle",
                "severity": "medium",
                "affected_component": "/api/z",
                "title": "HTTP 500 on /api/z",
            },
        ],
        loop_result={
            "completed": False,
            "iterations": 12,
            "verdict_counts": {"CONFIRMED": 0, "UNCONFIRMED": 1, "REFUTED": 2},
            "review_queue": [
                {
                    "id": "verify:x",
                    "stage": "verifier",
                    "status": "open",
                    "title": "x",
                    "reason": "need control",
                }
            ],
            "review_history": [
                {
                    "stage": "verifier",
                    "verdict": "UNCONFIRMED",
                    "title": "x",
                    "reason": "need control",
                }
            ],
            "branches": [{"id": "BR-1", "status": "open"}],
            "attempt_outcomes": [{"tool": "shell_exec", "status": "failed"}],
        },
        messages=[
            {
                "role": "tool",
                "iter": 5,
                "content": {
                    "name": "report_finding",
                    "result": {"ok": True, "summary": "reported"},
                },
            }
        ],
        llm_usage={"provider": "openai", "model": "gpt-5.4-mini"},
        control_plane={"telemetry": {
            "discipline_profile": "frontier_loose",
            "memory_compression": {
                "checks": 5,
                "triggered": 2,
                "compressed_runs": 2,
                "total_tokens_saved": 1200,
            },
        }},
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["scan_id"] == "scan-123"
    assert payload["findings_by_type"]["error_oracle"] == 3
    assert payload["review_history_count"] == 1
    assert payload["llm_runtime"]["provider"] == "openai"
    assert payload["llm_runtime"]["discipline_profile"] == "frontier_loose"
    assert payload["memory_compression"]["triggered"] == 2
    assert payload["memory_compression"]["total_tokens_saved"] == 1200
    assert payload["strix_comparison"]["reference"] == "strix"
    hint_ids = {hint["hint_id"] for hint in payload["improvement_hints"]}
    assert "error_oracle_noise" in hint_ids
    assert "false_positive_pressure" in hint_ids
    assert "evidence_gap" in hint_ids


def test_load_latest_target_retrospective_returns_newest_match(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(retro, "_RETRO_DIR", tmp_path / "retros")
    monkeypatch.setattr(retro, "_RETRO_INDEX", tmp_path / "retros" / "index.jsonl")

    p1 = retro.record_scan_retrospective(
        scan_id="scan-old",
        target="http://localhost:3000",
        findings=[],
        loop_result={"completed": True, "iterations": 1, "verdict_counts": {}, "review_queue": [], "branches": [], "attempt_outcomes": []},
        messages=[],
    )
    p2 = retro.record_scan_retrospective(
        scan_id="scan-new",
        target="http://localhost:3000",
        findings=[{"finding_type": "sql_injection"}],
        loop_result={"completed": False, "iterations": 9, "verdict_counts": {}, "review_queue": [], "branches": [], "attempt_outcomes": []},
        messages=[],
    )

    loaded = retro.load_latest_target_retrospective("http://localhost:3000")
    assert loaded is not None
    assert loaded["scan_id"] == "scan-new"
    assert loaded["findings_count"] == 1
    assert p1.exists() and p2.exists()


def test_record_scan_retrospective_tracks_callback_and_retrieval_gaps(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(retro, "_RETRO_DIR", tmp_path / "retros")
    monkeypatch.setattr(retro, "_RETRO_INDEX", tmp_path / "retros" / "index.jsonl")

    path = retro.record_scan_retrospective(
        scan_id="scan-ssrf",
        target="http://localhost:3000",
        findings=[
            {
                "id": "VXIS-0100",
                "finding_type": "ssrf",
                "severity": "high",
                "affected_component": "/api/proxy",
                "title": "SSRF on /api/proxy",
            },
            {
                "id": "VXIS-0101",
                "finding_type": "idor",
                "severity": "high",
                "affected_component": "/api/users/{id}",
                "title": "IDOR on users API",
            },
        ],
        loop_result={
            "completed": True,
            "iterations": 8,
            "verdict_counts": {"CONFIRMED": 2, "UNCONFIRMED": 0, "REFUTED": 0},
            "review_queue": [],
            "branches": [],
            "attempt_outcomes": [],
            "callback_observations": [],
            "retrieval_observations": [],
        },
        messages=[],
    )

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["callback_observation_count"] == 0
    assert payload["retrieval_observation_count"] == 0
    hint_ids = {hint["hint_id"] for hint in payload["improvement_hints"]}
    assert "callback_visibility_gap" in hint_ids
    assert "retrieval_trace_gap" in hint_ids
