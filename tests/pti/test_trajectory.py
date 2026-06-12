from __future__ import annotations

import json

import pytest

from vxis.pti import PTIStore, TrajectoryRecord, target_hash_for_url
from vxis.pti.trajectory import _safe_scan_id


def test_trajectory_append_and_retroactive_outcome_writeback(tmp_path) -> None:
    store = PTIStore(tmp_path / "data" / "pti")
    record = _record(iter=2)

    path = store.append_trajectory(record, privacy_mode="")
    loaded = store.load_trajectories(record.target_hash, "scan-1")

    assert path == tmp_path / "data" / "pti" / record.target_hash / "trajectories" / "scan-1.jsonl"
    assert loaded == [record]

    updated = store.writeback_trajectory_outcome(
        record.target_hash,
        "scan-1",
        iter=2,
        outcome_status="success",
        outcome_evidence="Confirmed reflected payload in response body",
        led_to_finding_id="VXIS-99",
        led_to_refutation=False,
    )

    reloaded = store.load_trajectories(record.target_hash, "scan-1")
    assert updated.outcome_status == "success"
    assert reloaded[0].outcome_evidence == "Confirmed reflected payload in response body"
    assert reloaded[0].led_to_finding_id == "VXIS-99"


def test_trajectory_schema_version_allows_forward_compatible_extras() -> None:
    raw = json.loads(_record().model_dump_json())
    raw["schema_version"] = "pti.trajectory.v2"
    raw["future_metric"] = {"reward": 0.91}

    restored = TrajectoryRecord.model_validate(raw)

    assert restored.schema_version == "pti.trajectory.v2"
    assert restored.model_extra == {"future_metric": {"reward": 0.91}}


def test_strict_privacy_hashes_hosts_and_query_strings(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("VXIS_TRAJECTORY_PRIVACY", "strict")
    store = PTIStore(tmp_path / "data" / "pti")
    record = _record(
        input_context={
            "target_url": "https://Tenant.Example.com/app?token=secret&role=admin",
            "host": "tenant.example.com",
            "request": "GET https://tenant.example.com/api?api_key=abc123 HTTP/1.1",
            "nested": {"query": "token=secret&role=admin"},
        }
    )

    store.append_trajectory(record)
    stored = store.load_trajectories(record.target_hash, "scan-1")[0]
    context_blob = json.dumps(stored.input_context)

    assert "tenant.example.com" not in context_blob.lower()
    assert "token=secret" not in context_blob
    assert "api_key=abc123" not in context_blob
    assert stored.input_context["host"].startswith("sha256:")
    assert stored.input_context["nested"]["query"].startswith("sha256:")
    assert "host_sha256_" in stored.input_context["target_url"]
    assert "query_sha256=" in stored.input_context["target_url"]


def test_safe_scan_id_sanitizes_rather_than_raises_on_unsafe_input() -> None:
    """_safe_scan_id in trajectory.py raises for inputs that scan_loop_v3 would sanitize.

    scan_loop_v3._safe_scan_id sanitizes "my scan/1" → "my-scan-1" (never raises).
    trajectory._safe_scan_id raises ValueError("scan_id must be a path-safe file stem")
    for the same input. A scan_id that passes through the v3 path but hits
    TrajectoryStore will silently swallow the trajectory write.
    """
    # These would be sanitized by scan_loop_v3's version but raise in trajectory.py
    unsafe_inputs = [
        "my scan/1",  # contains slash and space
        "scan id with spaces",  # spaces only
        "../traversal",  # path traversal attempt
    ]
    for raw in unsafe_inputs:
        # Current behavior: raises instead of sanitizing
        try:
            result = _safe_scan_id(raw)
            # If it doesn't raise, the result must be a safe path stem
            assert "/" not in result, f"_safe_scan_id({raw!r}) returned path with slash: {result!r}"
            assert " " not in result, f"_safe_scan_id({raw!r}) returned path with space: {result!r}"
            assert result not in {".", ".."}, (
                f"_safe_scan_id({raw!r}) returned dot-path: {result!r}"
            )
            assert result, f"_safe_scan_id({raw!r}) returned empty string"
        except ValueError as exc:
            pytest.fail(
                f"_safe_scan_id({raw!r}) raised ValueError({exc!r}) instead of sanitizing. "
                "This swallows trajectory writes for unsafe scan_ids."
            )

    # Clean inputs must pass through unchanged
    assert _safe_scan_id("scan-abc-1234") == "scan-abc-1234"
    assert _safe_scan_id("scan_001") == "scan_001"
    assert _safe_scan_id("  scan-1  ") == "scan-1"


def _record(
    *,
    iter: int = 1,
    input_context: dict | None = None,
) -> TrajectoryRecord:
    return TrajectoryRecord(
        scan_id="scan-1",
        target_hash=target_hash_for_url("https://example.com"),
        iter=iter,
        decision_class="strategy",
        model_used="claude-sonnet",
        input_context=input_context
        or {"dashboard": {"target_url": "https://example.com/path?x=1"}},
        input_token_count=100,
        output_action={"tool": "query_pti", "args": {"query_type": "surfaces"}},
        output_token_count=20,
        outcome_status="pending",
        cost_usd=0.02,
        latency_ms=300,
    )
