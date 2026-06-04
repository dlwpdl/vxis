from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from vxis.pti import Dossier, TrajectoryRecord, target_hash_for_url
from vxis.pti.models import (
    AuthoredTool,
    Defense,
    FindingHistoryEntry,
    HypothesisOutcome,
    PayloadEntry,
    StackEntry,
    SurfaceUnit,
)


def test_dossier_model_roundtrip_normalizes_target_and_nested_models() -> None:
    target_url = "HTTPS://Example.COM/app?token=secret"
    target_hash = target_hash_for_url(target_url)
    timestamp = datetime(2026, 6, 2, 12, 0, tzinfo=timezone.utc)

    dossier = Dossier(
        target_hash=target_hash,
        target_url=target_url,
        created_at=timestamp,
        updated_at=timestamp,
        scan_ids=["scan-1"],
        stack=[
            StackEntry(
                tech="rails",
                confidence=0.91,
                first_seen_scan="scan-1",
                last_seen_scan="scan-1",
                evidence=["x-powered-by: Rails"],
            )
        ],
        surface=[
            SurfaceUnit(
                surface_id="surface-login",
                path="/login",
                method="post",
                auth_role="anon",
                params=["next"],
                forms=[{"id": "login"}],
                status="alive",
                last_seen_scan="scan-1",
            )
        ],
        defenses=[
            Defense(
                kind="waf-signature",
                detector="cloudflare-cf-iuam",
                blocked_payload_classes=["sqli"],
                bypasses_known=["payloads/sqli.yaml"],
                first_seen_scan="scan-1",
            )
        ],
        findings_history=[
            FindingHistoryEntry(
                finding_id="VXIS-1",
                finding_type="xss",
                surface_id="surface-login",
                status="present",
                first_seen_scan="scan-1",
                last_verified_scan="scan-1",
            )
        ],
        authored_tools=[
            AuthoredTool(
                name="login_probe",
                purpose="Probe login behavior",
                script_path="tools/scan-1/login_probe.py",
                created_scan="scan-1",
                last_used_scan="scan-1",
                success_count=2,
                fail_count=1,
            )
        ],
        payload_library=[
            PayloadEntry(
                payload="' OR 1=1--",
                vector_class="sqli",
                outcome="blocked-signature",
                reason="WAF signature",
                scan_id="scan-1",
            )
        ],
        hypothesis_history=[
            HypothesisOutcome(
                claim="Login is injectable",
                prior_at_start=0.45,
                final_status="refuted",
                scan_id="scan-1",
            )
        ],
    )

    restored = Dossier.model_validate_json(dossier.model_dump_json())

    assert restored == dossier
    assert restored.target_url == "https://example.com:443"
    assert restored.surface[0].method == "POST"


def test_dossier_rejects_mismatched_target_hash() -> None:
    with pytest.raises(ValidationError, match="target_hash"):
        Dossier(target_hash="0" * 64, target_url="https://example.com")


def test_trajectory_record_roundtrip_and_validation() -> None:
    record = TrajectoryRecord(
        scan_id="scan-1",
        target_hash=target_hash_for_url("https://example.com"),
        iter=3,
        decision_class="exploit",
        model_used="claude-sonnet",
        input_context={"dashboard": {"target_url": "https://example.com/app?x=1"}},
        input_token_count=1200,
        output_action={"tool": "http_request", "args": {"path": "/app"}},
        output_token_count=220,
        outcome_status="pending",
        cost_usd=0.031,
        latency_ms=820,
    )

    restored = TrajectoryRecord.model_validate_json(record.model_dump_json())

    assert restored == record
    assert restored.schema_version == "pti.trajectory.v1"

    with pytest.raises(ValidationError):
        TrajectoryRecord(
            scan_id="scan-1",
            target_hash="z" * 64,
            iter=-1,
            decision_class="exploit",
            model_used="claude-sonnet",
            input_token_count=0,
            output_token_count=0,
            cost_usd=0,
            latency_ms=0,
        )
