from __future__ import annotations

import pytest
from pydantic import ValidationError

from vxis.pti import (
    AuthoredTool,
    Defense,
    Dossier,
    FindingHistoryEntry,
    HypothesisOutcome,
    PTIStore,
    PayloadEntry,
    StackEntry,
    SurfaceUnit,
    query_pti,
    target_hash_for_url,
)


def test_query_helpers_filter_each_dossier_collection() -> None:
    dossier = _dossier()

    assert [entry.tech for entry in query_pti(dossier, "stack", {"min_confidence": 0.8})] == [
        "rails"
    ]
    assert [entry.surface_id for entry in query_pti(dossier, "surfaces", {"method": "get"})] == [
        "admin"
    ]
    assert [
        entry.detector
        for entry in query_pti(dossier, "defenses", {"blocked_payload_class": "sqli"})
    ] == ["cloudflare"]
    assert [
        entry.finding_id for entry in query_pti(dossier, "findings_history", {"status": "present"})
    ] == ["VXIS-1"]
    assert [entry.name for entry in query_pti(dossier, "tools", {"min_success_count": 2})] == [
        "admin_probe"
    ]
    assert [
        entry.payload for entry in query_pti(dossier, "payloads", {"outcome": "blocked-rate"})
    ] == ["<script>alert(1)</script>"]
    assert [
        entry.claim for entry in query_pti(dossier, "hypotheses", {"claim_contains": "admin"})
    ] == ["Admin panel exposes IDOR"]


def test_store_query_loads_dossier_by_hash(tmp_path) -> None:
    store = PTIStore(tmp_path / "pti")
    dossier = _dossier()
    store.persist(dossier)

    result = store.query(dossier.target_hash, "surfaces", {"auth_role": "admin"})

    assert [entry.surface_id for entry in result] == ["admin"]


def test_query_filters_reject_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        query_pti(_dossier(), "stack", {"unknown": True})

    with pytest.raises(ValueError):
        query_pti(_dossier(), "unknown", {})


def _dossier() -> Dossier:
    target_url = "https://example.com"
    return Dossier(
        target_hash=target_hash_for_url(target_url),
        target_url=target_url,
        stack=[
            StackEntry(
                tech="rails",
                confidence=0.95,
                first_seen_scan="scan-1",
                last_seen_scan="scan-2",
                evidence=["header"],
            ),
            StackEntry(
                tech="nginx",
                confidence=0.6,
                first_seen_scan="scan-1",
                last_seen_scan="scan-1",
                evidence=["server"],
            ),
        ],
        surface=[
            SurfaceUnit(
                surface_id="login",
                path="/login",
                method="POST",
                auth_role="anon",
                params=["next"],
                forms=[],
                status="alive",
                last_seen_scan="scan-2",
            ),
            SurfaceUnit(
                surface_id="admin",
                path="/admin",
                method="GET",
                auth_role="admin",
                params=["id"],
                forms=[],
                status="alive",
                last_seen_scan="scan-2",
            ),
        ],
        defenses=[
            Defense(
                kind="waf-signature",
                detector="cloudflare",
                blocked_payload_classes=["sqli"],
                bypasses_known=["payloads/sqli.yaml"],
                first_seen_scan="scan-1",
            )
        ],
        findings_history=[
            FindingHistoryEntry(
                finding_id="VXIS-1",
                finding_type="idor",
                surface_id="admin",
                status="present",
                first_seen_scan="scan-1",
                last_verified_scan="scan-2",
            )
        ],
        authored_tools=[
            AuthoredTool(
                name="admin_probe",
                purpose="Probe admin object access",
                script_path="tools/scan-1/admin_probe.py",
                created_scan="scan-1",
                last_used_scan="scan-2",
                success_count=2,
                fail_count=0,
            )
        ],
        payload_library=[
            PayloadEntry(
                payload="<script>alert(1)</script>",
                vector_class="xss",
                outcome="blocked-rate",
                reason="rate limit",
                scan_id="scan-2",
            )
        ],
        hypothesis_history=[
            HypothesisOutcome(
                claim="Admin panel exposes IDOR",
                prior_at_start=0.7,
                final_status="confirmed",
                scan_id="scan-2",
            )
        ],
    )
