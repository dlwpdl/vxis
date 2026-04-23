"""G.6 — report_finding auto-tag surface from ctx.kind 테스트.

spec:
  - _build_finding_from_dict(kind=DESKTOP) 로 만든 Finding 의
    evidence[0].surface 가 TargetKind.DESKTOP 이어야 한다.
  - kind 미지정 시 기본값 WEB 이다.
  - 직접 finding_tools.report_finding 을 호출할 때는 현재 ctx 가 없으므로
    pipeline 레이어(_build_finding_from_dict)가 surface 태깅을 담당한다.
"""
from __future__ import annotations

import pytest

from vxis.interaction.surface import TargetKind


# ── pipeline finding builder — surface 전파 ──────────────────────


def test_build_finding_propagates_desktop_surface() -> None:
    """ctx.kind=DESKTOP 이면 Evidence.surface == DESKTOP 이어야 한다."""
    from vxis.pipeline.scan_pipeline_v2 import _build_finding_from_dict

    finding = _build_finding_from_dict(
        {
            "id": "VXIS-0001",
            "title": "hardcoded API key",
            "severity": "high",
            "finding_type": "secret",
            "affected_component": "/Applications/X.app/Contents/Info.plist",
            "description": "AWS key found in Info.plist",
            "evidence": "aws_access_key_id = AKIA...",
        },
        scan_id="scan-desktop-1",
        target="/Applications/X.app",
        kind=TargetKind.DESKTOP,
    )

    assert finding.evidence, "evidence list should not be empty"
    assert finding.evidence[0].surface == TargetKind.DESKTOP


def test_build_finding_propagates_mobile_surface() -> None:
    """ctx.kind=MOBILE 이면 Evidence.surface == MOBILE 이어야 한다."""
    from vxis.pipeline.scan_pipeline_v2 import _build_finding_from_dict

    finding = _build_finding_from_dict(
        {
            "id": "VXIS-0002",
            "title": "exported activity without permission",
            "severity": "medium",
            "finding_type": "misconfig",
            "affected_component": "com.example.app/.LoginActivity",
            "description": "activity exported without permission check",
            "evidence": "AndroidManifest.xml exported=true",
        },
        scan_id="scan-mobile-1",
        target="com.example.app",
        kind=TargetKind.MOBILE,
    )

    assert finding.evidence[0].surface == TargetKind.MOBILE


def test_build_finding_defaults_web_surface_when_no_kind() -> None:
    """kind 미지정 시 기본값 WEB — 레거시 웹 스캔 back-compat."""
    from vxis.pipeline.scan_pipeline_v2 import _build_finding_from_dict

    finding = _build_finding_from_dict(
        {
            "id": "VXIS-0003",
            "title": "SQL injection",
            "severity": "critical",
            "finding_type": "sqli",
            "affected_component": "/api/users",
            "description": "UNION-based SQLi",
            "evidence": "1=1 OR",
        },
        scan_id="scan-web-1",
        target="http://example.com",
    )

    assert finding.evidence[0].surface == TargetKind.WEB


def test_build_finding_all_evidences_inherit_surface() -> None:
    """모든 Evidence 항목이 동일한 surface 를 가져야 한다.

    현재 구현은 evidence 가 항상 1개이지만, 확장 시에도 검증하기 위해
    단일 evidence 에 대해 표면적으로 검증한다.
    """
    from vxis.pipeline.scan_pipeline_v2 import _build_finding_from_dict

    finding = _build_finding_from_dict(
        {
            "id": "VXIS-0004",
            "title": "dylib hijacking",
            "severity": "high",
            "finding_type": "dylib_hijack",
            "affected_component": "/Applications/X.app/Contents/MacOS/X",
            "description": "weak dylib load path",
            "evidence": "DYLIB_PATH not @rpath",
        },
        scan_id="scan-desktop-2",
        target="/Applications/X.app",
        kind=TargetKind.DESKTOP,
    )

    for ev in finding.evidence:
        assert ev.surface == TargetKind.DESKTOP, (
            f"evidence item surface mismatch: {ev.surface}"
        )


# ── cross-surface synthesis 확인 ─────────────────────────────────


def test_desktop_surface_evidence_triggers_cross_surface_chain() -> None:
    """DESKTOP surface Evidence 가 chain synthesis 에서 boundary 마커를 붙인다."""
    import asyncio

    from vxis.evidence.schema import Evidence as SchemaEvidence
    from vxis.evidence.schema import EvidenceType, Severity
    from vxis.synthesis.cross_protocol import CrossProtocolSynthesizer

    desktop_ev = SchemaEvidence(
        agent_id="desktop_local_storage_secrets",
        title="Hardcoded AWS key in app.asar",
        description="aws_access_key_id leaked in resources/app.asar",
        evidence_type=EvidenceType.SECRET,
        severity=Severity.HIGH,
        surface=TargetKind.DESKTOP,
    )
    cloud_ev = SchemaEvidence(
        agent_id="cloud",
        title="S3 bucket public listing",
        description="public bucket, AWS data exfiltration possible",
        evidence_type=EvidenceType.MISCONFIGURATION,
        severity=Severity.MEDIUM,
    )

    syn = CrossProtocolSynthesizer()
    syn.add_findings([desktop_ev, cloud_ev])
    chains = asyncio.run(syn.synthesize())

    cross_surface_chains = [
        c for c in chains if "crosses surface boundary" in c.description
    ]
    assert cross_surface_chains, (
        "Expected at least one cross-surface boundary chain when evidence spans "
        "DESKTOP and WEB surfaces"
    )
