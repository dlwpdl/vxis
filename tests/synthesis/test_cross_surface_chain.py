"""Cross-surface synthesis tests — phase-G.

Phase-G enables Brain to chain findings *across* surface boundaries
(web ↔ desktop ↔ mobile ↔ game). Two cross-surface chain patterns land:
  - desktop_creds_to_cloud: desktop credential harvest → cloud exfiltration
  - desktop_ipc_to_lateral: desktop IPC initial-access → app priv-esc

Tests cover six concerns:
  G.1 — Both Evidence models carry a `surface: TargetKind` field
  G.2 — OSILayer.DESKTOP exists; _tag_layer respects evidence.surface
  G.3 — desktop_creds_to_cloud pattern synthesizes a CRITICAL chain
  G.4 — Cross-surface chains decorate description with boundary marker
  G.5 — scan_pipeline_v2 _build_finding_from_dict propagates ctx.kind
  G.6 — desktop_ipc_to_lateral pattern + back-compat sanity
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from vxis.evidence.schema import Evidence as SchemaEvidence
from vxis.evidence.schema import EvidenceType, Severity
from vxis.interaction.surface import TargetKind
from vxis.models.finding import Evidence as FindingEvidence


# ── G.1 — Evidence carries surface field ────────────────────────────────


def test_finding_evidence_carries_surface_field_default_web() -> None:
    """models.finding.Evidence defaults to WEB so existing reports stay valid."""
    e = FindingEvidence(evidence_type="screenshot", title="t", content="...")
    assert e.surface == TargetKind.WEB


def test_finding_evidence_accepts_explicit_surface() -> None:
    """Desktop findings can tag their evidence at construction time."""
    e = FindingEvidence(
        evidence_type="screenshot",
        title="t",
        content="...",
        surface=TargetKind.DESKTOP,
    )
    assert e.surface == TargetKind.DESKTOP
    # Round-trips through Pydantic — important for SQLite/JSON persistence.
    assert FindingEvidence.model_validate(e.model_dump()).surface == TargetKind.DESKTOP


def test_schema_evidence_carries_surface_field_default_web() -> None:
    """evidence.schema.Evidence (cross_protocol consumer) also defaults WEB."""
    e = _make_schema_evidence(agent_id="web", title="x", description="y")
    assert e.surface == TargetKind.WEB


def test_schema_evidence_accepts_explicit_surface() -> None:
    e = _make_schema_evidence(
        agent_id="desktop_local_storage_secrets",
        title="planted JWT",
        description="leaked AWS key in app.asar",
        surface=TargetKind.DESKTOP,
    )
    assert e.surface == TargetKind.DESKTOP


# ── G.2 — Desktop layer mapping ─────────────────────────────────────────


def test_osilayer_has_desktop_member() -> None:
    """OSILayer.DESKTOP enables surface-aware layer tagging."""
    from vxis.synthesis.cross_protocol import OSILayer

    assert OSILayer.DESKTOP.value == "desktop"


def test_tag_layer_uses_desktop_for_desktop_agent_prefix() -> None:
    """Any agent_id starting with `desktop_` lands in DESKTOP layer."""
    from vxis.synthesis.cross_protocol import CrossProtocolSynthesizer, OSILayer

    syn = CrossProtocolSynthesizer()
    e = _make_schema_evidence(
        agent_id="desktop_local_storage_secrets", title="x", description="y"
    )
    assert syn._tag_layer(e) == OSILayer.DESKTOP


def test_tag_layer_uses_desktop_for_explicit_surface_field() -> None:
    """Even agents not on the prefix list land in DESKTOP if surface=DESKTOP.

    This lets new/custom desktop skills be classified without touching
    _AGENT_LAYER_MAP for every new addition.
    """
    from vxis.synthesis.cross_protocol import CrossProtocolSynthesizer, OSILayer

    syn = CrossProtocolSynthesizer()
    e = _make_schema_evidence(
        agent_id="custom_thing_not_in_map",
        title="x",
        description="y",
        surface=TargetKind.DESKTOP,
    )
    assert syn._tag_layer(e) == OSILayer.DESKTOP


def test_tag_layer_back_compat_for_existing_agents() -> None:
    """Existing web/cloud agent_id mappings unchanged (no regression)."""
    from vxis.synthesis.cross_protocol import CrossProtocolSynthesizer, OSILayer

    syn = CrossProtocolSynthesizer()
    web_e = _make_schema_evidence(agent_id="web", title="x", description="y")
    cloud_e = _make_schema_evidence(agent_id="cloud", title="x", description="y")
    assert syn._tag_layer(web_e) == OSILayer.APPLICATION
    assert syn._tag_layer(cloud_e) == OSILayer.CLOUD


# ── G.3 — desktop_creds_to_cloud chain pattern ──────────────────────────


def test_desktop_creds_to_cloud_chain_synthesizes() -> None:
    """Hardcoded AWS key in desktop binary + exposed cloud metadata = CRITICAL chain."""
    from vxis.synthesis.cross_protocol import CrossProtocolSynthesizer

    desktop_finding = _make_schema_evidence(
        agent_id="desktop_local_storage_secrets",
        title="Hardcoded AWS access key in app.asar",
        description="aws_access_key_id leaked in resources/app.asar at line 42",
        surface=TargetKind.DESKTOP,
        severity=Severity.HIGH,
    )
    cloud_finding = _make_schema_evidence(
        agent_id="cloud",
        title="S3 bucket exposed PII dump",
        description="public bucket listing, AWS data exfiltration possible",
        severity=Severity.MEDIUM,
    )

    syn = CrossProtocolSynthesizer()
    syn.add_findings([desktop_finding, cloud_finding])
    chains = asyncio.run(syn.synthesize())

    assert any(
        c.pattern_name == "desktop_creds_to_cloud" and c.severity == Severity.CRITICAL
        for c in chains
    ), f"expected desktop_creds_to_cloud CRITICAL chain, got: {[(c.pattern_name, c.severity) for c in chains]}"


# ── G.4 — Surface-boundary description decorator ────────────────────────


def test_chain_description_marks_cross_surface_boundary() -> None:
    """Chains that span two TargetKinds get a `[crosses surface boundary: ...]` marker.

    Lets analysts spot which chains are inherently cross-platform attacks
    (the highest-impact discoveries) at a glance.
    """
    from vxis.synthesis.cross_protocol import CrossProtocolSynthesizer

    desktop_finding = _make_schema_evidence(
        agent_id="desktop_local_storage_secrets",
        title="AWS key in app.asar",
        description="aws_access_key_id leaked",
        surface=TargetKind.DESKTOP,
        severity=Severity.HIGH,
    )
    cloud_finding = _make_schema_evidence(
        agent_id="cloud",
        title="S3 bucket public",
        description="data exfiltration via S3 dump",
        severity=Severity.MEDIUM,
    )

    syn = CrossProtocolSynthesizer()
    syn.add_findings([desktop_finding, cloud_finding])
    chains = asyncio.run(syn.synthesize())

    cross_surface = [c for c in chains if "crosses surface boundary" in c.description]
    assert cross_surface, "expected at least one cross-surface boundary marker in chain descriptions"
    # The marker should name both surfaces
    blob = cross_surface[0].description
    assert "desktop" in blob.lower()
    assert "web" in blob.lower()


def test_chain_description_omits_marker_for_same_surface() -> None:
    """Web→web chains (the existing patterns) must NOT gain the marker."""
    from vxis.synthesis.cross_protocol import CrossProtocolSynthesizer

    web_creds = _make_schema_evidence(
        agent_id="web",
        title=".env file exposed",
        description="aws_access_key in .env",
        severity=Severity.HIGH,
    )
    cloud_finding = _make_schema_evidence(
        agent_id="cloud",
        title="S3 bucket public",
        description="data exfiltration via S3 dump",
        severity=Severity.MEDIUM,
    )

    syn = CrossProtocolSynthesizer()
    syn.add_findings([web_creds, cloud_finding])
    chains = asyncio.run(syn.synthesize())

    # We expect credential_to_cloud to fire (existing pattern). It must NOT
    # gain the cross-surface marker since both findings default to WEB.
    cred_chains = [c for c in chains if c.pattern_name == "credential_to_cloud"]
    assert cred_chains, "credential_to_cloud should still match (regression check)"
    for c in cred_chains:
        assert "crosses surface boundary" not in c.description


# ── G.5 — scan_pipeline_v2 propagates ctx.kind to Evidence ──────────────


def test_pipeline_finding_builder_propagates_desktop_kind() -> None:
    """When ctx.kind == DESKTOP, every Evidence created from a Brain dict
    gets surface=DESKTOP so downstream synthesis can spot cross-surface chains."""
    from vxis.pipeline.scan_pipeline_v2 import _build_finding_from_dict

    finding_dict = {
        "id": "VXIS-0001",
        "title": "hardcoded secret",
        "severity": "high",
        "finding_type": "secret",
        "affected_component": "/Applications/X.app/Contents/Info.plist",
        "description": "...",
        "evidence": "found JWT",
    }
    finding = _build_finding_from_dict(
        finding_dict,
        scan_id="scan-1",
        target="/Applications/X.app",
        kind=TargetKind.DESKTOP,
    )
    assert finding.evidence
    assert finding.evidence[0].surface == TargetKind.DESKTOP


def test_pipeline_finding_builder_defaults_web_kind() -> None:
    """No kind kwarg → default WEB so legacy callers keep working."""
    from vxis.pipeline.scan_pipeline_v2 import _build_finding_from_dict

    finding = _build_finding_from_dict(
        {
            "id": "VXIS-0001",
            "title": "x",
            "severity": "low",
            "finding_type": "info",
            "affected_component": "/",
            "description": "y",
            "evidence": "z",
        },
        scan_id="scan-1",
        target="http://x",
    )
    assert finding.evidence[0].surface == TargetKind.WEB


# ── G.6 — desktop_ipc_to_lateral + regression ───────────────────────────


def test_desktop_ipc_to_lateral_chain_synthesizes() -> None:
    """Desktop IPC initial-access + privilege-escalation = CRITICAL chain.

    Models the attack: malicious payload over named pipe / COM lands as
    initial access, then climbs into application priv-esc on the same host.
    """
    from vxis.synthesis.cross_protocol import CrossProtocolSynthesizer

    ipc_initial = _make_schema_evidence(
        agent_id="desktop_ipc_injection",
        title="Named pipe accepts unauthenticated payload",
        description="initial access via vxis-test pipe injection",
        surface=TargetKind.DESKTOP,
        severity=Severity.HIGH,
    )
    app_pe = _make_schema_evidence(
        agent_id="web",
        title="Privilege escalation via writable install dir",
        description="admin sudo escalation possible from the foothold",
        severity=Severity.HIGH,
    )

    syn = CrossProtocolSynthesizer()
    syn.add_findings([ipc_initial, app_pe])
    chains = asyncio.run(syn.synthesize())

    assert any(
        c.pattern_name == "desktop_ipc_to_lateral" for c in chains
    ), f"expected desktop_ipc_to_lateral chain, got: {[c.pattern_name for c in chains]}"


def test_existing_web_patterns_unaffected() -> None:
    """All 10 pre-existing KNOWN_PATTERNS must still fire for matching evidence."""
    from vxis.synthesis.cross_protocol import KNOWN_PATTERNS

    pattern_names = {p.name for p in KNOWN_PATTERNS}
    for must_have in (
        "credential_to_cloud",
        "ssrf_to_internal",
        "subdomain_to_session",
        "dns_to_tls_bypass",
        "supply_chain_to_rce",
        "email_spoof_to_cred",
        "weak_tls_to_mitm",
        "container_escape_to_infra",
        "deserialization_to_rce",
        "wifi_to_ad",
    ):
        assert must_have in pattern_names, f"regression: pattern {must_have} missing"
    # Phase-G additions
    assert "desktop_creds_to_cloud" in pattern_names
    assert "desktop_ipc_to_lateral" in pattern_names


# ── helpers ─────────────────────────────────────────────────────────────


def _make_schema_evidence(
    *,
    agent_id: str,
    title: str,
    description: str,
    severity: Severity = Severity.MEDIUM,
    evidence_type: EvidenceType = EvidenceType.OTHER,
    surface: TargetKind | None = None,
) -> SchemaEvidence:
    """Build a schema.Evidence with sensible defaults; surface is optional so
    `default WEB` back-compat behaviour can be exercised explicitly."""
    kw: dict[str, Any] = dict(
        agent_id=agent_id,
        title=title,
        severity=severity,
        evidence_type=evidence_type,
        description=description,
    )
    if surface is not None:
        kw["surface"] = surface
    return SchemaEvidence(**kw)
