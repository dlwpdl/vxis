"""G.1 — Evidence.surface 필드 단위 테스트.

spec:
  - evidence.schema.Evidence 는 surface: TargetKind 필드를 가진다.
  - 기본값은 TargetKind.WEB (back-compat, 기존 직렬화 깨지지 않음).
  - 명시적으로 다른 surface 지정 가능.
  - model_validate(model_dump()) round-trip 에서 값 보존.
"""
from __future__ import annotations

import pytest

from vxis.evidence.schema import Evidence, EvidenceType, Severity
from vxis.interaction.surface import TargetKind


def _make(
    *,
    agent_id: str = "web",
    title: str = "t",
    description: str = "d",
    evidence_type: EvidenceType = EvidenceType.OTHER,
    severity: Severity = Severity.LOW,
    **kw: object,
) -> Evidence:
    return Evidence(
        agent_id=agent_id,
        title=title,
        description=description,
        evidence_type=evidence_type,
        severity=severity,
        **kw,  # type: ignore[arg-type]
    )


# ── 기본값 ──────────────────────────────────────────────────────────


def test_evidence_default_surface_is_web() -> None:
    """surface 지정 없이 생성하면 WEB 이 기본값이어야 한다."""
    e = _make()
    assert e.surface == TargetKind.WEB


def test_evidence_default_surface_with_legacy_constructor() -> None:
    """기존 코드가 surface 를 전달하지 않아도 WEB 으로 동작한다."""
    e = Evidence(
        agent_id="web",
        title="legacy finding",
        description="no surface field",
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        severity=Severity.MEDIUM,
    )
    assert e.surface == TargetKind.WEB


# ── 명시적 surface ────────────────────────────────────────────────


def test_evidence_carries_desktop_surface() -> None:
    """DESKTOP surface 를 명시하면 그대로 유지돼야 한다."""
    e = Evidence(
        agent_id="desktop_local_storage_secrets",
        title="hardcoded token",
        description="JWT in app.asar",
        evidence_type=EvidenceType.SECRET,
        severity=Severity.HIGH,
        surface=TargetKind.DESKTOP,
    )
    assert e.surface == TargetKind.DESKTOP


def test_evidence_carries_mobile_surface() -> None:
    e = Evidence(
        agent_id="mobile_static",
        title="exported activity",
        description="AndroidManifest exported",
        evidence_type=EvidenceType.MISCONFIGURATION,
        severity=Severity.MEDIUM,
        surface=TargetKind.MOBILE,
    )
    assert e.surface == TargetKind.MOBILE


def test_evidence_carries_game_surface() -> None:
    e = Evidence(
        agent_id="game_protocol",
        title="unencrypted game socket",
        description="game server sends plaintext",
        evidence_type=EvidenceType.NETWORK,
        severity=Severity.MEDIUM,
        surface=TargetKind.GAME,
    )
    assert e.surface == TargetKind.GAME


# ── round-trip 직렬화 ─────────────────────────────────────────────


def test_evidence_carries_surface_field() -> None:
    """TDD 명세 — Evidence 는 DESKTOP surface 를 round-trip 한다."""
    e = Evidence(
        agent_id="desktop_local_storage_secrets",
        title="t",
        description="...",
        evidence_type=EvidenceType.OTHER,
        severity=Severity.LOW,
        surface=TargetKind.DESKTOP,
    )
    restored = Evidence.model_validate(e.model_dump())
    assert restored.surface == TargetKind.DESKTOP


def test_evidence_default_roundtrip_preserves_web() -> None:
    """기본값 WEB 이 직렬화/역직렬화 후에도 WEB 으로 남아야 한다."""
    e = Evidence(
        agent_id="web",
        title="xss",
        description="reflected xss",
        evidence_type=EvidenceType.HTTP_EXCHANGE,
        severity=Severity.HIGH,
    )
    restored = Evidence.model_validate(e.model_dump())
    assert restored.surface == TargetKind.WEB


def test_evidence_model_dump_includes_surface_key() -> None:
    """직렬화 딕셔너리에 'surface' 키가 포함돼야 한다."""
    e = Evidence(
        agent_id="cloud",
        title="s3 bucket",
        description="public bucket",
        evidence_type=EvidenceType.MISCONFIGURATION,
        severity=Severity.HIGH,
        surface=TargetKind.WEB,
    )
    d = e.model_dump()
    assert "surface" in d
    assert d["surface"] == TargetKind.WEB.value
