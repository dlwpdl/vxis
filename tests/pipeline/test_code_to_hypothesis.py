"""Tests for code_recon_to_hypotheses — Code → Hypothesis adapter.

Verifies:
  1. Manifest tech labels trigger appropriate vulnerability hypotheses.
  2. OpenAPI endpoints generate per-endpoint IDOR/auth/SSRF hypotheses.
  3. Secret templates generate git-history secret-leak hypotheses.
  4. All produced hypotheses have status="unverified" and source=CODE.
  5. Duplicate descriptions are deduplicated.
  6. Dockerfile / compose components produce no hypotheses (dynamic skills handle them).
  7. CodeHypothesis is Pydantic (JSON-serialisable, runtime-validated).
"""
from __future__ import annotations

import pytest

from vxis.interaction.surface import ReconReport, TargetKind


@pytest.fixture
def make_report():
    """Factory: build a ReconReport with arbitrary components."""
    def _build(components: list[dict[str, str]]) -> ReconReport:
        return ReconReport(
            surface_kind=TargetKind.CODE,
            fingerprint={"root": "/tmp/test-repo"},
            components=components,
        )
    return _build


# ---------------------------------------------------------------------------
# Manifest tech → hypothesis mapping
# ---------------------------------------------------------------------------

def test_fastapi_manifest_generates_hypothesis(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {"type": "manifest", "value": "pyproject.toml", "tech": "python+fastapi"}
    ])
    hypotheses = code_recon_to_hypotheses(report)
    assert len(hypotheses) >= 1
    vectors = {h.vector_id_candidate for h in hypotheses}
    assert "idor" in vectors


def test_litellm_manifest_generates_prompt_injection_hypothesis(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {"type": "manifest", "value": "pyproject.toml", "tech": "python+litellm"}
    ])
    hypotheses = code_recon_to_hypotheses(report)
    assert len(hypotheses) >= 1
    vectors = {h.vector_id_candidate for h in hypotheses}
    assert "prompt_injection" in vectors


def test_python_jose_manifest_generates_jwt_alg_hypothesis(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {"type": "manifest", "value": "pyproject.toml", "tech": "python+python-jose"}
    ])
    hypotheses = code_recon_to_hypotheses(report)
    assert len(hypotheses) >= 1
    vectors = {h.vector_id_candidate for h in hypotheses}
    assert "jwt_alg_confusion" in vectors


def test_korma_manifest_generates_sqli_hypothesis(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {"type": "manifest", "value": "project.clj", "tech": "clojure+korma"}
    ])
    hypotheses = code_recon_to_hypotheses(report)
    assert len(hypotheses) >= 1
    vectors = {h.vector_id_candidate for h in hypotheses}
    assert "sqli" in vectors


def test_unknown_tech_produces_no_hypotheses(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {"type": "manifest", "value": "Cargo.toml", "tech": "fortran+obscure"}
    ])
    hypotheses = code_recon_to_hypotheses(report)
    # "rust" keyword won't match "fortran+obscure", so zero hypotheses expected
    assert len(hypotheses) == 0


# ---------------------------------------------------------------------------
# OpenAPI endpoints
# ---------------------------------------------------------------------------

def test_openapi_endpoints_generate_hypotheses(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {
            "type": "openapi",
            "value": "openapi.yaml",
            "endpoints": "/users, /items/{id}, /admin/settings",
        }
    ])
    hypotheses = code_recon_to_hypotheses(report)
    # One hypothesis per endpoint
    assert len(hypotheses) == 3
    endpoints = {h.target_endpoint for h in hypotheses}
    assert "/users" in endpoints
    assert "/items/{id}" in endpoints
    assert "/admin/settings" in endpoints


def test_openapi_empty_endpoints_no_hypotheses(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {"type": "openapi", "value": "openapi.yaml", "endpoints": ""}
    ])
    hypotheses = code_recon_to_hypotheses(report)
    assert len(hypotheses) == 0


# ---------------------------------------------------------------------------
# Secret templates
# ---------------------------------------------------------------------------

def test_secret_template_generates_git_leak_hypothesis(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {
            "type": "secret_template",
            "value": ".env.example",
            "keys": "DATABASE_URL, SECRET_KEY, API_TOKEN",
        }
    ])
    hypotheses = code_recon_to_hypotheses(report)
    assert len(hypotheses) == 1
    h = hypotheses[0]
    assert h.vector_id_candidate == "secret_in_git"
    assert "SECRET_KEY" in h.description_en
    assert "SECRET_KEY" in h.description_ko
    assert h.confidence_hint >= 0.75


# ---------------------------------------------------------------------------
# Dockerfile / compose produce no hypotheses
# ---------------------------------------------------------------------------

def test_dockerfile_produces_no_hypotheses(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {"type": "dockerfile", "value": "Dockerfile", "base_image": "python:3.11-slim"}
    ])
    hypotheses = code_recon_to_hypotheses(report)
    assert len(hypotheses) == 0


def test_compose_produces_no_hypotheses(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {"type": "compose", "value": "docker-compose.yml", "services": "web, db"}
    ])
    hypotheses = code_recon_to_hypotheses(report)
    assert len(hypotheses) == 0


# ---------------------------------------------------------------------------
# All hypotheses have status="unverified" and source=CODE
# ---------------------------------------------------------------------------

def test_all_hypotheses_are_unverified(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = make_report([
        {"type": "manifest", "value": "pyproject.toml", "tech": "python+fastapi"},
        {"type": "secret_template", "value": ".env.example", "keys": "SECRET_KEY"},
        {"type": "openapi", "value": "openapi.yaml", "endpoints": "/health"},
    ])
    hypotheses = code_recon_to_hypotheses(report)
    assert len(hypotheses) >= 3
    for h in hypotheses:
        assert h.status == "unverified", f"Expected unverified, got {h.status}"
        assert h.source == TargetKind.CODE


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def test_duplicate_tech_deduplicates(make_report):
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    # Two manifest components with the same tech → same hypotheses deduplicated
    report = make_report([
        {"type": "manifest", "value": "pyproject.toml", "tech": "python+fastapi"},
        {"type": "manifest", "value": "requirements.txt", "tech": "python+fastapi"},
    ])
    h1 = code_recon_to_hypotheses(ReconReport(
        surface_kind=TargetKind.CODE,
        fingerprint={},
        components=[{"type": "manifest", "value": "pyproject.toml", "tech": "python+fastapi"}],
    ))
    h2 = code_recon_to_hypotheses(report)
    # Deduplication means same count regardless of two identical-tech manifests
    assert len(h2) == len(h1)


# ---------------------------------------------------------------------------
# CodeHypothesis Pydantic model
# ---------------------------------------------------------------------------

def test_code_hypothesis_pydantic_roundtrip():
    from vxis.pipeline.code_to_hypothesis import CodeHypothesis

    h = CodeHypothesis(
        description_en="Test hypothesis|||테스트 가설",
        description_ko="테스트 가설",
        target_endpoint="/api/users/{id}",
        vector_id_candidate="idor",
        confidence_hint=0.65,
    )
    assert h.status == "unverified"
    assert h.source == TargetKind.CODE
    assert 0.0 <= h.confidence_hint <= 1.0
    # JSON round-trip
    restored = CodeHypothesis.model_validate_json(h.model_dump_json())
    assert restored == h


def test_code_hypothesis_confidence_bounds():
    from pydantic import ValidationError
    from vxis.pipeline.code_to_hypothesis import CodeHypothesis

    with pytest.raises(ValidationError):
        CodeHypothesis(
            description_en="x",
            description_ko="x",
            confidence_hint=1.5,  # out of bounds
        )

    with pytest.raises(ValidationError):
        CodeHypothesis(
            description_en="x",
            description_ko="x",
            confidence_hint=-0.1,  # out of bounds
        )


# ---------------------------------------------------------------------------
# Empty report produces no hypotheses
# ---------------------------------------------------------------------------

def test_empty_report_produces_no_hypotheses():
    from vxis.pipeline.code_to_hypothesis import code_recon_to_hypotheses

    report = ReconReport(
        surface_kind=TargetKind.CODE,
        fingerprint={"root": "/tmp/empty"},
        components=[],
    )
    hypotheses = code_recon_to_hypotheses(report)
    assert hypotheses == []
