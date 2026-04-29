"""Tests for CodeRecon — manifest / Dockerfile / OpenAPI / .env.example detection."""
from __future__ import annotations

import textwrap

import pytest

from vxis.interaction.surface import Target, TargetKind


@pytest.fixture
def repo(tmp_path):
    """Create a fixture repo with several manifest files."""
    # Python manifest with FastAPI
    (tmp_path / "pyproject.toml").write_text(
        textwrap.dedent("""\
            [tool.poetry.dependencies]
            fastapi = "^0.100"
            python-jose = "^3.3"
        """),
        encoding="utf-8",
    )
    # Dockerfile
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11-slim\nRUN pip install -r requirements.txt\n",
        encoding="utf-8",
    )
    # docker-compose
    (tmp_path / "docker-compose.yml").write_text(
        textwrap.dedent("""\
            services:
              web:
                build: .
              db:
                image: postgres:15
        """),
        encoding="utf-8",
    )
    # .env.example
    (tmp_path / ".env.example").write_text(
        "DATABASE_URL=postgres://localhost/mydb\nSECRET_KEY=change_me\nDEBUG=false\n",
        encoding="utf-8",
    )
    # OpenAPI (JSON)
    (tmp_path / "openapi.json").write_text(
        '{"openapi":"3.0.0","paths":{"/users":{},"items/{}":{}}}',
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def target(repo):
    return Target(kind=TargetKind.CODE, entry=str(repo))


@pytest.fixture
def recon(target):
    from vxis.interaction.code.code_recon import CodeRecon
    return CodeRecon(target)


# ---------------------------------------------------------------------------
# component type checks
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_manifest_detected(recon, target):
    report = await recon.fingerprint(target)
    assert report.surface_kind == TargetKind.CODE
    manifests = [c for c in report.components if c["type"] == "manifest"]
    assert len(manifests) >= 1
    assert any("python" in c["tech"] for c in manifests)


@pytest.mark.asyncio
async def test_manifest_tech_detail_fastapi(recon, target):
    """pyproject.toml with fastapi → tech label includes 'fastapi'."""
    report = await recon.fingerprint(target)
    manifests = [c for c in report.components if c["type"] == "manifest"]
    assert any("fastapi" in c["tech"] for c in manifests)


@pytest.mark.asyncio
async def test_dockerfile_detected(recon, target):
    report = await recon.fingerprint(target)
    dockerfiles = [c for c in report.components if c["type"] == "dockerfile"]
    assert len(dockerfiles) >= 1
    assert "python" in dockerfiles[0]["base_image"]


@pytest.mark.asyncio
async def test_compose_services_detected(recon, target):
    report = await recon.fingerprint(target)
    composes = [c for c in report.components if c["type"] == "compose"]
    assert len(composes) >= 1
    services = composes[0]["services"].split(", ")
    assert "web" in services
    assert "db" in services


@pytest.mark.asyncio
async def test_secret_template_detected(recon, target):
    report = await recon.fingerprint(target)
    templates = [c for c in report.components if c["type"] == "secret_template"]
    assert len(templates) >= 1
    keys = templates[0]["keys"].split(", ")
    assert "SECRET_KEY" in keys
    assert "DATABASE_URL" in keys


@pytest.mark.asyncio
async def test_openapi_endpoints_detected(recon, target):
    report = await recon.fingerprint(target)
    apis = [c for c in report.components if c["type"] == "openapi"]
    assert len(apis) >= 1
    # Should have extracted at least one endpoint from openapi.json
    assert apis[0]["endpoints"] != ""


# ---------------------------------------------------------------------------
# non-directory target
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_non_directory_returns_empty(tmp_path):
    from vxis.interaction.code.code_recon import CodeRecon
    fake_file = tmp_path / "notadir"
    fake_file.write_text("x", encoding="utf-8")
    target = Target(kind=TargetKind.CODE, entry=str(fake_file))
    recon = CodeRecon(target)
    report = await recon.fingerprint(target)
    assert report.components == []
    assert "error" in report.fingerprint


# ---------------------------------------------------------------------------
# ReconReport is JSON-serializable
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_recon_report_serializable(recon, target):
    from vxis.interaction.surface import ReconReport
    report = await recon.fingerprint(target)
    assert ReconReport.model_validate_json(report.model_dump_json()) == report
