"""Unit tests for the VXIS web dashboard.

Tests use FastAPI's TestClient with an in-memory SQLite database populated
with fixture data so that no real scan artifacts are required.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Generator

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed (optional 'dashboard' extra)")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncEngine  # noqa: E402

from vxis.core.db import create_engine, get_session, init_db  # noqa: E402
from vxis.dashboard.app import app  # noqa: E402
from vxis.dashboard.auth import SESSION_COOKIE, ensure_default_admin  # noqa: E402
from vxis.models.db_models import FindingRecord, ScanRecord  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_engine() -> AsyncEngine:
    return create_engine("sqlite+aiosqlite:///:memory:")


async def _seed(engine: AsyncEngine) -> tuple[int, int]:
    """Initialise schema and insert one scan + two findings. Returns (scan_id, finding_id)."""
    await init_db(engine)

    async with get_session(engine) as session:
        scan = ScanRecord(
            target="192.168.1.1",
            profile="standard",
            status="completed",
            started_at=datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            finished_at=datetime(2024, 1, 15, 10, 5, 0, tzinfo=timezone.utc),
        )
        session.add(scan)
        await session.flush()  # populate scan.id

        f1 = FindingRecord(
            scan_id=scan.id,
            dedup_hash="abc123",
            title="SQL Injection in login form",
            description="The login endpoint is vulnerable to SQL injection.",
            severity="critical",
            effective_severity="critical",
            status="open",
            finding_type="sqli",
            target="192.168.1.1",
            port=80,
            protocol="tcp",
            affected_component="/login",
            source_plugin="sqlmap",
            confidence=0.95,
        )
        f2 = FindingRecord(
            scan_id=scan.id,
            dedup_hash="def456",
            title="Open SSH port",
            description="SSH is accessible from the internet.",
            severity="low",
            effective_severity="low",
            status="open",
            finding_type="misconfig",
            target="192.168.1.1",
            port=22,
            protocol="tcp",
            affected_component="sshd",
            source_plugin="nmap",
            confidence=1.0,
        )
        session.add(f1)
        session.add(f2)
        await session.flush()

        scan_id = scan.id
        finding_id = f1.id

    return scan_id, finding_id


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def seeded_engine() -> Generator[tuple[AsyncEngine, int, int], None, None]:
    """Provide a seeded in-memory engine; shared across all tests in this module."""
    engine = _build_engine()
    scan_id, finding_id = asyncio.run(_seed(engine))
    yield engine, scan_id, finding_id
    asyncio.run(engine.dispose())


@pytest.fixture()
def client(seeded_engine, monkeypatch) -> Generator[TestClient, None, None]:  # type: ignore[no-untyped-def]
    """TestClient wired to the seeded in-memory DB engine."""
    engine, scan_id, finding_id = seeded_engine
    monkeypatch.setenv("VXIS_DASHBOARD_AUTH_DISABLED", "1")
    app.state.engine = engine
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture()
def auth_engine() -> Generator[AsyncEngine, None, None]:
    engine = _build_engine()
    asyncio.run(init_db(engine))
    asyncio.run(ensure_default_admin(engine, password="secret-password"))
    yield engine
    asyncio.run(engine.dispose())


@pytest.fixture()
def auth_client(auth_engine, monkeypatch) -> Generator[TestClient, None, None]:  # type: ignore[no-untyped-def]
    monkeypatch.delenv("VXIS_DASHBOARD_AUTH_DISABLED", raising=False)
    monkeypatch.delenv("VXIS_DASHBOARD_TOKEN", raising=False)
    app.state.engine = auth_engine
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture()
def scan_id(seeded_engine) -> int:  # type: ignore[no-untyped-def]
    _, sid, _ = seeded_engine
    return sid


@pytest.fixture()
def finding_id(seeded_engine) -> int:  # type: ignore[no-untyped-def]
    _, _, fid = seeded_engine
    return fid


# ---------------------------------------------------------------------------
# Health endpoint
# ---------------------------------------------------------------------------

def test_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_health_version(client: TestClient) -> None:
    response = client.get("/health")
    assert "version" in response.json()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def test_dashboard_redirects_browser_without_auth(auth_client: TestClient) -> None:
    response = auth_client.get("/", headers={"accept": "text/html"}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_dashboard_accepts_bearer_token(auth_client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("VXIS_DASHBOARD_TOKEN", "dashboard-token")
    response = auth_client.get("/", headers={"authorization": "Bearer dashboard-token"})
    assert response.status_code == 200


def test_dashboard_login_creates_session(auth_client: TestClient) -> None:
    response = auth_client.post(
        "/login",
        data={"username": "admin", "password": "secret-password"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert SESSION_COOKIE in auth_client.cookies

    response = auth_client.get("/")
    assert response.status_code == 200


# ---------------------------------------------------------------------------
# Index page
# ---------------------------------------------------------------------------

def test_index_returns_html(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_index_contains_dashboard_title(client: TestClient) -> None:
    response = client.get("/")
    assert "VXIS" in response.text


def test_index_shows_scan_target(client: TestClient) -> None:
    response = client.get("/")
    assert "192.168.1.1" in response.text


def test_index_shows_stats_cards(client: TestClient) -> None:
    response = client.get("/")
    text = response.text
    # Stats card labels should be present
    assert "Total Scans" in text
    assert "Total Findings" in text
    assert "Critical" in text


def test_index_shows_at_least_one_scan_row(client: TestClient) -> None:
    response = client.get("/")
    assert "standard" in response.text  # profile column


def test_index_empty_state_not_shown_when_scans_exist(client: TestClient) -> None:
    response = client.get("/")
    assert "No scans yet" not in response.text


def test_scan_new_includes_scan_type_select(client: TestClient) -> None:
    response = client.get("/scan/new")
    assert response.status_code == 200
    assert 'name="scan_type"' in response.text
    assert 'value="external"' in response.text


# ---------------------------------------------------------------------------
# Scan detail page
# ---------------------------------------------------------------------------

def test_scan_detail_returns_html(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_scan_detail_shows_target(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}")
    assert "192.168.1.1" in response.text


def test_scan_detail_shows_severity_chart(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}")
    # Charts are rendered as inline SVG
    assert "<svg" in response.text


def test_scan_detail_shows_filter_buttons(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}")
    assert "Critical" in response.text
    assert "High" in response.text
    assert "Medium" in response.text


def test_scan_detail_shows_export_button(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}")
    assert "Export" in response.text


def test_scan_detail_404_on_unknown_scan(client: TestClient) -> None:
    response = client.get("/scan/99999")
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Findings partial (HTMX)
# ---------------------------------------------------------------------------

def test_findings_partial_returns_html(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}/findings")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_findings_partial_shows_findings(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}/findings")
    assert "SQL Injection" in response.text


def test_findings_partial_filter_by_severity(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}/findings?severity=critical")
    assert response.status_code == 200
    assert "SQL Injection" in response.text
    # Low finding should be excluded
    assert "Open SSH port" not in response.text


def test_findings_partial_filter_by_low(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}/findings?severity=low")
    assert response.status_code == 200
    assert "Open SSH port" in response.text
    assert "SQL Injection" not in response.text


def test_findings_partial_all_filter(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}/findings?severity=all")
    assert "SQL Injection" in response.text
    assert "Open SSH port" in response.text


def test_findings_partial_empty_result(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}/findings?severity=high")
    assert response.status_code == 200
    # Should show the empty state message, not an error
    assert "No findings" in response.text


# ---------------------------------------------------------------------------
# Finding detail page
# ---------------------------------------------------------------------------

def test_finding_detail_returns_html(
    client: TestClient, scan_id: int, finding_id: int
) -> None:
    response = client.get(f"/scan/{scan_id}/finding/{finding_id}")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]


def test_finding_detail_shows_title(
    client: TestClient, scan_id: int, finding_id: int
) -> None:
    response = client.get(f"/scan/{scan_id}/finding/{finding_id}")
    assert "SQL Injection" in response.text


def test_finding_detail_shows_severity_badge(
    client: TestClient, scan_id: int, finding_id: int
) -> None:
    response = client.get(f"/scan/{scan_id}/finding/{finding_id}")
    assert "CRITICAL" in response.text


def test_finding_detail_shows_description(
    client: TestClient, scan_id: int, finding_id: int
) -> None:
    response = client.get(f"/scan/{scan_id}/finding/{finding_id}")
    assert "vulnerable to SQL injection" in response.text


def test_finding_detail_shows_target(
    client: TestClient, scan_id: int, finding_id: int
) -> None:
    response = client.get(f"/scan/{scan_id}/finding/{finding_id}")
    assert "192.168.1.1" in response.text


def test_finding_detail_404_on_unknown(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}/finding/99999")
    assert response.status_code == 404


def test_finding_detail_breadcrumb_links_back(
    client: TestClient, scan_id: int, finding_id: int
) -> None:
    response = client.get(f"/scan/{scan_id}/finding/{finding_id}")
    assert f"/scan/{scan_id}" in response.text


# ---------------------------------------------------------------------------
# Export endpoint
# ---------------------------------------------------------------------------

def test_export_returns_file(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}/export")
    assert response.status_code == 200
    # Should be an HTML download
    assert "text/html" in response.headers.get("content-type", "")


def test_export_contains_html_report(client: TestClient, scan_id: int) -> None:
    response = client.get(f"/scan/{scan_id}/export")
    # The generated report should contain the target
    assert "192.168.1.1" in response.text


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

def test_kb_page_is_linked_route(client: TestClient) -> None:
    response = client.get("/kb")

    assert response.status_code == 200
    assert "Knowledge Base" in response.text


def test_kb_search_partial_returns_cards(client: TestClient) -> None:
    response = client.get("/kb/search?q=injection")

    assert response.status_code == 200
    assert "No results found" not in response.text
