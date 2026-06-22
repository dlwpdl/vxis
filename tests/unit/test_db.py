"""Unit tests for vxis.core.db and vxis.models.db_models.

Uses an in-memory SQLite database so tests run without touching the filesystem
beyond what pytest's tmp_path provides for the aiosqlite driver.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect

from vxis.core.db import create_engine, get_session, init_db
from vxis.models.db_models import FindingRecord, ScanRecord, ToolRunRecord


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
async def engine():
    """In-memory async SQLite engine, initialised with the full schema."""
    eng = create_engine("sqlite+aiosqlite:///:memory:")
    await init_db(eng)
    yield eng
    await eng.dispose()


# ---------------------------------------------------------------------------
# Schema creation
# ---------------------------------------------------------------------------


class TestInitDb:
    async def test_init_db_succeeds(self) -> None:
        """init_db must complete without raising on a fresh in-memory database."""
        eng = create_engine("sqlite+aiosqlite:///:memory:")
        try:
            await init_db(eng)  # should not raise
            async with eng.begin() as conn:
                tables = await conn.run_sync(
                    lambda sync_conn: set(inspect(sync_conn).get_table_names())
                )
            assert {"scan_records", "finding_records", "tool_run_records"} <= tables
        finally:
            await eng.dispose()

    async def test_init_db_is_idempotent(self) -> None:
        """Calling init_db twice on the same engine must not raise."""
        eng = create_engine("sqlite+aiosqlite:///:memory:")
        try:
            await init_db(eng)
            await init_db(eng)  # second call — no-op
            async with eng.begin() as conn:
                tables = await conn.run_sync(
                    lambda sync_conn: set(inspect(sync_conn).get_table_names())
                )
            assert {"scan_records", "finding_records", "tool_run_records"} <= tables
        finally:
            await eng.dispose()


# ---------------------------------------------------------------------------
# ScanRecord CRUD
# ---------------------------------------------------------------------------


class TestScanRecord:
    async def test_insert_and_retrieve_scan_record(self, engine) -> None:
        async with get_session(engine) as session:
            scan = ScanRecord(
                target="10.0.0.1",
                profile="quick",
                status="running",
                started_at=datetime.now(timezone.utc),
                config_snapshot={"timeout": 300, "plugins": ["nmap"]},
            )
            session.add(scan)

        # Retrieve in a new session to verify persistence
        async with get_session(engine) as session:
            retrieved = await session.get(ScanRecord, 1)

        assert retrieved is not None
        assert retrieved.target == "10.0.0.1"
        assert retrieved.profile == "quick"
        assert retrieved.status == "running"
        assert retrieved.config_snapshot == {"timeout": 300, "plugins": ["nmap"]}

    async def test_scan_record_id_is_autoincremented(self, engine) -> None:
        async with get_session(engine) as session:
            s1 = ScanRecord(target="a.com", profile="quick", status="pending")
            s2 = ScanRecord(target="b.com", profile="full", status="pending")
            session.add_all([s1, s2])

        async with get_session(engine) as session:
            r1 = await session.get(ScanRecord, 1)
            r2 = await session.get(ScanRecord, 2)

        assert r1 is not None
        assert r2 is not None
        assert r1.id != r2.id

    async def test_scan_record_default_status(self, engine) -> None:
        async with get_session(engine) as session:
            scan = ScanRecord(target="example.com", profile="stealth")
            session.add(scan)

        async with get_session(engine) as session:
            retrieved = await session.get(ScanRecord, 1)

        assert retrieved is not None
        assert retrieved.status == "pending"


# ---------------------------------------------------------------------------
# FindingRecord CRUD with FK to ScanRecord
# ---------------------------------------------------------------------------


class TestFindingRecord:
    async def test_insert_and_retrieve_finding_with_fk(self, engine) -> None:
        """Insert a ScanRecord first, then attach a FindingRecord via FK."""
        async with get_session(engine) as session:
            scan = ScanRecord(target="10.0.0.5", profile="full", status="completed")
            session.add(scan)
            await session.flush()  # populate scan.id before FK reference

            finding = FindingRecord(
                scan_id=scan.id,
                dedup_hash="abc123def456abcd",
                title="Open SSH Port",
                description="SSH is exposed to the internet.",
                severity="medium",
                effective_severity="medium",
                status="open",
                finding_type="exposed_service",
                target="10.0.0.5",
                port=22,
                protocol="tcp",
                affected_component="sshd",
                source_plugin="nmap",
                confidence=0.95,
                cve_ids=["CVE-2023-1234"],
                cwe_ids=["CWE-284"],
            )
            session.add(finding)

        async with get_session(engine) as session:
            retrieved = await session.get(FindingRecord, 1)

        assert retrieved is not None
        assert retrieved.scan_id == 1
        assert retrieved.title == "Open SSH Port"
        assert retrieved.severity == "medium"
        assert retrieved.port == 22
        assert retrieved.protocol == "tcp"
        assert retrieved.cve_ids == ["CVE-2023-1234"]
        assert retrieved.cwe_ids == ["CWE-284"]
        assert retrieved.confidence == pytest.approx(0.95)

    async def test_finding_json_fields_round_trip(self, engine) -> None:
        """JSON columns (evidence, references, raw_data) survive a DB round-trip."""
        evidence_data = [{"evidence_type": "log", "title": "SSH Banner", "content": "OpenSSH_8.9"}]
        raw = {"nmap_output": "<nmaprun>...</nmaprun>"}

        async with get_session(engine) as session:
            scan = ScanRecord(target="192.168.0.1", profile="quick", status="completed")
            session.add(scan)
            await session.flush()

            finding = FindingRecord(
                scan_id=scan.id,
                dedup_hash="deadbeef12345678",
                title="Outdated OpenSSH",
                description="Old version detected.",
                severity="high",
                effective_severity="high",
                status="open",
                finding_type="outdated_software",
                target="192.168.0.1",
                source_plugin="banner_grabber",
                evidence=evidence_data,
                raw_data=raw,
                mitre_attack={"tactic_id": "TA0001", "technique_id": "T1190"},
            )
            session.add(finding)

        async with get_session(engine) as session:
            retrieved = await session.get(FindingRecord, 1)

        assert retrieved is not None
        assert retrieved.evidence == evidence_data
        assert retrieved.raw_data == raw
        assert retrieved.mitre_attack == {"tactic_id": "TA0001", "technique_id": "T1190"}

    async def test_multiple_findings_per_scan(self, engine) -> None:
        async with get_session(engine) as session:
            scan = ScanRecord(target="172.16.0.1", profile="full", status="completed")
            session.add(scan)
            await session.flush()

            for i in range(3):
                session.add(FindingRecord(
                    scan_id=scan.id,
                    dedup_hash=f"hash{i:016d}",
                    title=f"Finding {i}",
                    description="",
                    severity="low",
                    effective_severity="low",
                    status="open",
                    finding_type="info",
                    target="172.16.0.1",
                    source_plugin="scanner",
                ))

        async with get_session(engine) as session:
            from sqlalchemy import select
            result = await session.execute(
                select(FindingRecord).where(FindingRecord.scan_id == 1)
            )
            findings = result.scalars().all()

        assert len(findings) == 3


# ---------------------------------------------------------------------------
# ToolRunRecord
# ---------------------------------------------------------------------------


class TestToolRunRecord:
    async def test_insert_and_retrieve_tool_run(self, engine) -> None:
        async with get_session(engine) as session:
            scan = ScanRecord(target="10.0.1.1", profile="quick", status="running")
            session.add(scan)
            await session.flush()

            tool_run = ToolRunRecord(
                scan_id=scan.id,
                plugin_name="nmap",
                command="nmap -sV 10.0.1.1",
                return_code=0,
                elapsed_seconds=8.42,
                state="done",
            )
            session.add(tool_run)

        async with get_session(engine) as session:
            retrieved = await session.get(ToolRunRecord, 1)

        assert retrieved is not None
        assert retrieved.plugin_name == "nmap"
        assert retrieved.command == "nmap -sV 10.0.1.1"
        assert retrieved.return_code == 0
        assert retrieved.elapsed_seconds == pytest.approx(8.42)
        assert retrieved.state == "done"
