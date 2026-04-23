"""Smoke tests — verify VXIS components integrate correctly.

External tool binaries (nmap, nuclei, subfinder, etc.) are NOT required.
Every test is purely in-process: imports, model construction, pipeline logic,
and an ephemeral SQLite database written to pytest's tmp_path.
"""

from __future__ import annotations

import uuid

import pytest


# ---------------------------------------------------------------------------
# 1. Basic import
# ---------------------------------------------------------------------------


def test_import_vxis() -> None:
    """Verify vxis package version matches the SSOT in pyproject.toml.

    Version is read dynamically from pyproject.toml so we never have to
    bump this assertion manually. SSOT chain is:
      pyproject.toml [project].version
        → src/vxis/registry.py:VERSION (manual mirror, see registry comment)
        → src/vxis/__init__.py:__version__ (re-export from registry)
    """
    import sys
    import tomllib
    from pathlib import Path

    import vxis

    # Locate pyproject.toml — climb up from this test file until we find it.
    pyproject_path = Path(__file__).resolve()
    for parent in pyproject_path.parents:
        candidate = parent / "pyproject.toml"
        if candidate.exists():
            pyproject_path = candidate
            break
    else:  # pragma: no cover — repo layout is fixed
        raise FileNotFoundError("pyproject.toml not found above test_smoke.py")

    with pyproject_path.open("rb") as fh:
        expected_version = tomllib.load(fh)["project"]["version"]

    assert vxis.__version__ == expected_version, (
        f"vxis.__version__={vxis.__version__!r} but pyproject.toml has "
        f"{expected_version!r} — bump src/vxis/registry.py:VERSION too"
    )

    # Sanity: tomllib is stdlib only on 3.11+; guard against an accidental backport.
    assert sys.version_info >= (3, 11), "tomllib requires Python 3.11+"


# ---------------------------------------------------------------------------
# 2. Plugin registry
# ---------------------------------------------------------------------------


def test_plugin_discovery() -> None:
    from vxis.plugins.registry import discover_plugins

    registry = discover_plugins()

    # Phase 0 ships 8 concrete plugins.
    assert len(registry) >= 8, f"Expected >= 8 plugins, got {len(registry)}: {list(registry)}"

    # Spot-check the three most critical plugin names.
    assert "subfinder" in registry, f"subfinder missing from registry: {list(registry)}"
    assert "nuclei" in registry, f"nuclei missing from registry: {list(registry)}"
    assert "nmap" in registry, f"nmap missing from registry: {list(registry)}"


# ---------------------------------------------------------------------------
# 3. DAG construction and validation
# ---------------------------------------------------------------------------


def test_dag_builds_from_plugins() -> None:
    from vxis.plugins.registry import build_dag_from_plugins, discover_plugins
    from vxis.core.engine import validate_dag

    registry = discover_plugins()
    dag = build_dag_from_plugins(registry)
    errors = validate_dag(dag)

    # External binary tools (apktool, frida, nm, codesign, strings) are not
    # DAG nodes — filter those known-external-tool optional-dep warnings.
    _EXTERNAL_TOOLS = {"apktool", "frida", "nm", "codesign", "strings"}
    real_errors = [
        e for e in errors
        if not any(tool in e for tool in _EXTERNAL_TOOLS)
    ]
    assert real_errors == [], f"DAG validation errors: {real_errors}"


# ---------------------------------------------------------------------------
# 4. Config schema
# ---------------------------------------------------------------------------


def test_config_loads() -> None:
    from vxis.config.schema import VXISConfig

    config = VXISConfig()

    assert "standard" in config.profiles
    # Verify the remaining built-in profiles are present.
    assert "passive" in config.profiles
    assert "stealth" in config.profiles
    assert "aggressive" in config.profiles


# ---------------------------------------------------------------------------
# 5. Finding model — round-trip through model_dump / re-instantiation
# ---------------------------------------------------------------------------


def test_finding_roundtrip() -> None:
    """Create finding → serialize → deserialize; dedup_hash must be stable."""
    from vxis.models.finding import Finding, Severity

    f = Finding(
        id=str(uuid.uuid4()),
        scan_id="test",
        title="Test Finding",
        description="Test",
        severity=Severity.high,
        target="example.com",
        finding_type="vulnerability",
        source_plugin="nuclei",
    )

    data = f.model_dump()
    f2 = Finding(**data)

    assert f2.title == "Test Finding"
    assert f2.dedup_hash == f.dedup_hash


# ---------------------------------------------------------------------------
# 6. Async DB round-trip
# ---------------------------------------------------------------------------


async def test_db_roundtrip(tmp_path: pytest.TempPathFactory) -> None:
    """Create DB schema → insert scan → insert finding → query back."""
    from vxis.core.db import create_engine, init_db, get_session
    from vxis.models.db_models import ScanRecord, FindingRecord

    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite+aiosqlite:///{db_path}")
    await init_db(engine)

    try:
        # Insert scan — id is autoincrement Integer; do NOT pass id="smoke-001"
        async with get_session(engine) as session:
            scan = ScanRecord(
                target="example.com",
                profile="standard",
                status="completed",
            )
            session.add(scan)
            await session.flush()  # populate scan.id before using it
            scan_id: int = scan.id

        # Insert finding linked to the scan
        async with get_session(engine) as session:
            finding = FindingRecord(
                scan_id=scan_id,
                dedup_hash="abc123def4567890",
                title="Smoke Test Finding",
                description="Inserted by integration smoke test.",
                severity="high",
                effective_severity="high",
                finding_type="vulnerability",
                target="example.com",
                source_plugin="nuclei",
            )
            session.add(finding)

        # Query scan back and verify
        async with get_session(engine) as session:
            result = await session.get(ScanRecord, scan_id)
            assert result is not None
            assert result.target == "example.com"
            assert result.status == "completed"

    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# 7. Full pipeline: normalizer → dedup → enricher
# ---------------------------------------------------------------------------


def test_full_pipeline_mock() -> None:
    """Normalizer → dedup → enricher pipeline works end-to-end with mock data."""
    from vxis.core.normalizer import FindingFactory, FindingDeduplicator
    from vxis.core.enricher import FindingEnricher

    # Nuclei JSON output with an explicit CVE so CVSS enrichment fires.
    nuclei_data: dict = {
        "results": [
            {
                "template-id": "CVE-2021-44228",
                "info": {
                    "name": "Log4j RCE",
                    "severity": "critical",
                    "tags": ["cve", "rce"],
                    "classification": {
                        "cve-id": ["CVE-2021-44228"],
                    },
                },
                "host": "example.com",
                "matched-at": "https://example.com/api",
                "matcher-status": True,
            }
        ]
    }

    # --- Normalize ---
    findings = FindingFactory.from_nuclei(nuclei_data, "smoke-scan")
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    # CVE extracted from classification block
    assert "CVE-2021-44228" in findings[0].cve_ids

    # --- Deduplicate (single finding, no change expected) ---
    deduper = FindingDeduplicator()
    deduped = deduper.deduplicate(findings)
    assert len(deduped) == 1

    # --- Enrich ---
    enricher = FindingEnricher()
    enriched = enricher.enrich(deduped)

    f = enriched[0]

    # CVSS is set because the finding has a CVE ID.
    assert f.cvss is not None, "CVSS should be populated for a finding with a CVE ID"
    assert f.cvss.base_score > 0

    # MITRE ATT&CK is populated (rce maps to TA0002/T1203 or similar).
    # The enricher sets mitre_attack as a single MitreAttack object, not a list.
    assert f.mitre_attack is not None, "MITRE ATT&CK should be populated"
    assert f.mitre_attack.tactic_id != ""
    assert f.mitre_attack.technique_id != ""

    # Remediation template is filled in.
    assert f.remediation is not None and len(f.remediation) > 0
