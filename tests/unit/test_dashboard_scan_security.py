from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from vxis.dashboard.scan_manager import SCAN_TYPE_PLUGINS, SCAN_TYPE_TIERS, ScanManager


@pytest.fixture(autouse=True)
def _block_background_scans(monkeypatch):  # type: ignore[no-untyped-def]
    def _close(coro, **_kwargs):  # type: ignore[no-untyped-def]
        coro.close()
        return MagicMock()

    monkeypatch.setattr("vxis.dashboard.scan_manager.asyncio.create_task", _close)


def _scope_file(tmp_path, domains: list[str]):  # type: ignore[no-untyped-def]
    path = tmp_path / "scope.json"
    path.write_text(json.dumps({"in_scope_domains": domains}), encoding="utf-8")
    return path


@pytest.mark.asyncio
async def test_scan_manager_rejects_unknown_scan_type(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("VXIS_DASHBOARD_SCAN_SCOPE", "/missing/scope.json")

    with pytest.raises(ValueError, match="scan type"):
        await ScanManager().start_scan("example.com", scan_type="typo")


@pytest.mark.asyncio
async def test_scan_manager_rejects_shell_metacharacters(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(
        "VXIS_DASHBOARD_SCAN_SCOPE",
        str(_scope_file(tmp_path, ["example.com"])),
    )

    with pytest.raises(ValueError, match="target"):
        await ScanManager().start_scan("example.com; id", scan_type="external", profile="standard")


@pytest.mark.asyncio
async def test_scan_manager_rejects_unknown_profile(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(
        "VXIS_DASHBOARD_SCAN_SCOPE",
        str(_scope_file(tmp_path, ["example.com"])),
    )

    with pytest.raises(ValueError, match="profile"):
        await ScanManager().start_scan("example.com", scan_type="external", profile="not-a-profile")


@pytest.mark.asyncio
async def test_scan_manager_rejects_target_outside_server_scope(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv(
        "VXIS_DASHBOARD_SCAN_SCOPE",
        str(_scope_file(tmp_path, ["allowed.example"])),
    )

    with pytest.raises(ValueError, match="scope"):
        await ScanManager().start_scan("evil.example", scan_type="external", profile="standard")


@pytest.mark.asyncio
async def test_scan_manager_accepts_allowed_target(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    scope_path = _scope_file(tmp_path, ["example.com"])
    monkeypatch.setenv("VXIS_DASHBOARD_SCAN_SCOPE", str(scope_path))

    managed = await ScanManager().start_scan(
        "https://example.com/app", scan_type="external", profile="standard"
    )

    assert managed.target == "https://example.com/app"
    assert managed.scope_path == str(scope_path)


def test_cloud_scan_uses_registered_plugin_names() -> None:
    assert SCAN_TYPE_PLUGINS["cloud"] == [
        "prowler",
        "s3scanner",
        "trivy-k8s",
        "kube-bench",
    ]
    assert SCAN_TYPE_TIERS["cloud"] == 2
    assert SCAN_TYPE_TIERS["zero_touch"] == 1


def test_dashboard_expands_canonical_sqlite_url() -> None:
    from vxis.dashboard.app import _expand_db_url

    expanded = _expand_db_url("sqlite+aiosqlite:///~/.vxis/vxis.db")

    assert "~" not in expanded
    assert expanded.endswith("/.vxis/vxis.db")
