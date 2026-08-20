from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer

import vxis.cli.main as cli


def test_secure_scan_log_has_private_directory_and_file_permissions(tmp_path: Path) -> None:
    log_dir = tmp_path / "logs"

    log_path = cli._create_secure_scan_log(log_dir)

    assert log_path.parent == log_dir
    assert os.stat(log_dir).st_mode & 0o777 == 0o700
    assert os.stat(log_path).st_mode & 0o777 == 0o600


def test_tui_debug_log_uses_private_data_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vxis.cli.scan_tui import ScanTUI

    monkeypatch.setenv("VXIS_TUI_DEBUG", "1")
    monkeypatch.setenv("VXIS_DATA_DIR", str(tmp_path))
    tui = ScanTUI.__new__(ScanTUI)

    tui._dbg("safe diagnostic")

    debug_files = list((tmp_path / "logs").glob("tui_debug_*.log"))
    assert len(debug_files) == 1
    assert debug_files[0].read_text(encoding="utf-8") == "safe diagnostic\n"
    assert os.stat(debug_files[0].parent).st_mode & 0o777 == 0o700
    assert os.stat(debug_files[0]).st_mode & 0o777 == 0o600


def test_scheduled_scan_returns_explicit_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="ok", stderr=""),
    )

    assert cli._run_scheduled_scan("https://app.example", "standard") is True


def test_scheduled_scan_returns_explicit_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout="", stderr="failed"),
    )

    assert cli._run_scheduled_scan("https://app.example", "standard") is False


def test_schedule_run_does_not_advance_failed_schedule(monkeypatch: pytest.MonkeyPatch) -> None:
    schedule = SimpleNamespace(
        id="sched-1",
        target="https://app.example",
        profile="standard",
        next_run="later",
    )

    class Store:
        marked: list[str] = []

        def get(self, schedule_id: str):
            return schedule

        def mark_ran(self, schedule_id: str) -> None:
            self.marked.append(schedule_id)

    monkeypatch.setattr("vxis.scheduler.ScheduleStore", Store)
    monkeypatch.setattr(cli, "_run_scheduled_scan", lambda *args: False)

    with pytest.raises(typer.Exit) as exc:
        cli.schedule_run("sched-1")

    assert exc.value.exit_code == 1
    assert Store.marked == []


def test_schedule_tick_only_advances_successful_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    failed = SimpleNamespace(id="bad", target="https://bad.example", profile="standard")
    succeeded = SimpleNamespace(id="good", target="https://good.example", profile="standard")

    class Store:
        marked: list[str] = []

        def due_schedules(self):
            return [failed, succeeded]

        def mark_ran(self, schedule_id: str) -> None:
            self.marked.append(schedule_id)

    outcomes = iter((False, True))
    monkeypatch.setattr("vxis.scheduler.ScheduleStore", Store)
    monkeypatch.setattr(cli, "_run_scheduled_scan", lambda *args: next(outcomes))
    monkeypatch.setattr(cli, "_diff_latest_two_for_target", lambda target: _noop())

    with pytest.raises(typer.Exit) as exc:
        cli.schedule_tick()

    assert exc.value.exit_code == 1
    assert Store.marked == ["good"]


async def _noop() -> None:
    return None


def test_dashboard_init_uses_configured_password_and_canonical_db(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'vxis.db'}"
    engine = SimpleNamespace(dispose=_noop)
    captured: dict[str, object] = {}
    output: list[str] = []

    async def init_db(received_engine) -> None:
        captured["init_engine"] = received_engine

    async def ensure_default_admin(received_engine, password: str):
        captured["admin_engine"] = received_engine
        captured["password"] = password
        return object()

    def create_engine(url: str):
        captured["url"] = url
        return engine

    monkeypatch.setattr(cli, "_require_optional_dependency", lambda *args: None)
    monkeypatch.setattr(cli, "_get_config", lambda: SimpleNamespace(db_url=db_url))
    monkeypatch.setattr("vxis.core.db.create_engine", create_engine)
    monkeypatch.setattr("vxis.core.db.init_db", init_db)
    monkeypatch.setattr("vxis.dashboard.auth.ensure_default_admin", ensure_default_admin)
    monkeypatch.setattr(
        cli.console, "print", lambda value, *args, **kwargs: output.append(str(value))
    )

    cli.dashboard_init("super-secret")

    assert captured["url"] == db_url
    assert captured["password"] == "super-secret"
    assert all("super-secret" not in line and "password=admin" not in line for line in output)


def test_alembic_config_accepts_percent_encoded_database_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db_url = "postgresql+asyncpg://user:p%25ss@db.example/vxis"
    monkeypatch.setattr(cli, "_get_config", lambda: SimpleNamespace(db_url=db_url))

    config = cli._alembic_cfg()

    assert config.get_main_option("sqlalchemy.url") == db_url
