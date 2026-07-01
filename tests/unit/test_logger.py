"""Unit tests for vxis.core.logger.AuditLogger.

Uses pytest's tmp_path fixture to keep tests hermetic — no filesystem state
is shared between test functions.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vxis.core.logger import AuditLogger, redact_command


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _read_lines(path: Path) -> list[dict]:
    """Parse all JSON lines from *path* and return as a list of dicts."""
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    return [json.loads(line) for line in lines]


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestAuditLoggerInit:
    def test_creates_parent_directories(self, tmp_path: Path) -> None:
        log_path = tmp_path / "nested" / "deeply" / "audit.jsonl"
        AuditLogger(log_path)
        assert log_path.parent.exists()

    def test_does_not_create_file_on_init(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        AuditLogger(log_path)
        # File should not exist yet — only created on first write
        assert not log_path.exists()


# ---------------------------------------------------------------------------
# log_tool_run
# ---------------------------------------------------------------------------


class TestLogToolRun:
    def test_creates_jsonl_file_with_correct_event(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log_tool_run(
            scan_id="scan-001",
            plugin_name="nmap",
            target="192.168.1.1",
            command="nmap -sV 192.168.1.1",
            exit_code=0,
            elapsed_seconds=12.5,
        )

        records = _read_lines(tmp_path / "audit.jsonl")
        assert len(records) == 1
        rec = records[0]
        assert rec["event"] == "tool_run"

    def test_log_tool_run_contains_all_fields(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log_tool_run(
            scan_id="scan-001",
            plugin_name="nmap",
            target="10.0.0.5",
            command="nmap -p 80,443 10.0.0.5",
            exit_code=0,
            elapsed_seconds=3.14,
        )

        rec = _read_lines(tmp_path / "audit.jsonl")[0]
        assert rec["scan_id"] == "scan-001"
        assert rec["plugin_name"] == "nmap"
        assert rec["target"] == "10.0.0.5"
        assert rec["command"] == "nmap -p 80,443 10.0.0.5"
        assert rec["exit_code"] == 0
        assert rec["elapsed_seconds"] == pytest.approx(3.14)
        assert "timestamp" in rec

    def test_log_tool_run_redacts_ad_password_flag(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log_tool_run(
            scan_id="scan-001",
            plugin_name="netexec",
            target="10.0.0.5",
            command="nxc smb 10.0.0.5 -u alice -p SuperSecret123 --shares",
        )

        rec = _read_lines(tmp_path / "audit.jsonl")[0]
        assert "SuperSecret123" not in rec["command"]
        assert "-p ***" in rec["command"]

    def test_redact_command_handles_secret_flag_at_start(self) -> None:
        redacted = redact_command("--password SuperSecret run")
        assert "SuperSecret" not in redacted
        assert redacted == "--password *** run"

    def test_log_tool_run_optional_fields_can_be_none(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log_tool_run(
            scan_id="scan-002",
            plugin_name="masscan",
            target="10.0.0.0/24",
            command="masscan 10.0.0.0/24",
        )

        rec = _read_lines(tmp_path / "audit.jsonl")[0]
        assert rec["exit_code"] is None
        assert rec["elapsed_seconds"] is None


# ---------------------------------------------------------------------------
# log_scope_check
# ---------------------------------------------------------------------------


class TestLogScopeCheck:
    def test_records_in_scope_true(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log_scope_check("scan-010", "example.com", in_scope=True)

        rec = _read_lines(tmp_path / "audit.jsonl")[0]
        assert rec["event"] == "scope_check"
        assert rec["in_scope"] is True
        assert rec["target"] == "example.com"

    def test_records_in_scope_false(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log_scope_check("scan-010", "evil.com", in_scope=False)

        rec = _read_lines(tmp_path / "audit.jsonl")[0]
        assert rec["in_scope"] is False

    def test_scope_check_has_timestamp(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log_scope_check("scan-010", "example.com", in_scope=True)

        rec = _read_lines(tmp_path / "audit.jsonl")[0]
        assert "timestamp" in rec
        # ISO-8601 format — should contain 'T'
        assert "T" in rec["timestamp"]


# ---------------------------------------------------------------------------
# Append mode — multiple writes produce multiple lines
# ---------------------------------------------------------------------------


class TestAppendMode:
    def test_two_writes_produce_two_lines(self, tmp_path: Path) -> None:
        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path)

        logger.log_tool_run(
            scan_id="scan-A",
            plugin_name="nmap",
            target="10.0.0.1",
            command="nmap 10.0.0.1",
            exit_code=0,
        )
        logger.log_scope_check("scan-A", "10.0.0.1", in_scope=True)

        records = _read_lines(log_path)
        assert len(records) == 2
        assert records[0]["event"] == "tool_run"
        assert records[1]["event"] == "scope_check"

    def test_second_logger_instance_appends(self, tmp_path: Path) -> None:
        """Two separate AuditLogger instances pointing at the same file append correctly."""
        log_path = tmp_path / "shared.jsonl"

        AuditLogger(log_path).log_scan_start(
            "scan-X", "10.0.0.1", "quick", {"timeout": 30}
        )
        AuditLogger(log_path).log_scan_end("scan-X", finding_count=5, status="completed")

        records = _read_lines(log_path)
        assert len(records) == 2
        assert records[0]["event"] == "scan_start"
        assert records[1]["event"] == "scan_end"


# ---------------------------------------------------------------------------
# log_scan_start / log_scan_end
# ---------------------------------------------------------------------------


class TestLogScanLifecycle:
    def test_scan_start_fields(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        config = {"profile": "full", "timeout": 600}
        logger.log_scan_start("scan-100", "10.1.2.3", "full", config)

        rec = _read_lines(tmp_path / "audit.jsonl")[0]
        assert rec["event"] == "scan_start"
        assert rec["scan_id"] == "scan-100"
        assert rec["target"] == "10.1.2.3"
        assert rec["profile"] == "full"
        assert rec["config_snapshot"] == config

    def test_scan_end_fields(self, tmp_path: Path) -> None:
        logger = AuditLogger(tmp_path / "audit.jsonl")
        logger.log_scan_end("scan-100", finding_count=42, status="completed")

        rec = _read_lines(tmp_path / "audit.jsonl")[0]
        assert rec["event"] == "scan_end"
        assert rec["scan_id"] == "scan-100"
        assert rec["finding_count"] == 42
        assert rec["status"] == "completed"
