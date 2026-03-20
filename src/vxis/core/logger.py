"""Append-only JSONL audit logger for VXIS security automation platform.

Every operation that touches an external target is recorded here for
compliance, reproducibility, and incident investigation purposes.  The log
file is written in JSON Lines format (one JSON object per line) so that it
can be parsed incrementally with standard tooling.

Design constraints:
- Append-only: records are never modified or deleted after being written.
- UTC timestamps: all events carry an 'timestamp' field in ISO-8601 UTC.
- Atomic line writes: each record is serialised to a single line before
  being written so that concurrent writers on the same process do not
  interleave partial records.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLogger:
    """Append-only JSONL audit logger.

    Creates the parent directory tree on instantiation if it does not
    already exist.  All writes are synchronous; for high-throughput
    scenarios consider wrapping this class with an async queue.

    Args:
        log_path: Absolute or relative path to the target ``.jsonl`` file.
    """

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write(self, record: dict[str, Any]) -> None:
        """Append a single record to the log file.

        A UTC timestamp is injected as the 'timestamp' key before
        serialisation.  The record is written as a single JSON line
        followed by a newline character.

        Args:
            record: Arbitrary dictionary to serialise and append.
        """
        record["timestamp"] = datetime.now(timezone.utc).isoformat()
        line = json.dumps(record, default=str) + "\n"
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)

    # ------------------------------------------------------------------
    # Public logging methods
    # ------------------------------------------------------------------

    def log_tool_run(
        self,
        scan_id: str,
        plugin_name: str,
        target: str,
        command: str,
        exit_code: int | None = None,
        elapsed_seconds: float | None = None,
    ) -> None:
        """Record a single tool execution event.

        Args:
            scan_id: Identifier of the parent scan.
            plugin_name: Name of the plugin that invoked the tool.
            target: Target against which the tool was run.
            command: Full command string that was executed.
            exit_code: Process exit code, or None if not yet finished.
            elapsed_seconds: Wall-clock execution time, or None if unknown.
        """
        self._write(
            {
                "event": "tool_run",
                "scan_id": scan_id,
                "plugin_name": plugin_name,
                "target": target,
                "command": command,
                "exit_code": exit_code,
                "elapsed_seconds": elapsed_seconds,
            }
        )

    def log_scope_check(
        self,
        scan_id: str,
        target: str,
        in_scope: bool,
    ) -> None:
        """Record the result of a scope validation check.

        Args:
            scan_id: Identifier of the parent scan.
            target: Target that was checked.
            in_scope: True when the target passed the scope check.
        """
        self._write(
            {
                "event": "scope_check",
                "scan_id": scan_id,
                "target": target,
                "in_scope": in_scope,
            }
        )

    def log_scan_start(
        self,
        scan_id: str,
        target: str,
        profile: str,
        config_snapshot: dict[str, Any],
    ) -> None:
        """Record the initiation of a scan.

        Args:
            scan_id: Identifier of the scan being started.
            target: Primary scan target.
            profile: Scan profile name (e.g. 'full', 'quick', 'stealth').
            config_snapshot: Snapshot of the effective configuration at
                             scan start time for later reproducibility.
        """
        self._write(
            {
                "event": "scan_start",
                "scan_id": scan_id,
                "target": target,
                "profile": profile,
                "config_snapshot": config_snapshot,
            }
        )

    def log_scan_end(
        self,
        scan_id: str,
        finding_count: int,
        status: str,
    ) -> None:
        """Record the completion of a scan.

        Args:
            scan_id: Identifier of the scan that finished.
            finding_count: Total number of findings produced by this scan.
            status: Final scan status (e.g. 'completed', 'failed', 'aborted').
        """
        self._write(
            {
                "event": "scan_end",
                "scan_id": scan_id,
                "finding_count": finding_count,
                "status": status,
            }
        )
