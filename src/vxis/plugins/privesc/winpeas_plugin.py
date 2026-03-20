"""WinPEAS plugin — Windows privilege escalation enumeration."""

from __future__ import annotations

import re
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# Same percentage-based severity scheme as LinPEAS
_SEVERITY_MAP: dict[str, str] = {
    "95": "critical",
    "70": "high",
    "50": "medium",
}

_MARKER_PATTERN = re.compile(r"\[(\d+)%\]\s*(.+)")


class WinpeasPlugin(BasePlugin):
    """Run WinPEAS and parse its colored output for privilege escalation vectors."""

    _meta = PluginMeta(
        name="winpeas",
        version="1.0.0",
        tool_binary="winpeas.exe",
        category="privesc",
            tier=2,
        depends_on=(),
        produces=("windows_privesc",),
        timeout_seconds=600,
    )

    @property
    def meta(self) -> PluginMeta:
        return self._meta

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        return "winpeas.exe quiet searchall"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """Parse WinPEAS output for severity-marked privilege escalation findings.

        WinPEAS annotates findings with percentage markers indicating exploitability:
        - [95%] = critical
        - [70%] = high
        - [50%] = medium
        """
        parsed_data: dict[str, Any] = {}
        findings: list[dict[str, Any]] = []
        errors: list[str] = []

        if not raw_stdout.strip():
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
                errors=errors,
            )

        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0}

        for line in raw_stdout.splitlines():
            # Strip ANSI escape codes
            clean_line = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
            if not clean_line:
                continue

            match = _MARKER_PATTERN.search(clean_line)
            if not match:
                continue

            pct = match.group(1)
            title_text = match.group(2).strip()
            severity = _SEVERITY_MAP.get(pct)
            if not severity:
                continue

            counts[severity] += 1
            findings.append({
                "type": "windows_privesc_vector",
                "severity": severity,
                "title": title_text,
                "description": (
                    f"WinPEAS identified a privilege escalation vector with "
                    f"{pct}% exploitability confidence: {title_text}"
                ),
                "confidence_pct": int(pct),
                "raw_line": clean_line,
            })

        parsed_data = {
            "findings_by_severity": counts,
            "total_findings": len(findings),
        }

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
            errors=errors,
        )
