"""LinPEAS plugin — Linux privilege escalation enumeration."""

from __future__ import annotations

import re
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# Mapping from linpeas severity percentage markers to canonical severity names
_SEVERITY_MAP: dict[str, str] = {
    "95": "critical",
    "70": "high",
    "50": "medium",
}

# Pattern matches lines with a percentage marker, e.g. "[95%] ..." or "╔...95%..."
_MARKER_PATTERN = re.compile(r"\[(\d+)%\]\s*(.+)")


class LinpeasPlugin(BasePlugin):
    """Run LinPEAS and parse its colored output for privilege escalation vectors."""

    _meta = PluginMeta(
        name="linpeas",
        version="1.0.0",
        tool_binary="bash",
        category="privesc",
        tier=2,
        depends_on=(),
        produces=("linux_privesc",),
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
        # LinPEAS runs locally on the compromised host.
        # The script path can be customised; default assumes it was dropped to
        # /opt/vxis/linpeas.sh by the VXIS agent upload step.
        linpeas_path: str = tool_config.get("linpeas_path", "/opt/vxis/linpeas.sh")
        # -q: quiet (suppress banner), -a: all checks including slow ones
        return f"bash {linpeas_path} -q -a"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """Parse linpeas output for severity-marked privilege escalation findings.

        LinPEAS annotates findings with percentage markers indicating exploitability:
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
            # Strip ANSI escape codes for cleaner matching
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
                "type": "linux_privesc_vector",
                "severity": severity,
                "title": title_text,
                "description": (
                    f"LinPEAS identified a privilege escalation vector with "
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
