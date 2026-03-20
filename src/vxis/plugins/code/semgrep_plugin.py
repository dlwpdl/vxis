"""Semgrep plugin — SAST scanning for security vulnerabilities in source code."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class SemgrepPlugin(BasePlugin):
    """Run semgrep SAST scan and surface ERROR/WARNING severity findings."""

    _meta = PluginMeta(
        name="semgrep",
        version="1.0.0",
        tool_binary="semgrep",
        category="code",
            tier=2,
        depends_on=(),
        produces=("sast_findings",),
        timeout_seconds=1800,
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
        source_path = tool_config.get("source_path", ".")
        return (
            f"semgrep scan --config auto --json"
            f" --severity ERROR --severity WARNING {source_path}"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"sast_findings": []}

        raw_stdout = raw_stdout.strip()
        if not raw_stdout:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
            )

        try:
            data = json.loads(raw_stdout)
        except json.JSONDecodeError:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
                errors=["Failed to parse semgrep JSON output"],
            )

        results: list[dict[str, Any]] = data.get("results", [])
        if not isinstance(results, list):
            results = []

        sast_findings: list[dict[str, Any]] = []
        for result in results:
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            raw_cwe = metadata.get("cwe", [])
            if isinstance(raw_cwe, str):
                raw_cwe = [raw_cwe]
            cwe_ids: list[str] = list(raw_cwe) if isinstance(raw_cwe, list) else []

            file_path = result.get("path", "")
            line_number = result.get("start", {}).get("line", 0)
            affected_component = f"{file_path}:{line_number}" if file_path else ""

            finding: dict[str, Any] = {
                "check_id": result.get("check_id", ""),
                "message": extra.get("message", ""),
                "severity": extra.get("severity", ""),
                "path": file_path,
                "line": line_number,
                "cwe_ids": cwe_ids,
                "affected_component": affected_component,
            }
            sast_findings.append(finding)
            findings.append(finding)

        parsed_data["sast_findings"] = sast_findings

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
