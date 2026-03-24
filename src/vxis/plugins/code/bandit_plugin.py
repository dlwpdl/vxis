"""Bandit plugin — Python-specific SAST scanning for security issues."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class BanditPlugin(BasePlugin):
    """Run bandit on Python source code and surface medium+ severity findings."""

    _meta = PluginMeta(
        name="bandit",
        version="1.0.0",
        tool_binary="bandit",
        category="code",
        tier=2,
        depends_on=(),
        produces=("python_sast",),
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
        source_path = tool_config.get("source_path", ".")
        return f"bandit -r {source_path} -f json -ll"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"python_sast": []}

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
                errors=["Failed to parse bandit JSON output"],
            )

        results: list[dict[str, Any]] = data.get("results", [])
        if not isinstance(results, list):
            results = []

        python_sast: list[dict[str, Any]] = []
        for result in results:
            cwe_raw = result.get("issue_cwe", {})
            cwe_id: int | None = None
            if isinstance(cwe_raw, dict):
                cwe_id = cwe_raw.get("id")
            elif isinstance(cwe_raw, int):
                cwe_id = cwe_raw

            finding: dict[str, Any] = {
                "test_id": result.get("test_id", ""),
                "issue_text": result.get("issue_text", ""),
                "issue_severity": result.get("issue_severity", ""),
                "filename": result.get("filename", ""),
                "line_number": result.get("line_number", 0),
                "cwe_id": cwe_id,
            }
            python_sast.append(finding)
            findings.append(finding)

        parsed_data["python_sast"] = python_sast

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
