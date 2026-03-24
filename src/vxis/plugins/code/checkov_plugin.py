"""Checkov plugin — Infrastructure-as-Code (IaC) security scanning."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class CheckovPlugin(BasePlugin):
    """Scan Terraform, CloudFormation, and Kubernetes IaC files with checkov."""

    _meta = PluginMeta(
        name="checkov",
        version="1.0.0",
        tool_binary="checkov",
        category="code",
        tier=2,
        depends_on=(),
        produces=("iac_findings",),
        timeout_seconds=900,
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
        # --framework all covers Terraform, CloudFormation, Kubernetes, Dockerfile,
        # ARM, Bicep, Ansible, GitHub Actions, and every other checkov framework
        # in one pass, giving maximum IaC security coverage without maintaining an
        # explicit allowlist that grows stale as new frameworks are added.
        return (
            f"checkov -d {source_path}"
            " --framework all"
            " --output json --compact"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"iac_findings": []}

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
                errors=["Failed to parse checkov JSON output"],
            )

        # checkov output may be a list (one object per framework) or a single dict
        if isinstance(data, list):
            all_failed: list[dict[str, Any]] = []
            for section in data:
                failed = section.get("results", {}).get("failed_checks", [])
                if isinstance(failed, list):
                    all_failed.extend(failed)
        else:
            all_failed = data.get("results", {}).get("failed_checks", [])
            if not isinstance(all_failed, list):
                all_failed = []

        iac_findings: list[dict[str, Any]] = []
        for check in all_failed:
            line_range = check.get("file_line_range", [])
            finding: dict[str, Any] = {
                "check_id": check.get("check_id", ""),
                "name": check.get("check_name", check.get("name", "")),
                "guideline": check.get("guideline", ""),
                "file_path": check.get("file_path", ""),
                "file_line_range": line_range,
                "severity": check.get("severity", ""),
            }
            iac_findings.append(finding)
            findings.append(finding)

        parsed_data["iac_findings"] = iac_findings

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
