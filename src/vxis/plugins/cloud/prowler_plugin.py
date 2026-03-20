"""Prowler plugin — AWS/Azure/GCP cloud security configuration auditing."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class ProwlerPlugin(BasePlugin):
    """Audit cloud infrastructure security posture using Prowler."""

    _meta = PluginMeta(
        name="prowler",
        version="1.0.0",
        tool_binary="prowler",
        category="cloud",
        depends_on=(),
        produces=("cloud_findings",),
        timeout_seconds=3600,
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
        provider = tool_config.get("provider", "aws")
        return (
            f"prowler {provider}"
            " --output-formats json"
            " --output-directory /tmp/vxis/prowler"
            " --severity critical high medium"
            " -b"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"cloud_findings": []}

        raw_stdout = raw_stdout.strip()
        if not raw_stdout:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
            )

        try:
            records = json.loads(raw_stdout)
        except json.JSONDecodeError:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
                errors=["Failed to parse Prowler JSON output"],
            )

        if not isinstance(records, list):
            records = [records]

        cloud_findings: list[dict[str, Any]] = []
        for record in records:
            status = record.get("Status", record.get("status", ""))
            if str(status).upper() != "FAIL":
                continue

            remediation_raw = record.get("Remediation", {})
            remediation_text = ""
            if isinstance(remediation_raw, dict):
                recommendation = remediation_raw.get("Recommendation", remediation_raw.get("recommendation", {}))
                if isinstance(recommendation, dict):
                    remediation_text = recommendation.get("Text", recommendation.get("text", ""))
                else:
                    remediation_text = str(recommendation)
            else:
                remediation_text = str(remediation_raw)

            finding: dict[str, Any] = {
                "check_id": record.get("CheckID", record.get("check_id", "")),
                "status": "FAIL",
                "severity": record.get("Severity", record.get("severity", "")),
                "service_name": record.get("ServiceName", record.get("service_name", "")),
                "description": record.get("Description", record.get("description", "")),
                "risk": record.get("Risk", record.get("risk", "")),
                "remediation": remediation_text,
                "resource_arn": record.get("ResourceArn", record.get("resource_arn", "")),
            }
            cloud_findings.append(finding)
            findings.append(finding)

        parsed_data["cloud_findings"] = cloud_findings

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
