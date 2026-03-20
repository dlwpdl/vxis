"""Gitleaks plugin — detect secrets and credentials in source code repositories."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.models.evidence import mask_secret
from vxis.plugins.base import BasePlugin, PluginMeta


class GitleaksPlugin(BasePlugin):
    """Scan a git repository for leaked secrets using gitleaks."""

    _meta = PluginMeta(
        name="gitleaks",
        version="1.0.0",
        tool_binary="gitleaks",
        category="osint",
        depends_on=(),
        produces=("code_secrets",),
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
        repo_url = tool_config.get("repo_url", target)
        return (
            f"gitleaks detect"
            f" --source={repo_url}"
            " --report-format json"
            " --report-path /tmp/vxis/gitleaks.json"
            " --no-git"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"code_secrets": []}

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
                errors=["Failed to parse Gitleaks JSON output"],
            )

        if not isinstance(records, list):
            records = [records]

        secrets: list[dict[str, Any]] = []
        for record in records:
            raw_secret = record.get("Secret", record.get("secret", ""))
            finding: dict[str, Any] = {
                "rule_id": record.get("RuleID", record.get("rule_id", "")),
                "description": record.get("Description", record.get("description", "")),
                "file": record.get("File", record.get("file", "")),
                "start_line": record.get("StartLine", record.get("start_line", 0)),
                "commit": record.get("Commit", record.get("commit", "")),
                "secret": mask_secret(str(raw_secret)) if raw_secret else "",
            }
            secrets.append(finding)
            findings.append(finding)

        parsed_data["code_secrets"] = secrets

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
