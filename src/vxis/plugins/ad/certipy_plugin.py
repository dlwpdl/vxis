"""Certipy plugin — Active Directory Certificate Services (ADCS) vulnerability assessment."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# ESC classes and their severity assignments
_ESC_SEVERITY: dict[str, str] = {
    "ESC1": "critical",
    "ESC2": "critical",
    "ESC3": "high",
    "ESC4": "high",
    "ESC5": "high",
    "ESC6": "high",
    "ESC7": "high",
    "ESC8": "high",
}


class CertipyPlugin(BasePlugin):
    """Enumerate ADCS misconfigurations using certipy find."""

    _meta = PluginMeta(
        name="certipy",
        version="1.0.0",
        tool_binary="certipy",
        category="ad",
        depends_on=(),
        produces=("adcs_findings",),
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
        username: str = tool_config.get("username", "")
        domain: str = tool_config.get("domain", target)
        password: str = tool_config.get("password", "")
        dc_ip: str = tool_config.get("dc_ip", "")
        return (
            f"certipy find -u {username}@{domain} -p {password}"
            f" -dc-ip {dc_ip} -json"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """Parse certipy JSON output and extract vulnerable certificate templates."""
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

        try:
            data = json.loads(raw_stdout.strip())
        except json.JSONDecodeError as exc:
            errors.append(f"JSON decode error: {exc}")
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
                errors=errors,
            )

        templates: list[dict[str, Any]] = data.get("Certificate Templates", [])
        vulnerable_templates: list[dict[str, Any]] = []

        for template in templates:
            vulnerability = template.get("Vulnerability", "")
            if not vulnerability:
                continue

            esc_class = vulnerability.strip().upper()
            severity = _ESC_SEVERITY.get(esc_class, "high")
            template_name = template.get("Template Name", "Unknown")

            vuln_entry = {
                "template_name": template_name,
                "vulnerability": esc_class,
                "severity": severity,
                "enabled": template.get("Enabled", False),
                "client_authentication": template.get("Client Authentication", False),
                "enrollee_supplies_subject": template.get("Enrollee Supplies Subject", False),
            }
            vulnerable_templates.append(vuln_entry)

            findings.append({
                "type": "adcs_vulnerable_template",
                "severity": severity,
                "title": f"ADCS Vulnerable Template: {template_name} ({esc_class})",
                "description": (
                    f"Certificate template '{template_name}' is vulnerable to {esc_class}. "
                    f"Enabled: {template.get('Enabled', False)}, "
                    f"Client Authentication: {template.get('Client Authentication', False)}, "
                    f"Enrollee Supplies Subject: {template.get('Enrollee Supplies Subject', False)}."
                ),
                "template_name": template_name,
                "esc_class": esc_class,
            })

        parsed_data = {
            "vulnerable_templates": vulnerable_templates,
            "total_vulnerable": len(vulnerable_templates),
        }

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
            errors=errors,
        )
