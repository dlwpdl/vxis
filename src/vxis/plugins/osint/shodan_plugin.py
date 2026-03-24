"""Shodan plugin — query Shodan for internet-exposed services."""

from __future__ import annotations

import os
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

_SHODAN_API_KEY_ENV = "SHODAN_API_KEY"


class ShodanPlugin(BasePlugin):
    """Query Shodan for exposed services associated with the target domain."""

    _meta = PluginMeta(
        name="shodan",
        version="1.0.0",
        tool_binary="shodan",
        category="osint",
        depends_on=("subfinder",),
        optional_depends=(),
        produces=("shodan_results",),
        timeout_seconds=300,
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
        # Resolve target to IP, then use 'shodan host' (works with free API).
        # 'shodan search/domain' requires a paid plan.
        return f"shodan host $(dig +short {target} A | head -1)"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        # Require SHODAN_API_KEY — skip gracefully if absent.
        api_key = os.environ.get(_SHODAN_API_KEY_ENV, "")
        if not api_key:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"shodan_results": []},
                findings=[],
                errors=["SHODAN_API_KEY environment variable not configured; skipping Shodan scan."],
            )

        services: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []

        raw_stdout = raw_stdout.strip()
        if not raw_stdout:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"shodan_results": services},
                findings=findings,
            )

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split("\t")
            # Pad to 5 fields in case some are missing.
            while len(parts) < 5:
                parts.append("")

            ip_str, port_raw, org, os_name, product = parts[:5]

            try:
                port = int(port_raw)
            except (ValueError, TypeError):
                port = 0

            service: dict[str, Any] = {
                "ip": ip_str,
                "port": port,
                "org": org,
                "os": os_name,
                "product": product,
            }
            services.append(service)

            # Each exposed service is an informational finding.
            finding: dict[str, Any] = {
                "type": "exposed_service",
                "ip": ip_str,
                "port": port,
                "org": org,
                "os": os_name,
                "product": product,
                "severity": "informational",
            }
            findings.append(finding)

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"shodan_results": services},
            findings=findings,
        )
