"""testssl plugin — TLS/SSL configuration analysis."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# Severities that represent actual issues (exclude informational / clean states).
_NOISE_SEVERITIES = {"OK", "INFO", "WARN", "NOT TESTED", "NOT ok"}
_PASS_SEVERITIES = {"OK", "INFO"}


class TestsslPlugin(BasePlugin):
    """Analyse TLS configuration of HTTPS endpoints discovered by nmap."""

    _meta = PluginMeta(
        name="testssl",
        version="1.0.0",
        tool_binary="testssl.sh",
        category="crypto",
        depends_on=(),
        optional_depends=("nmap",),
        produces=("tls_findings",),
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
        # Collect hosts that have port 443 open from nmap results.
        nmap_hosts: list[dict[str, Any]] = ctx.get_data("nmap", "hosts", [])
        https_targets: list[str] = []
        for host in nmap_hosts:
            ip = host.get("ip") or host.get("hostname", "")
            for port_entry in host.get("ports", []):
                if port_entry.get("port") == 443 and port_entry.get("state") == "open":
                    https_targets.append(ip)
                    break

        if not https_targets:
            https_targets = [target]

        # testssl.sh operates on one host at a time; the engine will call
        # build_command once and can iterate over multiple hosts if needed.
        # We run against the first (or sole) target here; production orchestration
        # would fan out across hosts.
        host = https_targets[0]

        if scan_profile == "stealth":
            flags = "--jsonfile - --fast --sneaky --severity LOW --nodns min"
        elif scan_profile == "aggressive":
            # Maximum depth: protocols, all cipher suites per protocol,
            # known vulnerabilities (BEAST, POODLE, Heartbleed, ROBOT, etc.),
            # HTTP security headers, server defaults, and certificate chain.
            flags = (
                "--jsonfile - --severity LOW"
                " --protocols --vulnerable --headers"
                " --cipher-per-proto --server-defaults --server-preference"
                " --certificate"
            )
        else:
            # Standard: protocols + vulnerabilities + headers + certificate chain.
            # Deliberately omits --fast and --sneaky to maximise check depth.
            flags = (
                "--jsonfile - --severity LOW"
                " --protocols --vulnerable --headers"
                " --server-defaults --certificate"
            )

        return f"testssl.sh {flags} {host}:443"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []

        if not raw_stdout.strip():
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"tls_findings": findings},
            )

        try:
            records = json.loads(raw_stdout)
        except json.JSONDecodeError:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"tls_findings": findings},
                errors=["Failed to parse testssl JSON output"],
            )

        if not isinstance(records, list):
            records = [records]

        for record in records:
            severity: str = record.get("severity", "")
            # Skip clean / informational results — only surface actionable issues.
            if severity in _PASS_SEVERITIES:
                continue

            findings.append({
                "id": record.get("id", ""),
                "severity": severity,
                "finding": record.get("finding", ""),
                "cwe": record.get("cwe", ""),
                "cve": record.get("cve", ""),
            })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"tls_findings": findings},
            findings=findings,
        )
