"""DNStwist plugin — detect typosquatting and lookalike domains."""

from __future__ import annotations

import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class DnstwistPlugin(BasePlugin):
    """Find registered lookalike domains that could be used for phishing or brand abuse."""

    _meta = PluginMeta(
        name="dnstwist",
        version="1.0.0",
        tool_binary="dnstwist",
        category="brand",
        depends_on=(),
        produces=("lookalike_domains",),
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
        # --mxcheck: test if lookalike domains have functioning mail servers
        # (strong indicator of active phishing infrastructure).
        # --whois: include registrar / creation-date intel for registered domains.
        # stealth omits --mxcheck (makes extra DNS/SMTP connections per candidate).
        if scan_profile == "stealth":
            extra = "--whois"
        else:
            extra = "--mxcheck --whois"

        return f"dnstwist --registered --format json {extra} {target}"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"lookalike_domains": []}

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
                errors=["Failed to parse dnstwist JSON output"],
            )

        if not isinstance(records, list):
            records = [records]

        registered_domains: list[dict[str, Any]] = []

        for record in records:
            dns_a: list[str] = record.get("dns_a", []) or []
            dns_mx: list[str] = record.get("dns_mx", []) or []

            # Only include domains that have actual DNS records (are registered).
            if not dns_a and not dns_mx:
                continue

            domain_info: dict[str, Any] = {
                "fuzzer": record.get("fuzzer", ""),
                "domain": record.get("domain", ""),
                "dns_a": dns_a,
                "dns_mx": dns_mx,
            }
            registered_domains.append(domain_info)
            findings.append(domain_info)

        parsed_data["lookalike_domains"] = registered_domains

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
