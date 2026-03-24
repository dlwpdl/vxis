"""httpx plugin — probe live hosts, collect metadata."""

from __future__ import annotations

import json
import tempfile
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta


class HttpxPlugin(BasePlugin):
    """Probe subdomains with httpx: status codes, titles, tech detection, TLS, CDN."""

    _meta = PluginMeta(
        name="httpx",
        version="1.0.0",
        tool_binary="httpx",
        category="recon",
        depends_on=("subfinder",),
        produces=("live_hosts", "live_urls"),
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
        rate_map = {
            "stealth": 10,
            "standard": 150,
            "aggressive": 300,
        }
        rate = rate_map.get(scan_profile, 150)

        # Collect subdomains from subfinder output; fall back to target itself.
        subdomains: list[str] = ctx.get_data("subfinder", "subdomains", [])
        if not subdomains:
            subdomains = [target]

        # Write subdomains to a deterministic temp file path.  In real execution
        # the engine would manage temp-file lifecycle; we embed the write here so
        # that the command string is immediately usable.
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            prefix="vxis_httpx_",
            delete=False,
        )
        tmp.write("\n".join(subdomains))
        tmp.close()
        input_file = tmp.name

        return (
            f"httpx -l {input_file} -json -title -tech-detect -status-code"
            f" -follow-redirects -rate-limit {rate} -tls-grab -cdn -cname -asn"
            f" -response-header -favicon -method -websocket -ip -silent"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        live_hosts: list[dict[str, Any]] = []
        live_urls: list[str] = []

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            url: str = record.get("url", "")
            if not url:
                continue

            host_entry: dict[str, Any] = {
                "url": url,
                "status_code": record.get("status_code"),
                "title": record.get("title", ""),
                "tech": record.get("tech", []),
                "cdn": record.get("cdn", False),
                "cname": record.get("cname", []),
                "asn": record.get("asn", {}),
            }

            live_hosts.append(host_entry)
            live_urls.append(url)

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={
                "live_hosts": live_hosts,
                "live_urls": live_urls,
            },
        )
