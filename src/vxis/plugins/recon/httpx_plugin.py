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

        from urllib.parse import urlparse

        # Collect subdomains from subfinder output; fall back to target itself.
        subdomains: list[str] = ctx.get_data("subfinder", "subdomains", [])
        if not subdomains:
            # URL → hostname 변환 (Docker 컨테이너에서 읽을 수 있는 형태)
            host = urlparse(target).hostname or target
            subdomains = [host]

        if len(subdomains) == 1:
            # 단일 호스트는 파일 없이 직접 전달 (Windows temp 경로 → Docker 불일치 방지)
            return (
                f"httpx -u {subdomains[0]} -json -title -tech-detect -status-code"
                f" -follow-redirects -rate-limit {rate} -tls-grab -cdn -cname -asn"
                f" -response-header -favicon -method -websocket -ip -silent"
            )

        # 여러 호스트는 /workspace에 파일 저장 (Docker 마운트 경로)
        import os
        workspace = "/tmp/vxis_workspace"
        os.makedirs(workspace, exist_ok=True)
        input_file_host = os.path.join(workspace, "httpx_input.txt")
        input_file_container = "/workspace/httpx_input.txt"
        with open(input_file_host, "w") as f:
            f.write("\n".join(subdomains))

        return (
            f"httpx -l {input_file_container} -json -title -tech-detect -status-code"
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
