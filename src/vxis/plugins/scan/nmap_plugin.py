"""nmap plugin — port scanning and service version detection."""

from __future__ import annotations

import tempfile
import xml.etree.ElementTree as ET
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# Port lists per scan profile
_PORT_PROFILES: dict[str, str] = {
    "stealth": "80,443,8080,8443,22,3389",
    "standard": "--top-ports 1000",
    "aggressive": "-",  # all 65535 ports
}


class NmapPlugin(BasePlugin):
    """Scan live hosts discovered by httpx for open ports and services."""

    _meta = PluginMeta(
        name="nmap",
        version="1.0.0",
        tool_binary="nmap",
        category="scan",
        depends_on=("httpx",),
        produces=("open_ports", "services"),
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
        timing_map = {
            "stealth": 2,
            "standard": 3,
            "aggressive": 4,
        }
        timing = timing_map.get(scan_profile, 3)

        # Filter out CDN-fronted hosts — scanning CDN IPs yields noise.
        live_hosts: list[dict[str, Any]] = ctx.get_data("httpx", "live_hosts", [])
        ips: list[str] = []
        seen: set[str] = set()
        for host in live_hosts:
            if host.get("cdn", False):
                continue
            url: str = host.get("url", "")
            # Extract hostname/IP from the URL (strip scheme and path).
            hostname = url.split("//")[-1].split("/")[0].split(":")[0]
            if hostname and hostname not in seen:
                seen.add(hostname)
                ips.append(hostname)

        if not ips:
            ips = [target]

        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".txt",
            prefix="vxis_nmap_",
            delete=False,
        )
        tmp.write("\n".join(ips))
        tmp.close()
        input_file = tmp.name

        port_spec = _PORT_PROFILES.get(scan_profile, _PORT_PROFILES["standard"])
        if port_spec == "-":
            port_flag = "-p-"
        elif port_spec.startswith("--"):
            port_flag = port_spec
        else:
            port_flag = f"-p {port_spec}"

        return (
            f"nmap -iL {input_file} -sV -sC --open --reason -oX -"
            f" {port_flag} -T{timing}"
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        hosts: list[dict[str, Any]] = []

        if not raw_stdout.strip():
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"hosts": hosts},
            )

        try:
            root = ET.fromstring(raw_stdout)
        except ET.ParseError:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={"hosts": hosts},
                errors=["Failed to parse nmap XML output"],
            )

        for host_elem in root.findall("host"):
            # Resolve IP address
            address_elem = host_elem.find("address[@addrtype='ipv4']")
            if address_elem is None:
                address_elem = host_elem.find("address")
            ip = address_elem.attrib.get("addr", "") if address_elem is not None else ""

            # Hostname
            hostname_elem = host_elem.find("hostnames/hostname")
            hostname = hostname_elem.attrib.get("name", "") if hostname_elem is not None else ""

            ports: list[dict[str, Any]] = []
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.attrib.get("state") != "open":
                        continue

                    portid = int(port_elem.attrib.get("portid", 0))
                    protocol = port_elem.attrib.get("protocol", "tcp")

                    service_elem = port_elem.find("service")
                    service_name = ""
                    product = ""
                    version = ""
                    if service_elem is not None:
                        service_name = service_elem.attrib.get("name", "")
                        product = service_elem.attrib.get("product", "")
                        version = service_elem.attrib.get("version", "")

                    scripts: list[dict[str, str]] = []
                    for script_elem in port_elem.findall("script"):
                        scripts.append({
                            "id": script_elem.attrib.get("id", ""),
                            "output": script_elem.attrib.get("output", ""),
                        })

                    reason_elem = state_elem
                    reason = reason_elem.attrib.get("reason", "") if reason_elem is not None else ""

                    ports.append({
                        "port": portid,
                        "protocol": protocol,
                        "state": "open",
                        "reason": reason,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "scripts": scripts,
                    })

            hosts.append({
                "ip": ip,
                "hostname": hostname,
                "ports": ports,
            })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"hosts": hosts},
        )
