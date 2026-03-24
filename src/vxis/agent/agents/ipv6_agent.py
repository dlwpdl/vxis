"""CRT-P9 IPv6Agent — NDP Spoofing, SLAAC attacks, RA Flood, 6in4 firewall bypass."""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class IPv6Agent(BaseAgent):
    agent_id = "ipv6"
    description = "NDP Spoofing, SLAAC attacks, RA Flood, 6in4 tunnel firewall bypass"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []
        stealth = context.mission.stealth

        # 1. IPv6 host discovery via nmap
        ipv6_hosts = await self._run_ipv6_scan(target)
        if ipv6_hosts:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"IPv6 enabled on {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=f"IPv6 addresses discovered: {len(ipv6_hosts)}",
                response=json.dumps(ipv6_hosts[:20], indent=2),
                tags=["ipv6", "discovery"],
            ))

            # IPv6 with services = expanded attack surface
            hypotheses.append(Hypothesis(
                title=f"IPv6-only services bypassing IPv4 firewall on {target}",
                rationale="IPv6 is active; firewall rules may not cover IPv6 traffic",
                probability=0.6, impact=0.8,
                suggested_agent="network",
            ))

        # 2. IPv6 service scan on discovered addresses
        for host in ipv6_hosts[:5]:
            ipv6_addr = host.get("ipv6", "")
            if ipv6_addr:
                ipv6_services = await self._run_ipv6_service_scan(ipv6_addr)
                if ipv6_services:
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"IPv6 services on {ipv6_addr}",
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.NETWORK,
                        description=f"{len(ipv6_services)} services on IPv6 address",
                        response=json.dumps(ipv6_services[:20], indent=2),
                        tags=["ipv6", "services"],
                    ))

                    # Check for services only on IPv6 (potential firewall bypass)
                    hypotheses.append(Hypothesis(
                        title=f"IPv6-exclusive service exploitation on {ipv6_addr}",
                        rationale="Services found on IPv6 may bypass IPv4 ACLs/firewall",
                        probability=0.5, impact=0.85,
                        suggested_agent="web",
                    ))

        # 3. Check for 6in4/6to4/Teredo tunnel endpoints
        tunnel_findings = await self._check_tunnel_endpoints(target)
        findings.extend(tunnel_findings)
        if tunnel_findings:
            hypotheses.append(Hypothesis(
                title=f"IPv6 tunnel firewall bypass on {target}",
                rationale="IPv6 tunnel endpoint detected; tunneled traffic may "
                          "bypass IPv4 firewall inspection",
                probability=0.6, impact=0.85,
                suggested_agent="network",
            ))

        # 4. NDP/RA analysis via nmap scripts
        ndp_findings = await self._run_ndp_analysis(target)
        findings.extend(ndp_findings)
        if ndp_findings:
            hypotheses.append(Hypothesis(
                title=f"NDP spoofing / RA injection on {target} segment",
                rationale="IPv6 NDP traffic detected; NDP lacks authentication "
                          "and is susceptible to spoofing",
                probability=0.7, impact=0.85,
                suggested_agent="l2_network",
            ))
            hypotheses.append(Hypothesis(
                title=f"SLAAC address manipulation near {target}",
                rationale="RA messages detected; rogue RA can force SLAAC "
                          "reconfiguration for MITM",
                probability=0.6, impact=0.8,
                suggested_agent="l2_network",
            ))

        # 5. DNS AAAA record check
        aaaa_findings = await self._check_aaaa_records(target)
        findings.extend(aaaa_findings)

        # 6. IPv6 extension header abuse hypothesis
        if ipv6_hosts:
            hypotheses.append(Hypothesis(
                title=f"IPv6 extension header firewall evasion on {target}",
                rationale="IPv6 active; fragmentation and extension headers "
                          "can bypass stateless firewalls and IDS",
                probability=0.5, impact=0.7,
                suggested_agent="network",
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "ipv6_hosts": len(ipv6_hosts),
                "tunnels_found": len(tunnel_findings),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _run_ipv6_scan(self, target: str) -> list[dict[str, Any]]:
        """Discover IPv6 addresses for the target."""
        if not shutil.which("nmap"):
            return []
        domain = target.lstrip("*.").split("/")[0].split(":")[0]
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-6", "-sn", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            hosts: list[dict[str, Any]] = []
            current_host: dict[str, Any] = {}
            for line in output.splitlines():
                if "Nmap scan report for" in line:
                    if current_host:
                        hosts.append(current_host)
                    parts = line.split()
                    addr = parts[-1].strip("()")
                    current_host = {"ipv6": addr}
                elif "Host is up" in line:
                    current_host["status"] = "up"
            if current_host:
                hosts.append(current_host)
            return hosts
        except asyncio.TimeoutError:
            return []

    async def _run_ipv6_service_scan(self, ipv6_addr: str) -> list[dict[str, Any]]:
        """Service scan on a specific IPv6 address."""
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-6", "-sV", "--top-ports", "1000",
            "-oX", "-", ipv6_addr,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            return self._parse_nmap_services(stdout.decode())
        except asyncio.TimeoutError:
            return []

    async def _check_tunnel_endpoints(self, target: str) -> list[Evidence]:
        """Detect 6in4, 6to4, and Teredo tunnel indicators."""
        if not shutil.which("nmap"):
            return []
        domain = target.lstrip("*.").split("/")[0].split(":")[0]
        # Protocol 41 = 6in4 encapsulation
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sO", "-p", "41", "-oX", "-", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            findings: list[Evidence] = []
            if 'state="open"' in output or "ipv6" in output.lower():
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"IPv6 tunnel endpoint (protocol 41) on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        "IP protocol 41 (6in4) is open. This indicates an IPv6 "
                        "tunnel endpoint that may bypass IPv4 firewall rules."
                    ),
                    response=output[:4096],
                    tags=["ipv6", "tunnel", "6in4", "firewall-bypass"],
                ))

            # Check for Teredo (UDP 3544)
            proc2 = await asyncio.create_subprocess_exec(
                "nmap", "-sU", "-p", "3544", "-oX", "-", domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=30)
            output2 = stdout2.decode()
            if 'state="open"' in output2:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Teredo tunnel endpoint (UDP/3544) on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description="Teredo tunnel detected; NAT-traversing IPv6 tunnel "
                                "that may bypass firewall policies",
                    response=output2[:4096],
                    tags=["ipv6", "tunnel", "teredo"],
                ))
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_ndp_analysis(self, target: str) -> list[Evidence]:
        """Analyse NDP / Router Advertisement traffic."""
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-6", "--script",
            "ipv6-ra-flood,ipv6-node-info",
            "--script-args", "newtargets",
            "-e", "eth0", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode()
            findings: list[Evidence] = []
            if "router" in output.lower() or "ra" in output.lower():
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"IPv6 Router Advertisement detected near {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        "Router Advertisements found on the segment. "
                        "RA spoofing can redirect traffic, inject DNS servers, "
                        "and force SLAAC reconfiguration."
                    ),
                    response=output[:4096],
                    tags=["ipv6", "ndp", "ra", "slaac"],
                ))
            return findings
        except asyncio.TimeoutError:
            return []

    async def _check_aaaa_records(self, target: str) -> list[Evidence]:
        """Check DNS AAAA records for the target."""
        if not shutil.which("dig"):
            return []
        domain = target.lstrip("*.").split("/")[0].split(":")[0]
        proc = await asyncio.create_subprocess_exec(
            "dig", "AAAA", "+short", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode().strip()
            findings: list[Evidence] = []
            if output and ":" in output:
                aaaa_records = [l.strip() for l in output.splitlines() if l.strip()]
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"DNS AAAA records for {domain}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=f"IPv6 addresses in DNS: {', '.join(aaaa_records)}",
                    response=output,
                    tags=["ipv6", "dns", "aaaa"],
                ))
            return findings
        except asyncio.TimeoutError:
            return []

    @staticmethod
    def _parse_nmap_services(xml_output: str) -> list[dict[str, Any]]:
        import xml.etree.ElementTree as ET
        results: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_output)
            for port_el in root.iter("port"):
                state_el = port_el.find("state")
                service_el = port_el.find("service")
                if state_el is not None and state_el.get("state") == "open":
                    results.append({
                        "port": port_el.get("portid", ""),
                        "protocol": port_el.get("protocol", "tcp"),
                        "service": service_el.get("name", "") if service_el is not None else "",
                        "product": service_el.get("product", "") if service_el is not None else "",
                        "version": service_el.get("version", "") if service_el is not None else "",
                    })
        except ET.ParseError:
            pass
        return results
