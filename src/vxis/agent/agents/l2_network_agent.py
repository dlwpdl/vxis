"""CRT-P4 L2NetworkAgent — ARP Poisoning, VLAN Hopping, STP, 802.1X, MAC Flooding."""

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
class L2NetworkAgent(BaseAgent):
    agent_id = "l2_network"
    description = "ARP Poisoning, VLAN Hopping, STP attacks, 802.1X bypass, MAC flooding"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []
        stealth = context.mission.stealth

        # 1. Network discovery — identify L2 neighbours and topology
        nmap_discovery = await self._run_nmap_discovery(target)
        if nmap_discovery:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"L2 network topology discovery for {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=f"Discovered {len(nmap_discovery)} hosts in local segment",
                    response=json.dumps(nmap_discovery[:30], indent=2),
                    tags=["l2", "discovery", "topology"],
                )
            )

        # 2. ARP scan to identify L2 peers
        arp_results = await self._run_arp_scan(target)
        if arp_results:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"ARP scan results for {target} segment",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=f"ARP scan found {len(arp_results)} hosts on local segment",
                    response="\n".join(arp_results[:50]),
                    tags=["l2", "arp", "discovery"],
                )
            )
            # ARP responders without static entries are susceptible to poisoning
            if len(arp_results) > 1 and not stealth:
                hypotheses.append(
                    Hypothesis(
                        title=f"ARP poisoning / MITM on {target} segment",
                        rationale=f"{len(arp_results)} ARP-responsive hosts found; "
                        "dynamic ARP entries likely susceptible to spoofing",
                        probability=0.7,
                        impact=0.85,
                        suggested_agent="l2_network",
                        suggested_tool="arpspoof",
                    )
                )

        # 3. Nmap scripts for VLAN and STP analysis
        l2_script_results = await self._run_nmap_l2_scripts(target)
        findings.extend(l2_script_results)

        # 4. Check for 802.1X bypass indicators
        dot1x_findings = await self._check_802_1x(target)
        findings.extend(dot1x_findings)
        if dot1x_findings:
            hypotheses.append(
                Hypothesis(
                    title=f"802.1X bypass via MAB or EAP downgrade on {target}",
                    rationale="802.1X indicators found; MAC Authentication Bypass "
                    "or EAP negotiation downgrade may be possible",
                    probability=0.5,
                    impact=0.9,
                    suggested_agent="l2_network",
                )
            )

        # 5. CDP/LLDP neighbor detection for VLAN hopping
        cdp_findings = await self._run_cdp_detection(target)
        findings.extend(cdp_findings)
        if cdp_findings:
            hypotheses.append(
                Hypothesis(
                    title=f"VLAN hopping via DTP/trunk negotiation near {target}",
                    rationale="CDP/LLDP data reveals switch information; "
                    "DTP trunk negotiation may allow VLAN hopping",
                    probability=0.5,
                    impact=0.9,
                    suggested_agent="l2_network",
                    suggested_tool="yersinia",
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"STP root bridge attack near {target}",
                    rationale="Switch infrastructure detected via CDP/LLDP; "
                    "STP manipulation could redirect traffic",
                    probability=0.4,
                    impact=0.8,
                    suggested_agent="l2_network",
                    suggested_tool="yersinia",
                )
            )

        # 6. Generate cross-agent hypotheses
        if any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings):
            hypotheses.append(
                Hypothesis(
                    title=f"Credential capture via L2 MITM on {target}",
                    rationale="L2 attack surface confirmed; MITM enables credential interception",
                    probability=0.7,
                    impact=0.9,
                    suggested_agent="identity_ad",
                )
            )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "hosts_discovered": len(nmap_discovery),
                "arp_hosts": len(arp_results),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _run_nmap_discovery(self, target: str) -> list[dict[str, Any]]:
        """Host discovery on the target's /24 segment."""
        if not shutil.which("nmap"):
            return []
        # Derive /24 from target for local segment scanning
        subnet = self._derive_subnet(target)
        if not subnet:
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-sn",
            "-oX",
            "-",
            subnet,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return self._parse_nmap_hosts(stdout.decode())
        except asyncio.TimeoutError:
            return []

    async def _run_arp_scan(self, target: str) -> list[str]:
        """Use arp-scan or nmap ARP ping for L2 host discovery."""
        if shutil.which("arp-scan"):
            subnet = self._derive_subnet(target)
            if not subnet:
                return []
            proc = await asyncio.create_subprocess_exec(
                "arp-scan",
                "--localnet",
                "-q",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                return [line.strip() for line in stdout.decode().splitlines() if line.strip()]
            except asyncio.TimeoutError:
                return []

        # Fallback: nmap ARP ping
        if shutil.which("nmap"):
            subnet = self._derive_subnet(target)
            if not subnet:
                return []
            proc = await asyncio.create_subprocess_exec(
                "nmap",
                "-sn",
                "-PR",
                subnet,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                return [line for line in stdout.decode().splitlines() if "MAC Address" in line]
            except asyncio.TimeoutError:
                return []
        return []

    async def _run_nmap_l2_scripts(self, target: str) -> list[Evidence]:
        """Run nmap broadcast scripts for L2 protocol discovery."""
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "--script",
            "broadcast-dhcp-discover,broadcast-listener",
            "-e",
            "eth0",
            "--top-ports",
            "0",
            "-oX",
            "-",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            findings: list[Evidence] = []
            if "dhcp" in output.lower():
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"DHCP server detected on {target} segment",
                        severity=Severity.INFO,
                        evidence_type=EvidenceType.NETWORK,
                        description="DHCP service found; rogue DHCP or DHCP starvation possible",
                        response=output[:4096],
                        tags=["l2", "dhcp", "broadcast"],
                    )
                )
            return findings
        except asyncio.TimeoutError:
            return []

    async def _check_802_1x(self, target: str) -> list[Evidence]:
        """Check for 802.1X authentication indicators."""
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-sV",
            "-p",
            "1812,1813,3799",
            "-oX",
            "-",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            findings: list[Evidence] = []
            if "radius" in output.lower() or "1812" in output:
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"RADIUS/802.1X infrastructure detected near {target}",
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.NETWORK,
                        description=(
                            "RADIUS port open — suggests 802.1X NAC deployment. "
                            "Potential bypass via MAC Authentication Bypass (MAB), "
                            "EAP-MD5 downgrade, or VLAN pre-auth access."
                        ),
                        response=output[:4096],
                        tags=["l2", "802.1x", "radius", "nac"],
                    )
                )
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_cdp_detection(self, target: str) -> list[Evidence]:
        """Detect CDP/LLDP announcements."""
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "--script",
            "broadcast-cdp",
            "-e",
            "eth0",
            "--top-ports",
            "0",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode()
            findings: list[Evidence] = []
            if "cdp" in output.lower() or "lldp" in output.lower():
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title="CDP/LLDP advertisements detected",
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.NETWORK,
                        description=(
                            "Switch CDP/LLDP advertisements captured. Reveals "
                            "switch model, VLAN IDs, management IPs. Enables "
                            "targeted VLAN hopping and STP attacks."
                        ),
                        response=output[:4096],
                        tags=["l2", "cdp", "lldp", "vlan"],
                    )
                )
            return findings
        except asyncio.TimeoutError:
            return []

    @staticmethod
    def _derive_subnet(target: str) -> str:
        """Derive a /24 CIDR from target for local scanning."""
        import re

        # Handle IP addresses
        ip_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}", target)
        if ip_match:
            return f"{ip_match.group(1)}.0/24"
        return ""

    @staticmethod
    def _parse_nmap_hosts(xml_output: str) -> list[dict[str, Any]]:
        import xml.etree.ElementTree as ET

        results: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_output)
            for host_el in root.iter("host"):
                addr_el = host_el.find("address")
                status_el = host_el.find("status")
                if addr_el is not None and status_el is not None:
                    if status_el.get("state") == "up":
                        results.append(
                            {
                                "addr": addr_el.get("addr", ""),
                                "addrtype": addr_el.get("addrtype", ""),
                            }
                        )
        except ET.ParseError:
            pass
        return results
