"""L5-6 RemoteAccessAgent — RDP, VNC, SSH, Citrix, Bastion host analysis."""

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

_REMOTE_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC",
    5902: "VNC",
    1494: "Citrix-ICA",
    2598: "Citrix-CGP",
    8443: "Citrix-Gateway",
    4443: "Citrix-DTLS",
    443: "HTTPS-VPN",
}

_NUCLEI_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@register
class RemoteAccessAgent(BaseAgent):
    agent_id = "remote_access"
    description = "RDP, VNC, SSH, Citrix, and Bastion host remote access analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Port scan for remote access services
        open_services = await self._scan_remote_ports(target)
        for svc in open_services:
            port = svc.get("port", 0)
            service = svc.get("service", "unknown")
            product = svc.get("product", "")
            version = svc.get("version", "")

            sev = Severity.MEDIUM
            if port == 23:
                sev = Severity.HIGH  # Telnet is unencrypted
            elif port == 3389:
                sev = Severity.MEDIUM

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Remote access service: {service} on {target}:{port}",
                severity=sev,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"{service} ({product} {version}) is accessible on port {port}. "
                    f"Remote access services expand the attack surface."
                ),
                response=json.dumps(svc, indent=2),
                tags=["remote-access", service.lower(), f"port-{port}"],
            ))

            # Hypotheses based on service type
            if "ssh" in service.lower():
                hypotheses.append(Hypothesis(
                    title=f"SSH brute-force or key-based auth bypass on {target}:{port}",
                    rationale=f"SSH service detected on port {port}",
                    probability=0.5, impact=0.9,
                    suggested_agent="identity_ad",
                    suggested_tool="hydra",
                ))
                hypotheses.append(Hypothesis(
                    title=f"SSH version vulnerability on {target}:{port}",
                    rationale=f"SSH {product} {version} may have known CVEs",
                    probability=0.4, impact=0.85,
                    suggested_agent="os_host",
                ))
            elif "rdp" in service.lower() or port == 3389:
                hypotheses.append(Hypothesis(
                    title=f"BlueKeep/RDP vulnerability on {target}:{port}",
                    rationale="RDP service exposed; check for CVE-2019-0708 and NLA bypass",
                    probability=0.35, impact=0.95,
                    suggested_agent="os_host",
                    suggested_tool="nmap",
                ))
                hypotheses.append(Hypothesis(
                    title=f"RDP credential brute-force on {target}:{port}",
                    rationale="Exposed RDP may allow credential attacks",
                    probability=0.55, impact=0.9,
                    suggested_agent="identity_ad",
                ))
            elif "vnc" in service.lower() or port in (5900, 5901, 5902):
                hypotheses.append(Hypothesis(
                    title=f"VNC no-auth or weak-auth on {target}:{port}",
                    rationale="VNC often has no authentication or weak passwords",
                    probability=0.6, impact=0.9,
                    suggested_agent="identity_ad",
                ))
            elif port == 23:
                hypotheses.append(Hypothesis(
                    title=f"Telnet credential sniffing on {target}",
                    rationale="Telnet transmits credentials in cleartext",
                    probability=0.8, impact=0.85,
                    suggested_agent="identity_ad",
                ))

        # Phase 2: Nuclei remote-access specific templates
        nuclei_results = await self._run_nuclei(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            severity = _NUCLEI_SEV_MAP.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", nf.get("template-id", ""))
            matched = nf.get("matched-at", target)

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {matched}",
                severity=severity,
                evidence_type=EvidenceType.NETWORK,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["remote-access", "nuclei", nf.get("template-id", "")],
            ))

            if severity in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title=f"Lateral movement via {name} on {matched}",
                    rationale=f"Critical remote access vulnerability: {name}",
                    probability=0.8, impact=0.95,
                    suggested_agent="lateral_move",
                ))

        # Phase 3: Check for bastion / jump host patterns
        bastion_indicators = await self._check_bastion_patterns(target)
        if bastion_indicators:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Bastion/jump host indicators on {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=f"Detected bastion patterns: {', '.join(bastion_indicators)}",
                tags=["remote-access", "bastion"],
            ))
            hypotheses.append(Hypothesis(
                title=f"Bastion host pivot to internal network from {target}",
                rationale="Bastion host may provide access to internal services",
                probability=0.6, impact=0.95,
                suggested_agent="lateral_move",
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "services_found": len(open_services),
                "nuclei_matches": len(nuclei_results),
            },
        )

    async def _scan_remote_ports(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        ports = ",".join(str(p) for p in _REMOTE_PORTS)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-Pn", "--open", "-p", ports,
            "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            return self._parse_nmap_xml(stdout.decode())
        except asyncio.TimeoutError:
            return []

    def _parse_nmap_xml(self, xml_data: str) -> list[dict[str, Any]]:
        """Parse nmap XML output for open ports and services."""
        import xml.etree.ElementTree as ET
        results: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_data)
            for host in root.findall(".//host"):
                for port_elem in host.findall(".//port"):
                    state = port_elem.find("state")
                    if state is not None and state.get("state") == "open":
                        service_elem = port_elem.find("service")
                        port_id = int(port_elem.get("portid", 0))
                        results.append({
                            "port": port_id,
                            "protocol": port_elem.get("protocol", "tcp"),
                            "service": (
                                service_elem.get("name", "")
                                if service_elem is not None
                                else _REMOTE_PORTS.get(port_id, "unknown")
                            ),
                            "product": (
                                service_elem.get("product", "")
                                if service_elem is not None else ""
                            ),
                            "version": (
                                service_elem.get("version", "")
                                if service_elem is not None else ""
                            ),
                        })
        except ET.ParseError:
            pass
        return results

    async def _run_nuclei(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "rdp,vnc,ssh,citrix,remote-access,vpn",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
        results: list[dict[str, Any]] = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results

    async def _check_bastion_patterns(self, target: str) -> list[str]:
        """Check for bastion / jump host indicators via DNS and banner."""
        indicators: list[str] = []
        if not shutil.which("nmap"):
            return indicators
        # Check if hostname suggests bastion
        bastion_keywords = ["bastion", "jump", "gateway", "vpn", "relay"]
        for kw in bastion_keywords:
            if kw in target.lower():
                indicators.append(f"hostname-contains-{kw}")

        # Check for SSH with port forwarding allowed (banner grab)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-Pn", "-p", "22", "--script", "ssh2-enum-algos",
            "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode()
            if "ssh" in output.lower() and "open" in output.lower():
                indicators.append("ssh-accessible")
        except asyncio.TimeoutError:
            pass
        return indicators
