"""CRT-P7 NetworkAgent — Port scanning, protocol analysis, firewall analysis."""

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

# Service-to-agent mapping for hypothesis generation
_SERVICE_AGENT_MAP: dict[str, tuple[str, str, float]] = {
    "http":      ("web", "Web application testing", 0.9),
    "https":     ("web", "HTTPS application testing", 0.9),
    "ssl":       ("crypto_tls", "TLS/SSL analysis", 0.85),
    "ssh":       ("os_host", "SSH brute-force / config audit", 0.6),
    "ftp":       ("os_host", "FTP anonymous login / vulnerabilities", 0.7),
    "smtp":      ("os_host", "SMTP relay / user enumeration", 0.6),
    "snmp":      ("os_host", "SNMP community string guessing", 0.75),
    "mysql":     ("os_host", "MySQL remote auth / weak credentials", 0.7),
    "ms-sql":    ("os_host", "MSSQL xp_cmdshell / weak credentials", 0.75),
    "postgresql": ("os_host", "PostgreSQL auth / RCE", 0.7),
    "rdp":       ("os_host", "RDP BlueKeep / NLA bypass", 0.65),
    "smb":       ("identity_ad", "SMB relay / null session", 0.8),
    "ldap":      ("identity_ad", "LDAP anonymous bind / enumeration", 0.8),
    "kerberos":  ("identity_ad", "Kerberoasting / AS-REP roasting", 0.85),
    "domain":    ("network", "DNS zone transfer / cache poisoning", 0.6),
}


@register
class NetworkAgent(BaseAgent):
    agent_id = "network"
    description = "Port scanning, service enumeration, protocol analysis, firewall detection"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []
        depth = context.mission.depth.value
        stealth = context.mission.stealth

        # 1. TCP SYN scan (or connect scan in stealth mode)
        tcp_services = await self._run_tcp_scan(target, depth, stealth)
        if tcp_services:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"TCP port scan: {len(tcp_services)} open ports on {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=f"Open TCP ports: {', '.join(s['port'] for s in tcp_services[:30])}",
                response=json.dumps(tcp_services[:50], indent=2),
                tags=["network", "tcp", "portscan"],
            ))

            # Generate hypotheses per service
            for svc in tcp_services:
                svc_name = svc.get("service", "").lower()
                for key, (agent, desc, prob) in _SERVICE_AGENT_MAP.items():
                    if key in svc_name:
                        hypotheses.append(Hypothesis(
                            title=f"{desc} on {target}:{svc['port']}",
                            rationale=f"Service '{svc_name}' on port {svc['port']}",
                            probability=prob, impact=0.8,
                            suggested_agent=agent,
                            suggested_tool="nmap",
                        ))
                        break

        # 2. UDP scan (top ports)
        udp_services = await self._run_udp_scan(target, stealth)
        if udp_services:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"UDP port scan: {len(udp_services)} open ports on {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=f"Open UDP ports: {', '.join(s['port'] for s in udp_services[:20])}",
                response=json.dumps(udp_services[:30], indent=2),
                tags=["network", "udp", "portscan"],
            ))

            # SNMP community string check
            snmp_ports = [s for s in udp_services if s.get("service", "").lower() == "snmp"]
            if snmp_ports:
                hypotheses.append(Hypothesis(
                    title=f"SNMP community string brute-force on {target}",
                    rationale="SNMP UDP port open — default/weak community strings common",
                    probability=0.75, impact=0.8,
                    suggested_agent="os_host",
                    suggested_tool="onesixtyone",
                ))

        # 3. Firewall / IDS detection
        fw_findings = await self._run_firewall_detection(target)
        findings.extend(fw_findings)

        # 4. Nmap vulnerability scripts on interesting ports
        if depth in ("aggressive", "elite"):
            vuln_findings = await self._run_nmap_vuln_scan(target, tcp_services)
            findings.extend(vuln_findings)
            for vf in vuln_findings:
                if vf.severity in (Severity.CRITICAL, Severity.HIGH):
                    hypotheses.append(Hypothesis(
                        title=f"Exploit {vf.title}",
                        rationale=f"Vulnerability confirmed: {vf.description[:100]}",
                        probability=0.8, impact=0.95,
                        suggested_agent="os_host",
                        suggested_tool="metasploit",
                    ))

        # 5. DNS zone transfer attempt
        dns_findings = await self._run_dns_zone_transfer(target)
        findings.extend(dns_findings)
        if dns_findings:
            hypotheses.append(Hypothesis(
                title=f"Internal host enumeration via DNS zone transfer on {target}",
                rationale="DNS zone transfer successful; internal hostnames revealed",
                probability=0.9, impact=0.7,
                suggested_agent="recon",
            ))

        # 6. IPv6 hypothesis chain
        hypotheses.append(Hypothesis(
            title=f"IPv6 attack surface on {target}",
            rationale="IPv6 may be enabled but unmonitored/unfirewalled",
            probability=0.5, impact=0.7,
            suggested_agent="ipv6",
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "tcp_ports": len(tcp_services),
                "udp_ports": len(udp_services),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _run_tcp_scan(
        self, target: str, depth: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        if depth == "passive":
            return []

        # Build scan command based on depth
        cmd = ["nmap", "-sV"]
        if depth == "elite":
            cmd.extend(["-p-", "-T4"])  # All ports
        elif depth == "aggressive":
            cmd.extend(["--top-ports", "10000", "-T4"])
        else:
            cmd.extend(["--top-ports", "1000", "-T3"])

        if stealth:
            cmd.extend(["-sS", "-T2", "--max-retries", "1"])
        else:
            cmd.append("-sS")

        cmd.extend(["-oX", "-", target])

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3600)
            return self._parse_nmap_services(stdout.decode())
        except asyncio.TimeoutError:
            return []

    async def _run_udp_scan(self, target: str, stealth: bool) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        rate = "100" if not stealth else "30"
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sU", "-sV", "--top-ports", "200",
            "--max-rate", rate, "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            return self._parse_nmap_services(stdout.decode())
        except asyncio.TimeoutError:
            return []

    async def _run_firewall_detection(self, target: str) -> list[Evidence]:
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sA", "--top-ports", "100", "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            findings: list[Evidence] = []
            # If most ports are "filtered" vs "unfiltered", a firewall is present
            filtered_count = output.lower().count('state="filtered"')
            unfiltered_count = output.lower().count('state="unfiltered"')
            if filtered_count > 0:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Stateful firewall detected on {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        f"ACK scan: {filtered_count} filtered, "
                        f"{unfiltered_count} unfiltered ports. "
                        "Stateful packet inspection is active."
                    ),
                    response=output[:4096],
                    tags=["network", "firewall", "ack-scan"],
                ))
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_nmap_vuln_scan(
        self, target: str, services: list[dict[str, Any]],
    ) -> list[Evidence]:
        if not shutil.which("nmap") or not services:
            return []
        # Scan only open ports for efficiency
        ports = ",".join(s["port"] for s in services[:50])
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "--script", "vuln",
            "-p", ports, "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
            output = stdout.decode()
            findings: list[Evidence] = []
            # Parse script output for VULNERABLE indicators
            import xml.etree.ElementTree as ET
            try:
                root = ET.fromstring(output)
                for script_el in root.iter("script"):
                    script_output = script_el.get("output", "")
                    if "VULNERABLE" in script_output or "vulnerable" in script_output.lower():
                        script_id = script_el.get("id", "unknown")
                        findings.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"Vulnerability: {script_id} on {target}",
                            severity=Severity.HIGH,
                            evidence_type=EvidenceType.EXPLOIT,
                            description=script_output[:500],
                            response=script_output[:4096],
                            tags=["network", "nmap", "vuln", script_id],
                        ))
            except ET.ParseError:
                pass
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_dns_zone_transfer(self, target: str) -> list[Evidence]:
        """Attempt DNS zone transfer."""
        if not shutil.which("dig"):
            return []
        # Extract domain
        domain = target.lstrip("*.").split("/")[0].split(":")[0]
        proc = await asyncio.create_subprocess_exec(
            "dig", "axfr", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode()
            findings: list[Evidence] = []
            # Successful zone transfer contains many record lines
            records = [l for l in output.splitlines() if l.strip() and not l.startswith(";")]
            if len(records) > 5:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"DNS zone transfer successful for {domain}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=f"Zone transfer returned {len(records)} records",
                    response=output[:4096],
                    tags=["network", "dns", "zone-transfer"],
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
