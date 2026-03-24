"""L7 LegacyProtocolAgent — SNMP, NFS, FTP, Telnet, TFTP, R-services analysis."""

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

_LEGACY_PORTS: dict[int, str] = {
    21: "FTP",
    23: "Telnet",
    69: "TFTP",
    111: "RPCbind",
    161: "SNMP",
    162: "SNMP-Trap",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    873: "rsync",
    2049: "NFS",
}

_SNMP_COMMUNITIES = ["public", "private", "community", "snmp", "default"]


@register
class LegacyProtocolAgent(BaseAgent):
    agent_id = "legacy_protocol"
    description = "SNMP, NFS, FTP, Telnet, TFTP, R-services legacy protocol analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Legacy port scan
        services = await self._scan_legacy_ports(target)
        for svc in services:
            port = svc.get("port", 0)
            service = svc.get("service", _LEGACY_PORTS.get(port, "unknown"))
            product = svc.get("product", "")

            sev = Severity.HIGH if port in (23, 512, 513, 514, 69) else Severity.MEDIUM
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Legacy service: {service} on {target}:{port}",
                severity=sev,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"Legacy protocol {service} ({product}) on port {port}. "
                    f"Legacy protocols often lack encryption and modern security controls."
                ),
                response=json.dumps(svc, indent=2),
                tags=["legacy", service.lower(), f"port-{port}"],
            ))

        # Phase 2: SNMP community string brute-force
        snmp_results = await self._check_snmp(target)
        for sr in snmp_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=sr["title"],
                severity=sr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=sr["description"],
                response=sr.get("detail", ""),
                tags=["legacy", "snmp"] + sr.get("tags", []),
            ))
            if sr.get("community"):
                hypotheses.append(Hypothesis(
                    title=f"Network reconnaissance via SNMP on {target}",
                    rationale=f"SNMP community '{sr['community']}' accepted",
                    probability=0.85, impact=0.8,
                    suggested_agent="recon",
                ))
                if sr.get("writable"):
                    hypotheses.append(Hypothesis(
                        title=f"Device reconfiguration via SNMP write on {target}",
                        rationale="SNMP write community string found",
                        probability=0.8, impact=0.95,
                        suggested_agent="os_host",
                    ))

        # Phase 3: NFS export enumeration
        nfs_results = await self._check_nfs(target)
        for nr in nfs_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=nr["title"],
                severity=nr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=nr["description"],
                response=nr.get("exports", ""),
                tags=["legacy", "nfs"],
            ))
            if nr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Data exfiltration via NFS on {target}",
                    rationale="NFS exports accessible without restriction",
                    probability=0.8, impact=0.9,
                    suggested_agent="data_exfiltration",
                ))

        # Phase 4: FTP anonymous access
        ftp_results = await self._check_ftp(target)
        for fr in ftp_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=fr["title"],
                severity=fr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=fr["description"],
                response=fr.get("detail", ""),
                tags=["legacy", "ftp"] + fr.get("tags", []),
            ))
            if fr.get("anonymous"):
                hypotheses.append(Hypothesis(
                    title=f"Sensitive file access via anonymous FTP on {target}",
                    rationale="Anonymous FTP access enabled",
                    probability=0.7, impact=0.75,
                    suggested_agent="secrets_lifecycle",
                ))

        # Phase 5: R-services check
        rservice_ports = [s for s in services if s.get("port") in (512, 513, 514)]
        if rservice_ports:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"R-services exposed on {target}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"R-services (rexec/rlogin/rsh) on ports {[s['port'] for s in rservice_ports]}. "
                    f"These protocols use IP-based trust with no encryption."
                ),
                tags=["legacy", "r-services"],
            ))
            hypotheses.append(Hypothesis(
                title=f"Remote command execution via R-services on {target}",
                rationale="R-services rely on IP trust, easily spoofable",
                probability=0.6, impact=0.9,
                suggested_agent="os_host",
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"legacy_services": len(services)},
        )

    async def _scan_legacy_ports(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        ports = ",".join(str(p) for p in _LEGACY_PORTS)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-Pn", "--open", "-p", ports, "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            return self._parse_nmap_xml(stdout.decode())
        except asyncio.TimeoutError:
            return []

    def _parse_nmap_xml(self, xml_data: str) -> list[dict[str, Any]]:
        import xml.etree.ElementTree as ET
        results: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_data)
            for port_elem in root.findall(".//port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    svc = port_elem.find("service")
                    port_id = int(port_elem.get("portid", 0))
                    results.append({
                        "port": port_id,
                        "service": svc.get("name", "") if svc is not None else "",
                        "product": svc.get("product", "") if svc is not None else "",
                    })
        except ET.ParseError:
            pass
        return results

    async def _check_snmp(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sU", "-Pn", "-p", "161",
            "--script", "snmp-brute,snmp-info,snmp-sysdescr",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            if "snmp-brute" in output and "Valid" in output:
                # Extract community strings
                for community in _SNMP_COMMUNITIES:
                    if community in output.lower():
                        results.append({
                            "title": f"SNMP community string '{community}' on {target}",
                            "severity": Severity.HIGH,
                            "description": f"SNMP community string '{community}' accepted",
                            "community": community,
                            "writable": community == "private",
                            "detail": output[:2048],
                            "tags": ["community-string"],
                        })
            if "snmp-info" in output or "snmp-sysdescr" in output:
                results.append({
                    "title": f"SNMP info disclosure on {target}",
                    "severity": Severity.MEDIUM,
                    "description": "SNMP system description and info accessible",
                    "detail": output[:2048],
                    "tags": ["info-disclosure"],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_nfs(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-p", "111,2049",
            "--script", "nfs-showmount,nfs-ls",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            if "nfs-showmount" in output:
                has_wildcard = "*" in output
                results.append({
                    "title": f"NFS exports on {target}",
                    "severity": Severity.CRITICAL if has_wildcard else Severity.HIGH,
                    "description": (
                        "NFS exports available" +
                        (" with wildcard (*) access — anyone can mount" if has_wildcard else "")
                    ),
                    "exports": output[output.find("nfs-showmount"):][:2048],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_ftp(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-Pn", "-p", "21",
            "--script", "ftp-anon,ftp-syst,ftp-bounce",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            if "ftp-anon" in output and "Anonymous" in output:
                results.append({
                    "title": f"Anonymous FTP on {target}",
                    "severity": Severity.HIGH,
                    "description": "FTP allows anonymous login",
                    "detail": output[:2048],
                    "anonymous": True,
                    "tags": ["anonymous"],
                })
            if "ftp-bounce" in output and "allowed" in output.lower():
                results.append({
                    "title": f"FTP bounce attack on {target}",
                    "severity": Severity.HIGH,
                    "description": "FTP server allows bounce attacks for port scanning",
                    "detail": output[:2048],
                    "tags": ["bounce"],
                })
        except asyncio.TimeoutError:
            pass
        return results
