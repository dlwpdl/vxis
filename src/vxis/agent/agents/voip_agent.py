"""L7 VoIPAgent — SIP, Caller ID spoofing, IVR bypass, Toll Fraud detection."""

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

_VOIP_PORTS = {
    5060: "SIP-UDP",
    5061: "SIP-TLS",
    5080: "SIP-ALT",
    4569: "IAX2",
    2000: "SCCP",
    1720: "H.323",
    10000: "RTP-range",
}


@register
class VoIPAgent(BaseAgent):
    agent_id = "voip"
    description = "SIP enumeration, Caller ID spoofing, IVR bypass, Toll Fraud detection"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Scan for VoIP services
        voip_services = await self._scan_voip_ports(target)
        for svc in voip_services:
            port = svc.get("port", 0)
            service = svc.get("service", "unknown")
            product = svc.get("product", "")

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"VoIP service: {service} on {target}:{port}",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"VoIP service {service} ({product}) found on port {port}. "
                    f"VoIP services may be vulnerable to enumeration, spoofing, and toll fraud."
                ),
                response=json.dumps(svc, indent=2),
                tags=["voip", service.lower(), f"port-{port}"],
            ))

            if "sip" in service.lower():
                hypotheses.append(Hypothesis(
                    title=f"SIP enumeration and extension brute-force on {target}",
                    rationale=f"SIP service on port {port}",
                    probability=0.65, impact=0.7,
                    suggested_agent="voip",
                ))
                hypotheses.append(Hypothesis(
                    title=f"Toll fraud via SIP on {target}",
                    rationale="SIP service exposed; unauthorized call routing possible",
                    probability=0.4, impact=0.85,
                    suggested_agent="voip",
                ))

        # Phase 2: SIP enumeration (if SIP found)
        sip_found = any("sip" in s.get("service", "").lower() for s in voip_services)
        if sip_found:
            sip_results = await self._sip_enumerate(target)
            for sr in sip_results:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=sr["title"],
                    severity=sr["severity"],
                    evidence_type=EvidenceType.NETWORK,
                    description=sr["description"],
                    response=sr.get("detail", ""),
                    tags=["voip", "sip"] + sr.get("tags", []),
                ))

        # Phase 3: SIP-specific nmap scripts
        sip_script_results = await self._run_sip_scripts(target)
        for ssr in sip_script_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=ssr["title"],
                severity=ssr["severity"],
                evidence_type=EvidenceType.NETWORK,
                description=ssr["description"],
                response=ssr.get("output", ""),
                tags=["voip", "sip", "nmap-script"],
            ))

        # Phase 4: Check for web-based VoIP management interfaces
        web_voip = await self._check_voip_web(target)
        for wv in web_voip:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=wv["title"],
                severity=wv["severity"],
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=wv["description"],
                tags=["voip", "web-interface"],
            ))
            if wv["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"VoIP admin panel exploitation on {target}",
                    rationale=wv["description"],
                    probability=0.6, impact=0.8,
                    suggested_agent="web",
                ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"voip_services": len(voip_services)},
        )

    async def _scan_voip_ports(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        ports = ",".join(str(p) for p in _VOIP_PORTS)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-sU", "-Pn", "--open", "-p", ports,
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
        import xml.etree.ElementTree as ET
        results: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(xml_data)
            for port_elem in root.findall(".//port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    service_elem = port_elem.find("service")
                    port_id = int(port_elem.get("portid", 0))
                    results.append({
                        "port": port_id,
                        "protocol": port_elem.get("protocol", ""),
                        "service": (
                            service_elem.get("name", "")
                            if service_elem is not None
                            else _VOIP_PORTS.get(port_id, "unknown")
                        ),
                        "product": service_elem.get("product", "") if service_elem is not None else "",
                    })
        except ET.ParseError:
            pass
        return results

    async def _sip_enumerate(self, target: str) -> list[dict[str, Any]]:
        """Use nmap SIP scripts for enumeration."""
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sU", "-Pn", "-p", "5060",
            "--script", "sip-methods,sip-enum-users",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            if "sip-methods" in output:
                methods_section = output[output.find("sip-methods"):]
                results.append({
                    "title": f"SIP methods enumerated on {target}",
                    "severity": Severity.LOW,
                    "description": "SIP methods discovered via OPTIONS request",
                    "detail": methods_section[:1024],
                    "tags": ["methods"],
                })
            if "sip-enum-users" in output:
                results.append({
                    "title": f"SIP user enumeration possible on {target}",
                    "severity": Severity.MEDIUM,
                    "description": "SIP user/extension enumeration via REGISTER/OPTIONS",
                    "detail": output[output.find("sip-enum-users"):][:1024],
                    "tags": ["enumeration"],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _run_sip_scripts(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-Pn", "-p", "5060,5061",
            "--script", "sip-brute,sip-call-spoof",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = stdout.decode()
            if "sip-brute" in output and "Valid" in output:
                results.append({
                    "title": f"SIP brute-force: valid credentials found on {target}",
                    "severity": Severity.CRITICAL,
                    "description": "SIP authentication brute-force succeeded",
                    "output": output[:2048],
                })
            if "sip-call-spoof" in output:
                results.append({
                    "title": f"SIP Caller ID spoofing possible on {target}",
                    "severity": Severity.HIGH,
                    "description": "SIP server accepts spoofed Caller-ID headers",
                    "output": output[:2048],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_voip_web(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        voip_paths = [
            ("/admin/", "PBX admin panel"),
            ("/freepbx/", "FreePBX interface"),
            ("/3cx/", "3CX management"),
            (":8088/", "Asterisk HTTP"),
            (":8089/", "Asterisk WebSocket"),
        ]
        for path, desc in voip_paths:
            url = f"http://{target}{path}" if not path.startswith(":") else f"http://{target}{path}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                url, "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status in ("200", "301", "302"):
                    results.append({
                        "title": f"VoIP web interface: {desc} at {url}",
                        "severity": Severity.MEDIUM,
                        "description": f"{desc} accessible at {url} (HTTP {status})",
                    })
            except asyncio.TimeoutError:
                continue
        return results
