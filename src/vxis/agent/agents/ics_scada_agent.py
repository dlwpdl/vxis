"""L7 ICSScadaAgent — Modbus, DNP3, OPC-UA, PLC, HMI analysis."""

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

_ICS_PORTS: dict[int, str] = {
    502: "Modbus",
    102: "S7comm",
    20000: "DNP3",
    44818: "EtherNet/IP",
    4840: "OPC-UA",
    47808: "BACnet",
    2222: "EtherNet/IP-Explicit",
    1911: "Niagara-Fox",
    789: "Crimson-v3",
    5006: "MELSEC-Q",
    9600: "OMRON-FINS",
    2404: "IEC-60870-5-104",
}


@register
class ICSScadaAgent(BaseAgent):
    agent_id = "ics_scada"
    description = "Modbus, DNP3, OPC-UA, PLC, HMI industrial control system analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: ICS port scan
        ics_services = await self._scan_ics_ports(target)
        for svc in ics_services:
            port = svc.get("port", 0)
            service = svc.get("service", _ICS_PORTS.get(port, "unknown"))
            product = svc.get("product", "")

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"ICS/SCADA service: {service} on {target}:{port}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"Industrial control protocol {service} ({product}) accessible on port {port}. "
                    f"ICS services exposed to network may allow unauthorized control."
                ),
                response=json.dumps(svc, indent=2),
                tags=["ics", "scada", service.lower(), f"port-{port}"],
            ))

            hypotheses.append(Hypothesis(
                title=f"Unauthorized PLC control via {service} on {target}",
                rationale=f"ICS protocol {service} exposed on port {port}",
                probability=0.7, impact=1.0,
                suggested_agent="ics_scada",
            ))

        # Phase 2: Modbus enumeration
        if any(s.get("port") == 502 for s in ics_services):
            modbus_results = await self._enumerate_modbus(target)
            for mr in modbus_results:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=mr["title"],
                    severity=mr["severity"],
                    evidence_type=EvidenceType.NETWORK,
                    description=mr["description"],
                    response=mr.get("detail", ""),
                    tags=["ics", "modbus"],
                ))

        # Phase 3: S7comm (Siemens) enumeration
        if any(s.get("port") == 102 for s in ics_services):
            s7_results = await self._enumerate_s7(target)
            for sr in s7_results:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=sr["title"],
                    severity=sr["severity"],
                    evidence_type=EvidenceType.NETWORK,
                    description=sr["description"],
                    response=sr.get("detail", ""),
                    tags=["ics", "s7comm", "siemens"],
                ))

        # Phase 4: HMI web interface checks
        hmi_results = await self._check_hmi_web(target)
        for hr in hmi_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=hr["title"],
                severity=hr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=hr["description"],
                response=hr.get("response", ""),
                tags=["ics", "hmi", "web-interface"],
            ))
            if hr["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"HMI takeover on {target}",
                    rationale=hr["description"],
                    probability=0.7, impact=0.95,
                    suggested_agent="web",
                ))

        # Phase 5: ICS-specific nmap scripts
        nmap_ics = await self._run_nmap_ics_scripts(target)
        for ni in nmap_ics:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=ni["title"],
                severity=ni["severity"],
                evidence_type=EvidenceType.NETWORK,
                description=ni["description"],
                response=ni.get("output", ""),
                tags=["ics", "nmap-script"],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"ics_services": len(ics_services)},
        )

    async def _scan_ics_ports(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        ports = ",".join(str(p) for p in _ICS_PORTS)
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
                        "service": svc.get("name", "") if svc is not None else _ICS_PORTS.get(port_id, "unknown"),
                        "product": svc.get("product", "") if svc is not None else "",
                    })
        except ET.ParseError:
            pass
        return results

    async def _enumerate_modbus(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-p", "502",
            "--script", "modbus-discover",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            if "modbus-discover" in output:
                results.append({
                    "title": f"Modbus device info on {target}",
                    "severity": Severity.HIGH,
                    "description": "Modbus device enumeration successful; device IDs and functions exposed",
                    "detail": output[:2048],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _enumerate_s7(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-p", "102",
            "--script", "s7-info",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            if "s7-info" in output:
                results.append({
                    "title": f"Siemens S7 PLC info on {target}",
                    "severity": Severity.HIGH,
                    "description": "Siemens S7 PLC information disclosed (module type, serial, firmware)",
                    "detail": output[:2048],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_hmi_web(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        hmi_indicators = [
            ("/", ["scada", "hmi", "plc", "automation", "siemens", "schneider", "honeywell", "rockwell"]),
            ("/web/", ["webvisu", "visualization"]),
            ("/portal/", ["portal"]),
            ("/awp/", ["siemens"]),
        ]
        for path, keywords in hmi_indicators:
            for port in (80, 443, 8080, 8443):
                scheme = "https" if port in (443, 8443) else "http"
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sS", "-k", f"{scheme}://{target}:{port}{path}",
                    "--max-time", "5",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                    body = stdout.decode(errors="replace").lower()
                    matched_kw = [kw for kw in keywords if kw in body]
                    if matched_kw:
                        results.append({
                            "title": f"HMI/SCADA web interface on {target}:{port}{path}",
                            "severity": Severity.HIGH,
                            "description": f"ICS web interface detected. Keywords: {matched_kw}",
                            "response": body[:1024],
                        })
                        break  # Found on this path, skip other ports
                except asyncio.TimeoutError:
                    continue
        return results

    async def _run_nmap_ics_scripts(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-sV",
            "-p", "502,102,44818,47808,20000,4840",
            "--script", "bacnet-info,enip-info",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            for script in ("bacnet-info", "enip-info"):
                if script in output:
                    results.append({
                        "title": f"ICS {script} on {target}",
                        "severity": Severity.MEDIUM,
                        "description": f"ICS protocol enumeration via {script}",
                        "output": output[output.find(script):][:1024],
                    })
        except asyncio.TimeoutError:
            pass
        return results
