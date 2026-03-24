"""CRT-P1 PhysicalUSBAgent — BadUSB, Rubber Ducky, physical access attack surface."""

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
class PhysicalUSBAgent(BaseAgent):
    agent_id = "physical_usb"
    description = "BadUSB, Rubber Ducky, physical access attack surface analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Physical USB attacks require physical access. This agent analyses
        # the attack surface from network scan data and generates hypotheses
        # about what physical vectors could be exploited.

        # 1. Enumerate exposed services that indicate physical/local interfaces
        nmap_data = await self._run_nmap_service_scan(target)
        usb_indicators = self._analyse_usb_surface(nmap_data, target)
        findings.extend(usb_indicators)

        # 2. Check for USB-over-IP / remote USB services (tcp/3240 usbip)
        usbip_findings = self._check_usbip_exposure(nmap_data, target)
        findings.extend(usbip_findings)
        if usbip_findings:
            hypotheses.append(Hypothesis(
                title=f"Remote USB-over-IP exploitation on {target}",
                rationale="USB/IP service exposed; BadUSB payloads deliverable remotely",
                probability=0.8, impact=0.95,
                suggested_agent="os_host",
                suggested_tool="nmap",
            ))

        # 3. Detect HID-class indicators from service banners
        hid_findings = self._check_hid_exposure(nmap_data, target)
        findings.extend(hid_findings)

        # 4. Generate physical attack hypotheses based on host profile
        if nmap_data:
            # Host is reachable — document physical attack vectors
            hypotheses.append(Hypothesis(
                title=f"BadUSB HID injection attack on {target}",
                rationale="Host is live; if physical access is obtained, Rubber Ducky / "
                          "BadUSB payloads can execute arbitrary commands in seconds",
                probability=0.3, impact=1.0,
                suggested_agent="os_host",
                suggested_tool="duckyscript",
            ))
            hypotheses.append(Hypothesis(
                title=f"USB boot media attack on {target}",
                rationale="If BIOS/UEFI boot order allows USB, an attacker can "
                          "boot a live OS and extract disk contents",
                probability=0.25, impact=1.0,
                suggested_agent="os_host",
            ))

            # If any management ports are open, physical access risk increases
            mgmt_ports = {"623", "5900", "5985", "5986", "3389", "22"}
            open_ports = {str(p.get("port", "")) for p in nmap_data}
            exposed_mgmt = mgmt_ports & open_ports
            if exposed_mgmt:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Management interfaces exposed on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        f"Ports {', '.join(sorted(exposed_mgmt))} are open. "
                        "Physical attacker with network access could pivot via "
                        "these management services."
                    ),
                    tags=["physical", "management", "usb-pivot"],
                ))
                hypotheses.append(Hypothesis(
                    title=f"Physical-to-remote pivot via management ports on {target}",
                    rationale=f"Management ports {exposed_mgmt} open alongside physical access",
                    probability=0.5, impact=0.9,
                    suggested_agent="network",
                ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "services_scanned": len(nmap_data),
                "physical_vectors": len(findings),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _run_nmap_service_scan(self, target: str) -> list[dict[str, Any]]:
        """Quick service scan to identify exposed interfaces."""
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "--top-ports", "1000", "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            return self._parse_nmap_xml(stdout.decode())
        except asyncio.TimeoutError:
            return []

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> list[dict[str, Any]]:
        """Minimal XML parser extracting port/service pairs."""
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

    def _analyse_usb_surface(
        self, nmap_data: list[dict[str, Any]], target: str,
    ) -> list[Evidence]:
        """Identify services suggesting USB/serial/physical exposure."""
        findings: list[Evidence] = []
        serial_services = {"serial", "modem", "console", "ipmi", "ilo", "idrac", "bmc"}
        for svc in nmap_data:
            svc_name = svc.get("service", "").lower()
            product = svc.get("product", "").lower()
            if any(s in svc_name or s in product for s in serial_services):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Serial/physical management interface on {target}:{svc.get('port')}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        f"Service '{svc.get('service')}' ({svc.get('product')}) "
                        f"on port {svc.get('port')} suggests physical/serial management. "
                        "May be exploitable via USB-to-serial or physical access."
                    ),
                    response=json.dumps(svc, indent=2),
                    tags=["physical", "serial", "usb", svc_name],
                ))
        return findings

    @staticmethod
    def _check_usbip_exposure(
        nmap_data: list[dict[str, Any]], target: str,
    ) -> list[Evidence]:
        """Check for USB/IP daemon exposure (port 3240)."""
        findings: list[Evidence] = []
        for svc in nmap_data:
            if svc.get("port") == "3240" or "usbip" in svc.get("service", "").lower():
                findings.append(Evidence(
                    agent_id="physical_usb",
                    title=f"USB/IP service exposed on {target}:{svc.get('port')}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "USB/IP daemon is remotely accessible. An attacker can attach "
                        "virtual USB devices including HID keyboards for keystroke injection."
                    ),
                    response=json.dumps(svc, indent=2),
                    tags=["physical", "usbip", "hid", "badusb"],
                ))
        return findings

    @staticmethod
    def _check_hid_exposure(
        nmap_data: list[dict[str, Any]], target: str,
    ) -> list[Evidence]:
        """Check for HID/keyboard emulation services in banners."""
        findings: list[Evidence] = []
        hid_keywords = {"hid", "keyboard", "teensy", "arduino", "digispark"}
        for svc in nmap_data:
            combined = f"{svc.get('product', '')} {svc.get('version', '')}".lower()
            for kw in hid_keywords:
                if kw in combined:
                    findings.append(Evidence(
                        agent_id="physical_usb",
                        title=f"HID device indicator on {target}:{svc.get('port')}",
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.NETWORK,
                        description=f"Banner contains HID keyword '{kw}': {combined}",
                        response=json.dumps(svc, indent=2),
                        tags=["physical", "hid", kw],
                    ))
                    break
        return findings
