"""CRT-P3 DMAAttackAgent — Thunderbolt/PCIe/FireWire DMA attack surface."""

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
class DMAAttackAgent(BaseAgent):
    agent_id = "dma_attack"
    description = "Thunderbolt/PCIe/FireWire DMA attack surface analysis"

    # Ports/services that indicate DMA-capable interfaces or management
    DMA_INDICATORS = {
        "623": ("ipmi", "IPMI/BMC — potential for DMA via BMC"),
        "5900": ("vnc", "VNC — may indicate physical console access"),
        "3389": ("rdp", "RDP — remote desktop, physical surface indicator"),
        "16992": ("amt", "Intel AMT — out-of-band management with DMA potential"),
        "16993": ("amt-tls", "Intel AMT TLS — out-of-band management"),
        "16994": ("amt-redir", "Intel AMT redirection"),
        "16995": ("amt-redir-tls", "Intel AMT redirection TLS"),
        "4743": ("thunderbolt-net", "Thunderbolt networking — DMA surface"),
    }

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # 1. Scan for DMA-related management interfaces
        nmap_data = await self._run_nmap_dma_ports(target)
        for svc in nmap_data:
            port = svc.get("port", "")
            if port in self.DMA_INDICATORS:
                indicator_name, desc = self.DMA_INDICATORS[port]
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"DMA-related interface: {indicator_name} on {target}:{port}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.NETWORK,
                    description=f"{desc}. Service: {svc.get('product', '')} {svc.get('version', '')}",
                    response=json.dumps(svc, indent=2),
                    tags=["dma", "physical", indicator_name],
                ))

        # 2. Intel AMT detection and vulnerability check
        amt_findings = await self._check_intel_amt(target)
        findings.extend(amt_findings)
        if amt_findings:
            hypotheses.append(Hypothesis(
                title=f"Intel AMT exploitation for full system control on {target}",
                rationale="Intel AMT interface detected — CVE-2017-5689 and similar "
                          "allow unauthenticated access with DMA capabilities",
                probability=0.6, impact=1.0,
                suggested_agent="os_host",
                suggested_tool="metasploit",
            ))

        # 3. IPMI/BMC analysis for DMA vectors
        ipmi_findings = await self._check_ipmi(target)
        findings.extend(ipmi_findings)
        if ipmi_findings:
            hypotheses.append(Hypothesis(
                title=f"BMC/IPMI exploitation for hardware-level access on {target}",
                rationale="IPMI service exposed — cipher zero, default creds, or "
                          "buffer overflows can grant DMA-equivalent access",
                probability=0.7, impact=1.0,
                suggested_agent="os_host",
                suggested_tool="ipmitool",
            ))

        # 4. Document physical DMA attack surface
        findings.append(Evidence(
            agent_id=self.agent_id,
            title=f"Physical DMA attack surface for {target}",
            severity=Severity.INFO,
            evidence_type=EvidenceType.OTHER,
            description=(
                "Physical DMA attack vectors documented: "
                "Thunderbolt/USB4 (PCILeech), FireWire/IEEE 1394, "
                "ExpressCard, M.2/NVMe slot access, PCI hot-plug. "
                "Requires physical access. Mitigated by IOMMU/VT-d "
                "and Thunderbolt security levels."
            ),
            tags=["dma", "physical", "thunderbolt", "firewire", "assessment"],
        ))

        # 5. Chain hypotheses for confirmed exposures
        high_findings = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if high_findings:
            hypotheses.append(Hypothesis(
                title=f"Firmware-level persistence via DMA on {target}",
                rationale=f"{len(high_findings)} DMA-related exposures found",
                probability=0.4, impact=1.0,
                suggested_agent="os_host",
            ))
            hypotheses.append(Hypothesis(
                title=f"Memory extraction via DMA on {target}",
                rationale="DMA interfaces allow direct memory read — credentials, "
                          "encryption keys extractable",
                probability=0.5, impact=0.95,
                suggested_agent="physical_usb",
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "dma_interfaces_found": len([f for f in findings if f.severity != Severity.INFO]),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _run_nmap_dma_ports(self, target: str) -> list[dict[str, Any]]:
        """Scan specific ports associated with DMA-capable management interfaces."""
        if not shutil.which("nmap"):
            return []
        ports = ",".join(self.DMA_INDICATORS.keys())
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-p", ports, "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            return self._parse_nmap_xml(stdout.decode())
        except asyncio.TimeoutError:
            return []

    async def _check_intel_amt(self, target: str) -> list[Evidence]:
        """Check for Intel AMT on common ports."""
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-p", "16992,16993,16994,16995",
            "--script", "http-vuln-cve2017-5689",
            "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            findings: list[Evidence] = []
            if "VULNERABLE" in output or "amt" in output.lower():
                severity = Severity.CRITICAL if "VULNERABLE" in output else Severity.MEDIUM
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Intel AMT detected on {target}",
                    severity=severity,
                    evidence_type=EvidenceType.EXPLOIT if severity == Severity.CRITICAL
                    else EvidenceType.NETWORK,
                    description="Intel Active Management Technology interface found. "
                                "AMT provides out-of-band management with DMA access.",
                    response=output[:4096],
                    tags=["dma", "amt", "intel", "oob-management"],
                ))
            return findings
        except asyncio.TimeoutError:
            return []

    async def _check_ipmi(self, target: str) -> list[Evidence]:
        """Check for IPMI/BMC exposure."""
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sU", "-p", "623",
            "--script", "ipmi-version,ipmi-cipher-zero",
            "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            findings: list[Evidence] = []
            if "ipmi" in output.lower():
                severity = Severity.CRITICAL if "cipher zero" in output.lower() else Severity.HIGH
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"IPMI/BMC service exposed on {target}:623",
                    severity=severity,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "IPMI/BMC service is accessible. BMC has direct hardware "
                        "access including DMA to host memory."
                        + (" Cipher zero (no auth) is enabled!" if severity == Severity.CRITICAL else "")
                    ),
                    response=output[:4096],
                    tags=["dma", "ipmi", "bmc"],
                ))
            return findings
        except asyncio.TimeoutError:
            return []

    @staticmethod
    def _parse_nmap_xml(xml_output: str) -> list[dict[str, Any]]:
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
