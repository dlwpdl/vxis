"""L8-02 SS7CellularAgent — SS7 SMS interception, SIM swap, IMSI catcher reconnaissance."""

from __future__ import annotations

import asyncio
import json
import shutil

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class SS7CellularAgent(BaseAgent):
    agent_id = "ss7_cellular"
    description = (
        "SS7/Diameter protocol reconnaissance, SMS interception risk assessment, "
        "SIM swap exposure, IMSI catcher detection capabilities"
    )

    # Known SS7 signalling ports
    _SS7_PORTS = [2905, 2906, 2907, 2944, 2945, 3868]
    # Diameter ports (4G/LTE)
    _DIAMETER_PORTS = [3868, 5868]

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Scan for SS7/Diameter signalling ports
        open_ports = await self._scan_ss7_ports(target)
        if open_ports:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"SS7/Diameter signalling ports open on {target}",
                    severity=Severity.CRITICAL,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        f"Open SS7/Diameter signalling ports detected: {open_ports}. "
                        "These ports may allow SS7 message injection if not properly "
                        "filtered by the signalling firewall."
                    ),
                    response=json.dumps({"open_ports": open_ports}, indent=2),
                    tags=["ss7", "diameter", "telecom", "signalling"],
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"SS7 message injection possible on {target}",
                    rationale=f"Open SS7 signalling ports: {open_ports}",
                    probability=0.4,
                    impact=0.95,
                    suggested_agent="ss7_cellular",
                    suggested_tool="sigploit",
                )
            )

        # Phase 2: Check for exposed telecom management interfaces
        mgmt_findings = await self._check_telecom_mgmt(target)
        findings.extend(mgmt_findings)

        # Phase 3: SMS-based 2FA risk assessment (passive analysis)
        sms_risk = self._assess_sms_2fa_risk(context)
        if sms_risk:
            findings.append(sms_risk)
            hypotheses.append(
                Hypothesis(
                    title="SIM swap attack for account takeover",
                    rationale="Target uses SMS-based 2FA which is vulnerable to SIM swap",
                    probability=0.6,
                    impact=0.9,
                    suggested_agent="identity_ad",
                )
            )

        # Phase 4: IMSI catcher detection assessment
        findings.append(
            Evidence(
                agent_id=self.agent_id,
                title="IMSI catcher exposure assessment",
                severity=Severity.INFO,
                evidence_type=EvidenceType.OTHER,
                description=(
                    "Assessment: Mobile devices connecting to the target network "
                    "may be vulnerable to IMSI catchers (Stingrays). Mitigation "
                    "requires enforcing LTE/5G-only mode and mutual authentication. "
                    "Active testing requires specialized RF equipment and licensing."
                ),
                tags=["ss7", "imsi-catcher", "assessment"],
            )
        )

        # Phase 5: Document SIM swap social engineering risk
        findings.append(
            Evidence(
                agent_id=self.agent_id,
                title="SIM swap social engineering risk",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.OTHER,
                description=(
                    "SIM swap attacks exploit carrier customer support processes. "
                    "Risk factors: SMS-based 2FA usage, publicly available PII of "
                    "key personnel, carrier porting policies. Recommend replacing "
                    "SMS 2FA with hardware tokens or authenticator apps."
                ),
                tags=["ss7", "sim-swap", "social-engineering"],
            )
        )

        hypotheses.append(
            Hypothesis(
                title=f"VoIP/telephony infrastructure exposed on {target}",
                rationale="SS7 reconnaissance suggests possible VoIP presence",
                probability=0.5,
                impact=0.7,
                suggested_agent="voip",
            )
        )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "ss7_ports_found": len(open_ports),
                "assessment_type": "passive_recon",
                "note": "Active SS7 exploitation requires SS7 network access",
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _scan_ss7_ports(self, target: str) -> list[int]:
        if not shutil.which("nmap"):
            return []
        ports_str = ",".join(str(p) for p in self._SS7_PORTS + self._DIAMETER_PORTS)
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-Pn",
            "-sS",
            "-p",
            ports_str,
            "--open",
            "-oG",
            "-",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        open_ports: list[int] = []
        for line in stdout.decode().splitlines():
            if "open" in line and "Ports:" in line:
                # Parse grepable nmap output
                parts = line.split("Ports:")[1] if "Ports:" in line else ""
                for port_entry in parts.split(","):
                    port_entry = port_entry.strip()
                    if "/open/" in port_entry:
                        try:
                            open_ports.append(int(port_entry.split("/")[0]))
                        except (ValueError, IndexError):
                            continue
        return open_ports

    async def _check_telecom_mgmt(self, target: str) -> list[Evidence]:
        """Check for exposed telecom management interfaces (HLR, MSC, SMSC)."""
        results: list[Evidence] = []
        if not shutil.which("nmap"):
            return results

        # Common telecom management ports
        mgmt_ports = "8080,8443,443,80,161,162,830,8008"
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-Pn",
            "-sV",
            "-p",
            mgmt_ports,
            "--open",
            "-oG",
            "-",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode()
        telecom_keywords = ["hlr", "msc", "smsc", "bsc", "ericsson", "nokia", "huawei"]
        if any(kw in output.lower() for kw in telecom_keywords):
            results.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Telecom management interface detected on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.NETWORK,
                    description="Exposed telecom management interface found during port scan",
                    response=output,
                    tags=["ss7", "telecom", "management-interface"],
                )
            )
        return results

    def _assess_sms_2fa_risk(self, context: AgentContext) -> Evidence | None:
        """Passive assessment of SMS-based 2FA risk."""
        target = context.mission.target
        return Evidence(
            agent_id=self.agent_id,
            title=f"SMS-based 2FA risk assessment for {target}",
            severity=Severity.MEDIUM,
            evidence_type=EvidenceType.OTHER,
            description=(
                "SMS-based two-factor authentication is vulnerable to: "
                "(1) SS7 interception via SendRoutingInfo + SendSMS, "
                "(2) SIM swap via social engineering of carrier support, "
                "(3) IMSI catcher for local interception. "
                "NIST SP 800-63B deprecates SMS as an out-of-band authenticator."
            ),
            tags=["ss7", "sms-2fa", "risk-assessment"],
        )
