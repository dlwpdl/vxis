"""L8-03 NTPTimeAgent — time manipulation, Kerberos window abuse, TOTP extension attacks."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class NTPTimeAgent(BaseAgent):
    agent_id = "ntp_time"
    description = (
        "NTP configuration analysis, time skew detection, Kerberos ticket "
        "window abuse, TOTP window extension, and NTP amplification checks"
    )

    # Kerberos default max clock skew is 5 minutes (300 seconds)
    KERBEROS_MAX_SKEW = 300
    # TOTP default step is 30 seconds
    TOTP_STEP = 30

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: NTP service detection and configuration analysis
        ntp_info = await self._probe_ntp(target)
        if ntp_info.get("responsive"):
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"NTP service active on {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=f"NTP service detected and responding on {target}",
                response=json.dumps(ntp_info, indent=2),
                tags=["ntp", "time", "network"],
            ))

            # Check for monlist (amplification / info leak)
            if ntp_info.get("monlist_enabled"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"NTP monlist enabled on {target} (CVE-2013-5211)",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        "NTP monlist command is enabled, allowing DDoS amplification "
                        "attacks and leaking client information. The monlist command "
                        "returns the last 600 hosts that contacted the NTP server."
                    ),
                    response=json.dumps(ntp_info, indent=2),
                    cvss_score=7.5,
                    tags=["ntp", "amplification", "cve-2013-5211"],
                ))
                hypotheses.append(Hypothesis(
                    title=f"NTP amplification DDoS from {target}",
                    rationale="monlist enabled — amplification factor ~556x",
                    probability=0.9,
                    impact=0.7,
                    suggested_agent="dos_resilience",
                ))

        # Phase 2: Time skew measurement
        skew = await self._measure_time_skew(target)
        if skew is not None:
            abs_skew = abs(skew)
            if abs_skew > self.KERBEROS_MAX_SKEW:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Severe time skew: {abs_skew:.1f}s on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"Time skew of {skew:.1f}s exceeds Kerberos max tolerance "
                        f"({self.KERBEROS_MAX_SKEW}s). This may indicate NTP "
                        "misconfiguration or time manipulation susceptibility."
                    ),
                    tags=["ntp", "time-skew", "kerberos"],
                ))
                hypotheses.append(Hypothesis(
                    title=f"Kerberos authentication issues due to time skew on {target}",
                    rationale=f"Time skew {abs_skew:.1f}s exceeds Kerberos 5-min window",
                    probability=0.8,
                    impact=0.85,
                    suggested_agent="identity_ad",
                ))
            elif abs_skew > self.TOTP_STEP:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Time skew ({abs_skew:.1f}s) may affect TOTP validation",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"Time skew of {skew:.1f}s exceeds TOTP step ({self.TOTP_STEP}s). "
                        "Applications using TOTP may need extended validation windows, "
                        "which increases the brute-force window for OTP codes."
                    ),
                    tags=["ntp", "time-skew", "totp"],
                ))
            else:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Time skew within tolerance: {abs_skew:.1f}s on {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=f"Time skew {skew:.1f}s is within acceptable range",
                    tags=["ntp", "time-skew"],
                ))

        # Phase 3: NTP mode 6 (control) queries for info disclosure
        mode6_info = await self._ntp_mode6_query(target)
        if mode6_info:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"NTP mode 6 (control) queries allowed on {target}",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "NTP control mode (mode 6) queries are allowed, disclosing "
                    "server configuration, peer list, and version information."
                ),
                response=mode6_info,
                tags=["ntp", "mode6", "info-disclosure"],
            ))

        # Phase 4: Assess Kerberos time manipulation attack surface
        hypotheses.append(Hypothesis(
            title=f"NTP spoofing for Kerberos ticket manipulation on {target}",
            rationale=(
                "If NTP is unauthenticated (no NTS or symmetric key), an attacker "
                "on the network can shift the clock to manipulate Kerberos tickets"
            ),
            probability=0.4,
            impact=0.9,
            suggested_agent="identity_ad",
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "ntp_responsive": ntp_info.get("responsive", False),
                "time_skew_seconds": skew,
                "monlist_enabled": ntp_info.get("monlist_enabled", False),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _probe_ntp(self, target: str) -> dict[str, Any]:
        result: dict[str, Any] = {"responsive": False, "monlist_enabled": False}
        if not shutil.which("ntpq"):
            # Fallback: use nmap NSE
            return await self._nmap_ntp_probe(target)

        # Basic NTP query
        proc = await asyncio.create_subprocess_exec(
            "ntpq", "-p", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode()
        if output.strip():
            result["responsive"] = True
            result["peers"] = output.strip()

        # Check monlist
        proc = await asyncio.create_subprocess_exec(
            "ntpq", "-c", "monlist", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        stderr_text = stderr.decode()
        if stdout.decode().strip() and "timed out" not in stderr_text:
            result["monlist_enabled"] = True

        return result

    async def _nmap_ntp_probe(self, target: str) -> dict[str, Any]:
        result: dict[str, Any] = {"responsive": False, "monlist_enabled": False}
        if not shutil.which("nmap"):
            return result
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sU", "-p", "123", "--script",
            "ntp-info,ntp-monlist", "-Pn", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        output = stdout.decode()
        if "open" in output:
            result["responsive"] = True
        if "monlist" in output.lower():
            result["monlist_enabled"] = True
        result["raw"] = output
        return result

    async def _measure_time_skew(self, target: str) -> float | None:
        """Measure time skew using ntpdate dry-run or nmap."""
        if shutil.which("ntpdate"):
            proc = await asyncio.create_subprocess_exec(
                "ntpdate", "-q", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            output = stdout.decode()
            # Parse offset from ntpdate output
            match = re.search(r"offset\s+([-\d.]+)", output)
            if match:
                try:
                    return float(match.group(1))
                except ValueError:
                    pass

        # Fallback: nmap ntp-info script
        if shutil.which("nmap"):
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-sU", "-p", "123", "--script", "ntp-info", "-Pn", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            # ntp-info doesn't directly report offset but we note it was checked
        return None

    async def _ntp_mode6_query(self, target: str) -> str:
        """Attempt NTP mode 6 control query."""
        if not shutil.which("ntpq"):
            return ""
        proc = await asyncio.create_subprocess_exec(
            "ntpq", "-c", "readvar", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode().strip()
        return output if output and "timed out" not in output.lower() else ""
