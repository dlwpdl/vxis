"""L5-01 IdentityADAgent — AD, Kerberoasting, AS-REP, BloodHound, NTLM Relay."""

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
class IdentityADAgent(BaseAgent):
    agent_id = "identity_ad"
    description = "Active Directory, Kerberoasting, AS-REP roasting, BloodHound, NTLM Relay"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # 1. BloodHound collection (SharpHound / bloodhound-python)
        bh_findings = await self._run_bloodhound(target)
        for bf in bh_findings:
            findings.append(bf)
            if bf.severity in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title=f"Privilege escalation via AD path: {bf.title}",
                    rationale=f"BloodHound identified attack path",
                    probability=0.8, impact=0.95,
                    suggested_agent="os_host",
                ))

        # 2. Kerberoasting (impacket GetUserSPNs)
        kerb_findings = await self._run_kerberoast(target)
        findings.extend(kerb_findings)
        if kerb_findings:
            hypotheses.append(Hypothesis(
                title=f"Offline password cracking of kerberoasted accounts",
                rationale=f"{len(kerb_findings)} SPN accounts found",
                probability=0.7, impact=0.9,
                suggested_agent="lateral_move",
            ))

        # 3. AS-REP Roasting (impacket GetNPUsers)
        asrep_findings = await self._run_asrep_roast(target)
        findings.extend(asrep_findings)

        # 4. Certipy (AD CS abuse)
        cert_findings = await self._run_certipy(target)
        findings.extend(cert_findings)
        for cf in cert_findings:
            if cf.severity in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title="Domain admin via AD CS certificate abuse",
                    rationale=f"Certipy found: {cf.title}",
                    probability=0.75, impact=1.0,
                    suggested_agent="lateral_move",
                ))

        # 5. NetExec SMB enumeration
        smb_findings = await self._run_netexec(target)
        findings.extend(smb_findings)

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "bloodhound_paths": len(bh_findings),
                "kerberoastable": len(kerb_findings),
                "asrep_roastable": len(asrep_findings),
            },
        )

    async def _run_bloodhound(self, target: str) -> list[Evidence]:
        if not shutil.which("bloodhound-python"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "bloodhound-python", "-d", target, "-c", "All", "--zip",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
            output = stdout.decode() + stderr.decode()
            findings: list[Evidence] = []
            if "Done" in output or proc.returncode == 0:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"BloodHound collection completed for {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description="AD enumeration data collected for attack path analysis",
                    response=output[:4096],
                    tags=["ad", "bloodhound", "enumeration"],
                ))
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_kerberoast(self, target: str) -> list[Evidence]:
        if not shutil.which("impacket-GetUserSPNs"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "impacket-GetUserSPNs", f"{target}/", "-no-pass", "-dc-ip", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            findings: list[Evidence] = []
            for line in output.splitlines():
                if "$krb5tgs$" in line:
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Kerberoastable SPN account found",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.NETWORK,
                        description="Service account with crackable TGS ticket",
                        response=line[:512],
                        tags=["ad", "kerberoasting", "credential"],
                    ))
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_asrep_roast(self, target: str) -> list[Evidence]:
        if not shutil.which("impacket-GetNPUsers"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "impacket-GetNPUsers", f"{target}/", "-no-pass", "-dc-ip", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            findings: list[Evidence] = []
            for line in output.splitlines():
                if "$krb5asrep$" in line:
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title="AS-REP roastable account found",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.NETWORK,
                        description="Account with Kerberos pre-auth disabled",
                        response=line[:512],
                        tags=["ad", "asrep", "credential"],
                    ))
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_certipy(self, target: str) -> list[Evidence]:
        if not shutil.which("certipy"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "certipy", "find", "-u", "", "-dc-ip", target, "-vulnerable", "-json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            findings: list[Evidence] = []
            try:
                data = json.loads(stdout.decode())
                templates = data.get("Certificate Templates", [])
                for tmpl in templates:
                    vuln_to = tmpl.get("Vulnerabilities", [])
                    if vuln_to:
                        findings.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"Vulnerable AD CS template: {tmpl.get('Template Name', '')}",
                            severity=Severity.CRITICAL,
                            evidence_type=EvidenceType.MISCONFIGURATION,
                            description=f"Vulnerabilities: {', '.join(str(v) for v in vuln_to)}",
                            response=json.dumps(tmpl, indent=2)[:4096],
                            tags=["ad", "adcs", "certipy", "certificate"],
                        ))
            except json.JSONDecodeError:
                pass
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_netexec(self, target: str) -> list[Evidence]:
        if not shutil.which("netexec"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "netexec", "smb", target, "--shares",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            findings: list[Evidence] = []
            if "READ" in output or "WRITE" in output:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"SMB shares accessible on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description="Accessible SMB shares detected via anonymous/guest login",
                    response=output[:4096],
                    tags=["ad", "smb", "shares"],
                ))
            return findings
        except asyncio.TimeoutError:
            return []
