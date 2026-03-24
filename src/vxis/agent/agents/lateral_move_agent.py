"""META-03 LateralMoveAgent — lateral movement, credential reuse, cloud IAM escalation."""

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
class LateralMoveAgent(BaseAgent):
    agent_id = "lateral_move"
    description = (
        "Lateral movement assessment: credential reuse, pass-the-hash, "
        "cloud IAM privilege escalation, network pivoting, WMI/WinRM/SSH"
    )

    # Common lateral movement ports
    _LATERAL_PORTS = {
        22: "SSH",
        135: "RPC/DCOM",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        5985: "WinRM-HTTP",
        5986: "WinRM-HTTPS",
    }

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Scan for lateral movement ports
        open_services = await self._scan_lateral_ports(target)
        if open_services:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Lateral movement services on {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"Services available for lateral movement: "
                    f"{', '.join(f'{svc}({port})' for port, svc in open_services.items())}"
                ),
                response=json.dumps(open_services, indent=2),
                tags=["lateral-movement", "network", "enumeration"],
            ))

        # Phase 2: SMB enumeration via netexec
        smb_findings = await self._run_netexec_smb(target)
        findings.extend(smb_findings)

        # Phase 3: Check for credential reuse indicators
        cred_findings = await self._check_credential_reuse(target, open_services)
        findings.extend(cred_findings)

        # Phase 4: WinRM / PSRemoting check
        if 5985 in open_services or 5986 in open_services:
            winrm_findings = await self._check_winrm(target)
            findings.extend(winrm_findings)
            hypotheses.append(Hypothesis(
                title=f"Remote code execution via WinRM on {target}",
                rationale="WinRM service is accessible",
                probability=0.6,
                impact=0.9,
                suggested_agent="os_host",
            ))

        # Phase 5: Cloud IAM enumeration
        iam_findings = await self._check_cloud_iam(target)
        findings.extend(iam_findings)

        # Phase 6: SSH key reuse / agent forwarding
        if 22 in open_services:
            ssh_findings = await self._check_ssh_config(target)
            findings.extend(ssh_findings)

        # Phase 7: Impacket-based checks
        impacket_findings = await self._run_impacket_checks(target)
        findings.extend(impacket_findings)

        # Generate chain hypotheses
        if 445 in open_services:
            hypotheses.append(Hypothesis(
                title=f"Pass-the-hash lateral movement via SMB on {target}",
                rationale="SMB port 445 open — PtH attacks possible with NTLM hashes",
                probability=0.6,
                impact=0.9,
                suggested_agent="lateral_move",
                suggested_tool="netexec",
            ))
        if 3389 in open_services:
            hypotheses.append(Hypothesis(
                title=f"RDP-based lateral movement on {target}",
                rationale="RDP port 3389 open",
                probability=0.5,
                impact=0.8,
                suggested_agent="lateral_move",
            ))
        hypotheses.append(Hypothesis(
            title=f"Privilege escalation after lateral movement to {target}",
            rationale="Lateral movement vectors identified",
            probability=0.5,
            impact=0.95,
            suggested_agent="os_host",
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "lateral_services": len(open_services),
                "smb_accessible": 445 in open_services,
                "winrm_accessible": 5985 in open_services or 5986 in open_services,
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _scan_lateral_ports(self, target: str) -> dict[int, str]:
        if not shutil.which("nmap"):
            return {}
        ports_str = ",".join(str(p) for p in self._LATERAL_PORTS)
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-sS", "-p", ports_str,
            "--open", "-oG", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        open_ports: dict[int, str] = {}
        for line in stdout.decode().splitlines():
            if "open" in line and "Ports:" in line:
                parts = line.split("Ports:")[1] if "Ports:" in line else ""
                for entry in parts.split(","):
                    entry = entry.strip()
                    if "/open/" in entry:
                        try:
                            port = int(entry.split("/")[0])
                            if port in self._LATERAL_PORTS:
                                open_ports[port] = self._LATERAL_PORTS[port]
                        except (ValueError, IndexError):
                            continue
        return open_ports

    async def _run_netexec_smb(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        nxc = shutil.which("netexec") or shutil.which("nxc") or shutil.which("crackmapexec")
        if not nxc:
            return results

        # SMB enumeration (null session)
        proc = await asyncio.create_subprocess_exec(
            nxc, "smb", target, "--shares", "-u", "", "-p", "",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
        output = stdout.decode()
        if "READ" in output or "WRITE" in output:
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"SMB shares accessible via null session on {target}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "SMB shares are accessible without authentication (null session). "
                    "This enables credential harvesting and data exfiltration."
                ),
                response=output[:2000],
                tags=["lateral-movement", "smb", "null-session"],
            ))

        # SMB signing check
        proc2 = await asyncio.create_subprocess_exec(
            nxc, "smb", target, "--gen-relay-list", "/dev/stdout",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=30)
        relay_output = stdout2.decode()
        if target in relay_output:
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"SMB signing not required on {target}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "SMB signing is not required, enabling NTLM relay attacks. "
                    "An attacker can relay authentication to this host."
                ),
                response=relay_output[:1000],
                cvss_score=7.5,
                tags=["lateral-movement", "smb", "ntlm-relay", "smb-signing"],
            ))
        return results

    async def _check_credential_reuse(
        self, target: str, services: dict[int, str],
    ) -> list[Evidence]:
        results: list[Evidence] = []
        if not services:
            return results
        # Document credential reuse attack surface
        results.append(Evidence(
            agent_id=self.agent_id,
            title=f"Credential reuse attack surface on {target}",
            severity=Severity.INFO,
            evidence_type=EvidenceType.OTHER,
            description=(
                f"Available services for credential testing: "
                f"{', '.join(f'{svc}' for svc in services.values())}. "
                "Credentials from other compromised systems should be tested "
                "against all accessible services."
            ),
            tags=["lateral-movement", "credential-reuse"],
        ))
        return results

    async def _check_winrm(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--max-time", "5",
            f"http://{target}:5985/wsman",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        code = stdout.decode().strip()
        if code and code != "000":
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"WinRM endpoint accessible on {target}",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"WinRM (HTTP {code}) is accessible on port 5985. "
                    "With valid credentials, this allows remote PowerShell execution."
                ),
                response=f"HTTP {code} on /wsman",
                tags=["lateral-movement", "winrm", "remote-execution"],
            ))
        return results

    async def _check_cloud_iam(self, target: str) -> list[Evidence]:
        """Check for cloud metadata / IAM role exposure."""
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # AWS IMDS check
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "--max-time", "3",
            "-H", "X-Forwarded-For: 169.254.169.254",
            f"http://{target}/latest/meta-data/iam/security-credentials/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        output = stdout.decode().strip()
        if output and "404" not in output and "<" not in output[:5]:
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"AWS IAM role accessible via SSRF on {target}",
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "AWS IMDS metadata endpoint accessible through the target. "
                    "IAM role credentials may be extractable for privilege escalation."
                ),
                response=output[:1000],
                tags=["lateral-movement", "cloud", "aws", "iam", "ssrf"],
            ))
        return results

    async def _check_ssh_config(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("ssh-audit"):
            return results
        proc = await asyncio.create_subprocess_exec(
            "ssh-audit", "-j", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        try:
            data = json.loads(stdout.decode())
            # Check for weak algorithms
            if data.get("kex") or data.get("key"):
                weak = []
                for section in ("kex", "key", "enc", "mac"):
                    for item in data.get(section, []):
                        if isinstance(item, dict) and item.get("warn"):
                            weak.append(item.get("algorithm", "unknown"))
                if weak:
                    results.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Weak SSH algorithms on {target}",
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=f"Weak SSH algorithms: {', '.join(weak[:10])}",
                        response=stdout.decode()[:2000],
                        tags=["lateral-movement", "ssh", "weak-crypto"],
                    ))
        except json.JSONDecodeError:
            pass
        return results

    async def _run_impacket_checks(self, target: str) -> list[Evidence]:
        """Run impacket-based enumeration if available."""
        results: list[Evidence] = []

        # Check for rpcdump
        rpcdump = shutil.which("rpcdump.py") or shutil.which("impacket-rpcdump")
        if rpcdump:
            proc = await asyncio.create_subprocess_exec(
                rpcdump, target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            output = stdout.decode()
            if "IRemoteWbemLevel" in output or "IWbemServices" in output:
                results.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"WMI accessible on {target} (DCOM)",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        "WMI/DCOM interfaces exposed. With valid credentials, "
                        "remote command execution is possible via WMI."
                    ),
                    response=output[:2000],
                    tags=["lateral-movement", "wmi", "dcom", "impacket"],
                ))
        return results
