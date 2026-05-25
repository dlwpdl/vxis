"""S-03 OSHostAgent — Windows/Linux local privilege escalation, DLL Hijack, SUID."""

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
class OSHostAgent(BaseAgent):
    agent_id = "os_host"
    description = "Windows/Linux privilege escalation, DLL hijack, SUID/SGID, kernel exploits"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # 1. LinPEAS (Linux Privilege Escalation Awesome Script)
        linpeas_results = await self._run_linpeas(target)
        findings.extend(linpeas_results)

        # 2. Nmap OS detection + service version
        nmap_findings = await self._run_nmap_os(target)
        findings.extend(nmap_findings)
        for nf in nmap_findings:
            if "outdated" in nf.description.lower() or "eol" in nf.description.lower():
                hypotheses.append(
                    Hypothesis(
                        title=f"Kernel exploit on {target}",
                        rationale=f"Outdated OS/service detected: {nf.title}",
                        probability=0.7,
                        impact=1.0,
                        suggested_agent="os_host",
                        suggested_tool="searchsploit",
                    )
                )

        # 3. Nuclei OS-level templates
        nuclei_results = await self._run_nuclei_host(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            matched = nf.get("matched-at", target)
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"{name} — {matched}",
                    severity=severity,
                    evidence_type=EvidenceType.EXPLOIT,
                    description=nf.get("info", {}).get("description", ""),
                    request=nf.get("request"),
                    response=nf.get("response"),
                    tags=["os", "nuclei", nf.get("template-id", "")],
                )
            )

        # Privilege escalation findings → lateral movement hypothesis
        privesc = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if privesc:
            hypotheses.append(
                Hypothesis(
                    title=f"Lateral movement after privilege escalation on {target}",
                    rationale=f"{len(privesc)} privilege escalation vectors found",
                    probability=0.8,
                    impact=0.95,
                    suggested_agent="lateral_move",
                )
            )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"privesc_vectors": len(privesc)},
        )

    async def _run_linpeas(self, target: str) -> list[Evidence]:
        """Run linpeas remotely or parse previous results."""
        # LinPEAS typically runs on the target host. In CRT mode we check if
        # the tool output was collected by a prior agent or is available locally.
        if not shutil.which("linpeas.sh") and not shutil.which("linpeas"):
            return []
        binary = "linpeas.sh" if shutil.which("linpeas.sh") else "linpeas"
        proc = await asyncio.create_subprocess_exec(
            binary,
            "-q",  # quiet mode
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            output = stdout.decode()
            findings: list[Evidence] = []

            # Parse key indicators from linpeas output
            indicators = {
                "SUID": ("SUID binary found", Severity.HIGH, "suid"),
                "writable": ("Writable sensitive file", Severity.HIGH, "writable"),
                "CVE-": ("Potential kernel exploit", Severity.CRITICAL, "kernel-cve"),
                "password": ("Password in file/env", Severity.HIGH, "credential"),
                "docker": ("Docker group / socket access", Severity.HIGH, "container-escape"),
            }
            for keyword, (title_prefix, severity, tag) in indicators.items():
                matching_lines = [
                    line for line in output.splitlines() if keyword.lower() in line.lower()
                ]
                if matching_lines:
                    findings.append(
                        Evidence(
                            agent_id=self.agent_id,
                            title=f"{title_prefix} on {target}",
                            severity=severity,
                            evidence_type=EvidenceType.EXPLOIT,
                            description=f"{len(matching_lines)} indicators found",
                            response="\n".join(matching_lines[:20]),
                            tags=["os", "linpeas", tag],
                        )
                    )
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_nmap_os(self, target: str) -> list[Evidence]:
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap",
            "-sV",
            "-O",
            "--top-ports",
            "100",
            "-oX",
            "-",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            output = stdout.decode()
            findings: list[Evidence] = []
            # Basic OS detection reporting
            if "<osmatch" in output:
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"OS fingerprint detected on {target}",
                        severity=Severity.INFO,
                        evidence_type=EvidenceType.NETWORK,
                        description="Nmap OS detection completed",
                        response=output[:4096],
                        tags=["os", "nmap", "fingerprint"],
                    )
                )
            return findings
        except asyncio.TimeoutError:
            return []

    async def _run_nuclei_host(
        self,
        target: str,
        stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei",
            "-u",
            target,
            "-tags",
            "default-login,panel,ssh,rdp,ftp,telnet",
            "-severity",
            "critical,high,medium",
            "-rate-limit",
            rate,
            "-jsonl",
            "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
        results = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
