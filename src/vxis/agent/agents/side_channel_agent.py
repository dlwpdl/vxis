"""CRT-P2 SideChannelAgent — timing attacks, cache side channels, Spectre/Meltdown."""

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

# Nuclei severity mapping
_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


@register
class SideChannelAgent(BaseAgent):
    agent_id = "side_channel"
    description = "Timing attacks, cache side channels, Spectre/Meltdown, EM/power analysis surface"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []
        stealth = context.mission.stealth

        # 1. Nuclei scan for known CPU/microarchitectural vulnerabilities
        nuclei_results = await self._run_nuclei_side_channel(target, stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            severity = _SEV_MAP.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            matched = nf.get("matched-at", target)
            template_id = nf.get("template-id", "")
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {matched}",
                severity=severity,
                evidence_type=EvidenceType.EXPLOIT,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["side-channel", "nuclei", template_id],
            ))
            if severity in (Severity.CRITICAL, Severity.HIGH):
                hypotheses.append(Hypothesis(
                    title=f"Memory disclosure via {name} on {target}",
                    rationale=f"Side-channel vulnerability {template_id} confirmed",
                    probability=0.8, impact=0.95,
                    suggested_agent="os_host",
                    suggested_tool="metasploit",
                ))

        # 2. HTTP timing analysis for authentication oracle
        timing_findings = await self._run_timing_analysis(target)
        findings.extend(timing_findings)
        for tf in timing_findings:
            if tf.severity in (Severity.HIGH, Severity.MEDIUM):
                hypotheses.append(Hypothesis(
                    title=f"Username enumeration via timing on {target}",
                    rationale=f"Timing difference detected: {tf.title}",
                    probability=0.7, impact=0.7,
                    suggested_agent="web",
                    suggested_tool="ffuf",
                ))

        # 3. Nmap script-based checks for CPU vuln disclosure
        nmap_findings = await self._run_nmap_vuln_scripts(target)
        findings.extend(nmap_findings)
        for nf in nmap_findings:
            if "spectre" in nf.title.lower() or "meltdown" in nf.title.lower():
                hypotheses.append(Hypothesis(
                    title=f"Cross-VM data leakage via Spectre/Meltdown on {target}",
                    rationale=nf.description,
                    probability=0.6, impact=0.9,
                    suggested_agent="os_host",
                ))

        # 4. Document non-remote side-channel attack surface
        findings.append(Evidence(
            agent_id=self.agent_id,
            title=f"Side-channel attack surface assessment for {target}",
            severity=Severity.INFO,
            evidence_type=EvidenceType.OTHER,
            description=(
                "Non-remote side-channel vectors documented: "
                "EM emanation analysis, power analysis (SPA/DPA), "
                "acoustic cryptanalysis, cold boot attacks. "
                "These require physical proximity or co-location."
            ),
            tags=["side-channel", "physical", "assessment"],
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "nuclei_matches": len(nuclei_results),
                "timing_issues": len(timing_findings),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _run_nuclei_side_channel(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "80"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "cve,spectre,meltdown,cpu,microarch,side-channel",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
            results = []
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results
        except asyncio.TimeoutError:
            return []

    async def _run_timing_analysis(self, target: str) -> list[Evidence]:
        """Use curl to measure response-time differences for auth endpoints."""
        if not shutil.which("curl"):
            return []
        findings: list[Evidence] = []
        auth_paths = ["/login", "/api/login", "/auth", "/api/auth", "/signin"]
        timings: dict[str, float] = {}

        for path in auth_paths:
            url = f"{target.rstrip('/')}{path}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{time_total}",
                "-X", "POST",
                "-d", "username=admin&password=wrong",
                "-m", "10",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                time_str = stdout.decode().strip()
                if time_str:
                    timings[path] = float(time_str)
            except (asyncio.TimeoutError, ValueError):
                continue

        # Check for valid-user timing with a different username
        for path in auth_paths:
            url = f"{target.rstrip('/')}{path}"
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{time_total}",
                "-X", "POST",
                "-d", "username=nonexistent_user_xyz&password=wrong",
                "-m", "10",
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                time_str = stdout.decode().strip()
                if time_str and path in timings:
                    diff = abs(float(time_str) - timings[path])
                    if diff > 0.1:  # >100ms difference suggests timing oracle
                        findings.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"Timing difference on auth endpoint {path}",
                            severity=Severity.MEDIUM,
                            evidence_type=EvidenceType.HTTP_EXCHANGE,
                            description=(
                                f"Response time difference of {diff:.3f}s between "
                                f"valid and invalid usernames at {url}. "
                                "May allow username enumeration via timing."
                            ),
                            request=f"POST {url}",
                            tags=["side-channel", "timing", "auth"],
                        ))
            except (asyncio.TimeoutError, ValueError):
                continue

        return findings

    async def _run_nmap_vuln_scripts(self, target: str) -> list[Evidence]:
        """Run nmap vuln scripts that detect CPU/microarch issues."""
        if not shutil.which("nmap"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "--script", "vuln", "--top-ports", "100",
            "-oX", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            output = stdout.decode()
            findings: list[Evidence] = []
            vuln_keywords = ["spectre", "meltdown", "mds", "zombieload", "taa", "l1tf"]
            for kw in vuln_keywords:
                if kw in output.lower():
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Potential {kw.upper()} vulnerability on {target}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.EXPLOIT,
                        description=f"Nmap vuln script detected {kw}-related indicator",
                        response=output[:4096],
                        tags=["side-channel", "nmap", kw],
                    ))
            return findings
        except asyncio.TimeoutError:
            return []
