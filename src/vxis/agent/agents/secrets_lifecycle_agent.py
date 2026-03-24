"""L7-27 SecretsLifecycleAgent — Git history, CI/CD vars, K8s Secrets, memory secrets."""

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
class SecretsLifecycleAgent(BaseAgent):
    agent_id = "secrets_lifecycle"
    description = "Git history secrets, CI/CD variables, K8s Secrets, memory-resident secrets"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # 1. Trufflehog — scan for secrets in repos
        tf_findings = await self._run_trufflehog(target)
        for tf in tf_findings:
            detector = tf.get("DetectorName", "unknown")
            verified = tf.get("Verified", False)
            raw = tf.get("Raw", "")[:100] + "..."
            sev = Severity.CRITICAL if verified else Severity.HIGH

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Secret found: {detector}" + (" (VERIFIED)" if verified else ""),
                severity=sev,
                evidence_type=EvidenceType.SECRET,
                description=f"{'Verified' if verified else 'Unverified'} {detector} secret in target repository",
                response=json.dumps({k: v for k, v in tf.items() if k != "Raw"}, indent=2)[:4096],
                tags=["secrets", "trufflehog", detector.lower()],
            ))
            if verified:
                hypotheses.append(Hypothesis(
                    title=f"Lateral access via verified {detector} credential",
                    rationale=f"Live credential found for {detector}",
                    probability=0.9, impact=0.95,
                    suggested_agent="lateral_move",
                ))

        # 2. Gitleaks — additional secret scanning
        gl_findings = await self._run_gitleaks(target)
        for gl in gl_findings:
            rule = gl.get("RuleID", "unknown")
            match = gl.get("Match", "")[:80]
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Gitleaks: {rule} match",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.SECRET,
                description=f"Secret pattern matched: {rule}",
                response=json.dumps(gl, indent=2)[:4096],
                tags=["secrets", "gitleaks", rule.lower()],
            ))

        # 3. Nuclei secret/exposure templates
        nuclei_results = await self._run_nuclei(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{nf.get('info', {}).get('name', '')} — {nf.get('matched-at', target)}",
                severity=sev_map.get(sev_str, Severity.INFO),
                evidence_type=EvidenceType.SECRET,
                description=nf.get("info", {}).get("description", ""),
                tags=["secrets", "nuclei"],
            ))

        return AgentResult(
            agent_id=self.agent_id, findings=findings, hypotheses=hypotheses,
            status="completed", metadata={"secrets_found": len(findings)},
        )

    async def _run_trufflehog(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("trufflehog"):
            return []
        domain = target.lstrip("*.")
        org = domain.split(".")[0]
        proc = await asyncio.create_subprocess_exec(
            "trufflehog", "github", "--org", org, "--json", "--no-verification",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3600)
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

    async def _run_gitleaks(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("gitleaks"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "gitleaks", "detect", "--source", ".", "--report-format", "json", "--report-path", "/dev/stdout",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            return json.loads(stdout.decode()) if stdout.decode().strip() else []
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return []

    async def _run_nuclei(self, target: str, stealth: bool) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-u", target, "-tags", "exposure,token,secret,api-key,env",
            "-severity", "critical,high,medium", "-rate-limit", rate, "-jsonl", "-silent",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
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
