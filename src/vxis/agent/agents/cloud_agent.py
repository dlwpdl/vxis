"""L7-14 CloudAgent — AWS/GCP/Azure IAM, S3, Lambda, cloud misconfiguration."""

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
class CloudAgent(BaseAgent):
    agent_id = "cloud"
    description = "AWS/GCP/Azure IAM, S3 bucket, Lambda, cloud misconfiguration scanning"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # 1. S3 bucket enumeration
        s3_results = await self._run_s3scanner(target)
        for bucket in s3_results:
            name = bucket.get("name", "")
            perm = bucket.get("permission", "")
            if perm in ("READ", "READ_ACP", "WRITE", "FULL_CONTROL"):
                sev = Severity.CRITICAL if perm in ("WRITE", "FULL_CONTROL") else Severity.HIGH
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"S3 bucket '{name}' is publicly {perm}",
                    severity=sev,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=f"AWS S3 bucket {name} allows {perm} access",
                    response=json.dumps(bucket, indent=2),
                    tags=["cloud", "aws", "s3", perm.lower()],
                ))
                hypotheses.append(Hypothesis(
                    title=f"Secrets in S3 bucket {name}",
                    rationale=f"Publicly accessible S3 bucket with {perm}",
                    probability=0.85, impact=0.95,
                    suggested_agent="secrets_lifecycle",
                ))

        # 2. Prowler (AWS security audit)
        prowler_findings = await self._run_prowler()
        for pf in prowler_findings:
            sev_str = pf.get("Severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = sev_map.get(sev_str, Severity.INFO)
            check_id = pf.get("CheckID", "")
            title = pf.get("CheckTitle", check_id)
            status = pf.get("Status", "")

            if status == "FAIL":
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"AWS: {title}",
                    severity=severity,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=pf.get("StatusExtended", ""),
                    response=json.dumps(pf, indent=2)[:4096],
                    tags=["cloud", "aws", "prowler", check_id],
                ))

        # 3. Nuclei cloud-specific templates
        nuclei_findings = await self._run_nuclei_cloud(target, context.mission.stealth)
        for nf in nuclei_findings:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            matched = nf.get("matched-at", target)
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {matched}",
                severity=severity,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["cloud", "nuclei", nf.get("template-id", "")],
            ))

        # IAM-related findings generate lateral movement hypotheses
        iam_findings = [f for f in findings if any(t in str(f.tags) for t in ("iam", "privilege", "role"))]
        if iam_findings:
            hypotheses.append(Hypothesis(
                title="Lateral movement via cloud IAM misconfiguration",
                rationale=f"{len(iam_findings)} IAM-related findings detected",
                probability=0.75, impact=0.95,
                suggested_agent="lateral_move",
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "s3_buckets": len(s3_results),
                "prowler_fails": len([f for f in prowler_findings if f.get("Status") == "FAIL"]),
            },
        )

    async def _run_s3scanner(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("s3scanner"):
            return []
        domain = target.lstrip("*.")
        proc = await asyncio.create_subprocess_exec(
            "s3scanner", "scan", "--bucket-file", "/dev/stdin",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        guesses = "\n".join([
            domain.replace(".", "-"), domain.split(".")[0],
            f"{domain.split('.')[0]}-backup", f"{domain.split('.')[0]}-assets",
            f"{domain.split('.')[0]}-data", f"{domain.split('.')[0]}-dev",
        ]).encode()
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(input=guesses), timeout=120)
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

    async def _run_prowler(self) -> list[dict[str, Any]]:
        if not shutil.which("prowler"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "prowler", "aws", "-M", "json-ocsf", "--severity", "critical", "high",
            "-b",  # brief mode
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

    async def _run_nuclei_cloud(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "cloud,aws,azure,gcp,s3,iam",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
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
