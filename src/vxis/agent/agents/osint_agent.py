"""L7 OSINTAgent — LinkedIn, job postings, GitHub repos, dark web reconnaissance."""

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
class OSINTAgent(BaseAgent):
    agent_id = "osint"
    description = "Open-source intelligence: LinkedIn, job postings, GitHub repos, dark web"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: theHarvester — email, subdomain, host enumeration
        harvester_results = await self._run_theharvester(target)
        emails = harvester_results.get("emails", [])
        hosts = harvester_results.get("hosts", [])

        if emails:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Email addresses discovered for {target}: {len(emails)} found",
                    severity=Severity.LOW,
                    evidence_type=EvidenceType.OSINT,
                    description=f"Harvested email addresses from public sources for {target}.",
                    response=json.dumps(emails[:100], indent=2),
                    tags=["osint", "email", "harvester"],
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"Credential stuffing with harvested emails for {target}",
                    rationale=f"{len(emails)} email addresses found via OSINT",
                    probability=0.6,
                    impact=0.85,
                    suggested_agent="identity_ad",
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"Phishing attack surface via harvested emails for {target}",
                    rationale="Email addresses exposed in public sources",
                    probability=0.7,
                    impact=0.7,
                    suggested_agent="email_security",
                )
            )

        if hosts:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Hosts discovered for {target}: {len(hosts)} found",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.OSINT,
                    description="Hosts and subdomains found via OSINT sources.",
                    response=json.dumps(hosts[:100], indent=2),
                    tags=["osint", "hosts", "harvester"],
                )
            )

        # Phase 2: Nuclei exposure templates
        nuclei_results = await self._run_nuclei_exposure(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", nf.get("template-id", ""))
            matched = nf.get("matched-at", target)
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"{name} — {matched}",
                    severity=severity,
                    evidence_type=EvidenceType.OSINT,
                    description=nf.get("info", {}).get("description", ""),
                    request=nf.get("request"),
                    response=nf.get("response"),
                    tags=["osint", "nuclei", nf.get("template-id", "")],
                )
            )

        # Phase 3: GitHub dork scan for leaked secrets
        github_results = await self._github_dork(target)
        for gr in github_results:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"GitHub exposure: {gr['description']}",
                    severity=gr.get("severity", Severity.MEDIUM),
                    evidence_type=EvidenceType.OSINT,
                    description=gr["description"],
                    response=gr.get("detail", ""),
                    tags=["osint", "github", "leak"],
                )
            )
            if gr.get("severity") in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(
                    Hypothesis(
                        title=f"Secret exposure in GitHub repos for {target}",
                        rationale=gr["description"],
                        probability=0.8,
                        impact=0.9,
                        suggested_agent="secrets_lifecycle",
                        suggested_tool="trufflehog",
                    )
                )

        # Phase 4: Metadata / tech-stack OSINT via DNS TXT records
        txt_findings = await self._check_dns_txt(target)
        for tf in txt_findings:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"DNS TXT record leaks info: {tf['record'][:80]}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.OSINT,
                    description=f"DNS TXT record for {target} reveals: {tf['record']}",
                    tags=["osint", "dns", "txt"],
                )
            )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "emails_found": len(emails),
                "hosts_found": len(hosts),
                "nuclei_matches": len(nuclei_results),
            },
        )

    async def _run_theharvester(self, target: str) -> dict[str, list[str]]:
        if not shutil.which("theHarvester"):
            return {"emails": [], "hosts": []}
        proc = await asyncio.create_subprocess_exec(
            "theHarvester",
            "-d",
            target,
            "-b",
            "all",
            "-f",
            "/dev/stdout",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
            output = stdout.decode(errors="replace")
            emails: list[str] = []
            hosts: list[str] = []
            section = ""
            for line in output.splitlines():
                line = line.strip()
                if "emails" in line.lower() and "found" in line.lower():
                    section = "emails"
                    continue
                elif "hosts" in line.lower() and "found" in line.lower():
                    section = "hosts"
                    continue
                elif line.startswith("[") or line.startswith("---"):
                    section = ""
                    continue
                if section == "emails" and "@" in line:
                    emails.append(line)
                elif section == "hosts" and line:
                    hosts.append(line)
            return {"emails": emails, "hosts": hosts}
        except asyncio.TimeoutError:
            return {"emails": [], "hosts": []}

    async def _run_nuclei_exposure(
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
            "exposure,osint,disclosure,listing",
            "-severity",
            "critical,high,medium,low",
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
        results: list[dict[str, Any]] = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results

    async def _github_dork(self, target: str) -> list[dict[str, Any]]:
        """Search for GitHub leaks using nuclei github-exposed templates."""
        if not shutil.which("nuclei"):
            return []
        cmd = [
            "nuclei",
            "-u",
            "https://github.com",
            "-tags",
            "exposure",
            "-var",
            f"domain={target}",
            "-jsonl",
            "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            results: list[dict[str, Any]] = []
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        data = json.loads(line)
                        results.append(
                            {
                                "description": data.get("info", {}).get("name", "GitHub exposure"),
                                "severity": Severity.MEDIUM,
                                "detail": json.dumps(data)[:2048],
                            }
                        )
                    except json.JSONDecodeError:
                        continue
            return results
        except asyncio.TimeoutError:
            return []

    async def _check_dns_txt(self, target: str) -> list[dict[str, str]]:
        if not shutil.which("dig"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "dig",
            "+short",
            "TXT",
            target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            records: list[dict[str, str]] = []
            for line in stdout.decode().splitlines():
                line = line.strip().strip('"')
                if line:
                    records.append({"record": line})
            return records
        except asyncio.TimeoutError:
            return []
