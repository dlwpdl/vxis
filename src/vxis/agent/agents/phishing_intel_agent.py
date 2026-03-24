"""L8-01 PhishingIntelAgent — spear phishing scenarios, domain similarity, vulnerable employees."""

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
class PhishingIntelAgent(BaseAgent):
    agent_id = "phishing_intel"
    description = (
        "Spear-phishing scenario assessment: lookalike domain discovery via "
        "dnstwist, MX/SPF/DMARC validation, and employee exposure analysis"
    )

    # Common phishing-relevant DNS record checks
    _SPF_QUALIFIERS = {"+all", "~all", "?all"}

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Lookalike domain discovery with dnstwist
        lookalikes = await self._run_dnstwist(target)
        registered = [d for d in lookalikes if d.get("dns_a") or d.get("dns_mx")]
        if registered:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Lookalike domains detected: {len(registered)} registered",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.OSINT,
                description=(
                    f"dnstwist found {len(registered)} registered lookalike domains "
                    f"for {target} that could be used in phishing campaigns"
                ),
                response=json.dumps(registered[:30], indent=2),
                tags=["phishing", "lookalike-domain", "osint"],
            ))
            # Domains with MX records are extra dangerous — ready to send mail
            mx_domains = [d for d in registered if d.get("dns_mx")]
            if mx_domains:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"{len(mx_domains)} lookalike domains have MX records",
                    severity=Severity.CRITICAL,
                    evidence_type=EvidenceType.OSINT,
                    description=(
                        "These domains can send/receive email and are prime "
                        "phishing infrastructure candidates"
                    ),
                    response=json.dumps(mx_domains[:20], indent=2),
                    tags=["phishing", "mx-record", "active-threat"],
                ))

        # Phase 2: SPF/DMARC/DKIM checks on the real domain
        spf_findings = await self._check_email_security(target)
        for finding in spf_findings:
            findings.append(finding)

        # Phase 3: OSINT employee enumeration via theHarvester
        employees = await self._run_theharvester(target)
        if employees:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Employee email exposure: {len(employees)} addresses found",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.OSINT,
                description=(
                    f"Public email addresses discovered for {target} that could "
                    "be targeted in spear-phishing campaigns"
                ),
                response=json.dumps(employees[:50], indent=2),
                tags=["phishing", "email", "osint", "employee"],
            ))
            hypotheses.append(Hypothesis(
                title=f"Credential stuffing against exposed employees of {target}",
                rationale=(
                    f"{len(employees)} employee emails found; likely reused "
                    "credentials in breached databases"
                ),
                probability=0.7,
                impact=0.85,
                suggested_agent="identity_ad",
                suggested_tool="h8mail",
            ))

        # Chain hypotheses
        if registered:
            hypotheses.append(Hypothesis(
                title=f"Active phishing campaign using lookalike domains of {target}",
                rationale=f"{len(registered)} registered lookalike domains detected",
                probability=0.6,
                impact=0.9,
                suggested_agent="phishing_intel",
                suggested_tool="dnstwist",
            ))
        hypotheses.append(Hypothesis(
            title=f"Email spoofing possible for {target}",
            rationale="Check SPF/DMARC enforcement to assess spoofability",
            probability=0.5,
            impact=0.8,
            suggested_agent="email_security",
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "lookalike_domains": len(registered),
                "mx_capable_lookalikes": len(
                    [d for d in registered if d.get("dns_mx")]
                ),
                "employees_found": len(employees) if employees else 0,
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _run_dnstwist(self, domain: str) -> list[dict[str, Any]]:
        if not shutil.which("dnstwist"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "dnstwist", "--registered", "--format", "json", domain,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        try:
            return json.loads(stdout.decode()) if stdout else []
        except json.JSONDecodeError:
            return []

    async def _check_email_security(self, domain: str) -> list[Evidence]:
        """Check SPF, DMARC, and DKIM records using dig."""
        results: list[Evidence] = []
        if not shutil.which("dig"):
            return results

        # SPF check
        spf_raw = await self._dig_txt(domain)
        spf_records = [r for r in spf_raw if "v=spf1" in r.lower()]
        if not spf_records:
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"No SPF record for {domain}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=f"Domain {domain} has no SPF record, allowing email spoofing",
                tags=["phishing", "spf", "email-security"],
            ))
        else:
            for spf in spf_records:
                if any(q in spf.lower() for q in self._SPF_QUALIFIERS):
                    results.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Weak SPF policy on {domain}",
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=f"SPF record uses permissive qualifier: {spf}",
                        response=spf,
                        tags=["phishing", "spf", "email-security"],
                    ))

        # DMARC check
        dmarc_raw = await self._dig_txt(f"_dmarc.{domain}")
        dmarc_records = [r for r in dmarc_raw if "v=dmarc1" in r.lower()]
        if not dmarc_records:
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"No DMARC record for {domain}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=f"Domain {domain} has no DMARC record, reducing spoofing protection",
                tags=["phishing", "dmarc", "email-security"],
            ))
        else:
            for dmarc in dmarc_records:
                if "p=none" in dmarc.lower():
                    results.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"DMARC policy is 'none' on {domain}",
                        severity=Severity.MEDIUM,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=f"DMARC set to monitor-only (p=none): {dmarc}",
                        response=dmarc,
                        tags=["phishing", "dmarc", "email-security"],
                    ))

        return results

    async def _dig_txt(self, name: str) -> list[str]:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "TXT", name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        return [
            line.strip().strip('"')
            for line in stdout.decode().splitlines()
            if line.strip()
        ]

    async def _run_theharvester(self, domain: str) -> list[str]:
        if not shutil.which("theHarvester"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "theHarvester", "-d", domain, "-b", "all", "-f", "/dev/null",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        emails: list[str] = []
        for line in stdout.decode().splitlines():
            line = line.strip()
            if "@" in line and domain in line:
                emails.append(line)
        return list(set(emails))
