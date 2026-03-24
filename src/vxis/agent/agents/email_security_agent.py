"""L7 EmailSecurityAgent — SPF/DKIM/DMARC, email spoofing, SMTP relay testing."""

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
class EmailSecurityAgent(BaseAgent):
    agent_id = "email_security"
    description = "SPF/DKIM/DMARC analysis, email spoofing tests, SMTP relay checks"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: checkdmarc analysis
        dmarc_results = await self._run_checkdmarc(target)
        if dmarc_results:
            # SPF analysis
            spf = dmarc_results.get("spf", {})
            if spf:
                spf_record = spf.get("record", "")
                spf_valid = spf.get("valid", False)
                sev = Severity.INFO if spf_valid else Severity.HIGH
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"SPF record for {target}: {'valid' if spf_valid else 'INVALID/missing'}",
                    severity=sev,
                    evidence_type=EvidenceType.MISCONFIGURATION if not spf_valid else EvidenceType.NETWORK,
                    description=f"SPF record: {spf_record}" if spf_record else "No SPF record found",
                    response=json.dumps(spf, indent=2),
                    tags=["email", "spf"],
                ))
                if not spf_valid:
                    hypotheses.append(Hypothesis(
                        title=f"Email spoofing via missing/weak SPF on {target}",
                        rationale="SPF record is missing or invalid",
                        probability=0.8, impact=0.75,
                        suggested_agent="email_security",
                    ))

            # DMARC analysis
            dmarc = dmarc_results.get("dmarc", {})
            if dmarc:
                dmarc_record = dmarc.get("record", "")
                dmarc_policy = dmarc.get("policy", "none")
                has_dmarc = bool(dmarc_record)
                sev = Severity.INFO
                if not has_dmarc:
                    sev = Severity.HIGH
                elif dmarc_policy == "none":
                    sev = Severity.MEDIUM
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"DMARC policy for {target}: {dmarc_policy if has_dmarc else 'MISSING'}",
                    severity=sev,
                    evidence_type=EvidenceType.MISCONFIGURATION if sev != Severity.INFO else EvidenceType.NETWORK,
                    description=(
                        f"DMARC record: {dmarc_record}" if has_dmarc
                        else "No DMARC record found. Domain is vulnerable to email spoofing."
                    ),
                    response=json.dumps(dmarc, indent=2),
                    tags=["email", "dmarc"],
                ))
                if not has_dmarc or dmarc_policy == "none":
                    hypotheses.append(Hypothesis(
                        title=f"Domain spoofing via weak DMARC on {target}",
                        rationale=f"DMARC policy is '{dmarc_policy}' or missing",
                        probability=0.85, impact=0.8,
                        suggested_agent="email_security",
                    ))

        # Phase 2: Direct DNS lookup for SPF/DKIM/DMARC
        dns_email = await self._check_email_dns(target)
        for record in dns_email:
            if record not in [f.title for f in findings]:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=record["title"],
                    severity=record["severity"],
                    evidence_type=EvidenceType.NETWORK,
                    description=record["description"],
                    response=record.get("value", ""),
                    tags=["email", "dns", record["type"]],
                ))

        # Phase 3: SMTP relay / open relay check
        smtp_results = await self._check_smtp(target)
        for sr in smtp_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=sr["title"],
                severity=sr["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=sr["description"],
                response=sr.get("banner", ""),
                tags=["email", "smtp"] + sr.get("tags", []),
            ))
            if sr.get("open_relay"):
                hypotheses.append(Hypothesis(
                    title=f"Spam/phishing via open SMTP relay on {target}",
                    rationale="Open SMTP relay detected",
                    probability=0.9, impact=0.85,
                    suggested_agent="email_security",
                ))

        # Phase 4: MX record analysis
        mx_results = await self._check_mx_records(target)
        for mx in mx_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"MX record: {mx['host']} (priority {mx['priority']})",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=f"Mail exchange server for {target}",
                tags=["email", "mx"],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "spf_valid": dmarc_results.get("spf", {}).get("valid") if dmarc_results else None,
                "dmarc_policy": dmarc_results.get("dmarc", {}).get("policy") if dmarc_results else None,
                "mx_count": len(mx_results),
            },
        )

    async def _run_checkdmarc(self, target: str) -> dict[str, Any] | None:
        if not shutil.which("checkdmarc"):
            return None
        proc = await asyncio.create_subprocess_exec(
            "checkdmarc", target, "--json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            return json.loads(stdout.decode())
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return None

    async def _check_email_dns(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("dig"):
            return []
        results: list[dict[str, Any]] = []
        # Check DKIM selector records
        common_selectors = ["default", "google", "selector1", "selector2", "mail", "k1"]
        for selector in common_selectors:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "TXT", f"{selector}._domainkey.{target}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode().strip()
                if output and "NXDOMAIN" not in output:
                    results.append({
                        "title": f"DKIM record found: {selector}._domainkey.{target}",
                        "severity": Severity.INFO,
                        "description": f"DKIM selector '{selector}' is configured",
                        "type": "dkim",
                        "value": output[:512],
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_smtp(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("nmap"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-sV", "-Pn", "--script", "smtp-open-relay,smtp-commands",
            "-p", "25,465,587", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode()
            if "open" in output and ("25/tcp" in output or "465/tcp" in output or "587/tcp" in output):
                is_relay = "open-relay" in output.lower() or "Server is an open relay" in output
                results.append({
                    "title": f"SMTP service on {target}",
                    "severity": Severity.CRITICAL if is_relay else Severity.INFO,
                    "description": f"SMTP service found. Open relay: {is_relay}",
                    "banner": output[:2048],
                    "open_relay": is_relay,
                    "tags": ["open-relay"] if is_relay else [],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _check_mx_records(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("dig"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "MX", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            results: list[dict[str, Any]] = []
            for line in stdout.decode().splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    results.append({
                        "priority": parts[0],
                        "host": parts[1].rstrip("."),
                    })
            return results
        except asyncio.TimeoutError:
            return []
