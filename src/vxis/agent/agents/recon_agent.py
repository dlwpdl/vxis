"""L7-01 ReconAgent — subdomain enumeration, ASN, WHOIS, tech stack detection."""

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
class ReconAgent(BaseAgent):
    agent_id = "recon"
    description = "Subdomain enumeration, ASN/WHOIS lookup, technology stack detection"

    # Tools this agent can invoke and their CLI templates.
    TOOLS: dict[str, dict[str, Any]] = {
        "subfinder": {
            "binary": "subfinder",
            "args": ["-d", "{target}", "-all", "-recursive", "-oJ", "-silent"],
            "parse": "_parse_subfinder",
        },
        "httpx": {
            "binary": "httpx",
            "args": ["-json", "-tech-detect", "-tls-grab", "-cdn", "-cname", "-asn"],
            "stdin": True,
            "parse": "_parse_httpx",
        },
    }

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Subdomain enumeration
        subdomains = await self._run_subfinder(target)
        if subdomains:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Subdomain enumeration: {len(subdomains)} hosts discovered",
                severity=Severity.INFO,
                evidence_type=EvidenceType.OSINT,
                description=f"Discovered subdomains for {target}",
                response=json.dumps(subdomains[:50], indent=2),
                tags=["recon", "subdomain"],
            ))

        # Phase 2: HTTP probing + tech detection
        live_hosts = await self._run_httpx(subdomains or [target])
        for host_info in live_hosts:
            url = host_info.get("url", "")
            techs = host_info.get("tech", [])
            status = host_info.get("status_code", 0)
            cdn = host_info.get("cdn", False)

            if techs:
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Technology stack detected on {url}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.OSINT,
                    description=f"Technologies: {', '.join(techs)}",
                    response=json.dumps(host_info, indent=2),
                    tags=["recon", "tech-detect"] + [t.lower() for t in techs],
                ))

                # Generate hypotheses based on detected tech
                for tech in techs:
                    tech_lower = tech.lower()
                    if "wordpress" in tech_lower:
                        hypotheses.append(Hypothesis(
                            title=f"WordPress vulnerabilities on {url}",
                            rationale=f"WordPress detected on {url}",
                            probability=0.75, impact=0.8,
                            suggested_agent="web",
                            suggested_tool="nuclei",
                        ))
                    elif "graphql" in tech_lower:
                        hypotheses.append(Hypothesis(
                            title=f"GraphQL introspection on {url}",
                            rationale=f"GraphQL detected on {url}",
                            probability=0.8, impact=0.85,
                            suggested_agent="api",
                        ))
                    elif any(k in tech_lower for k in ("aws", "amazon")):
                        hypotheses.append(Hypothesis(
                            title=f"AWS misconfiguration on {url}",
                            rationale=f"AWS service detected on {url}",
                            probability=0.6, impact=0.9,
                            suggested_agent="cloud",
                        ))

            if not cdn and status and 200 <= status < 500:
                hypotheses.append(Hypothesis(
                    title=f"Direct-origin web scan for {url}",
                    rationale=f"Non-CDN host {url} (status {status}) is directly reachable",
                    probability=0.9, impact=0.7,
                    suggested_agent="web",
                ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "subdomains_found": len(subdomains),
                "live_hosts": len(live_hosts),
            },
        )

    # ------------------------------------------------------------------
    # Tool execution helpers
    # ------------------------------------------------------------------

    async def _run_subfinder(self, target: str) -> list[str]:
        if not shutil.which("subfinder"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-d", target, "-all", "-recursive", "-silent",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        return [line.strip() for line in stdout.decode().splitlines() if line.strip()]

    async def _run_httpx(self, hosts: list[str]) -> list[dict[str, Any]]:
        if not shutil.which("httpx"):
            return []
        stdin_data = "\n".join(hosts).encode()
        proc = await asyncio.create_subprocess_exec(
            "httpx", "-json", "-tech-detect", "-tls-grab", "-cdn", "-silent",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=stdin_data), timeout=600,
        )
        results = []
        for line in stdout.decode().splitlines():
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
