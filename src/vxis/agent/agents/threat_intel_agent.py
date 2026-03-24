"""L7 ThreatIntelAgent — Real-time CVE monitoring, breach history, Shodan/Censys."""

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
class ThreatIntelAgent(BaseAgent):
    agent_id = "threat_intel"
    description = "Real-time CVE feeds, breach history, Shodan/Censys reconnaissance"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target.lstrip("*.")
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Shodan host intelligence
        shodan_data = await self._run_shodan(target)
        if shodan_data:
            ports = shodan_data.get("ports", [])
            vulns = shodan_data.get("vulns", [])
            org = shodan_data.get("org", "Unknown")

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Shodan intel for {target}: {len(ports)} ports, {len(vulns)} CVEs",
                severity=Severity.HIGH if vulns else Severity.INFO,
                evidence_type=EvidenceType.OSINT,
                description=(
                    f"Organization: {org}. Open ports: {ports[:20]}. "
                    f"Known CVEs: {vulns[:20]}"
                ),
                response=json.dumps(shodan_data, indent=2)[:4096],
                tags=["threat-intel", "shodan"],
            ))

            for cve in vulns[:10]:
                hypotheses.append(Hypothesis(
                    title=f"Exploit {cve} on {target}",
                    rationale=f"Shodan reports {cve} for {target}",
                    probability=0.7, impact=0.9,
                    suggested_agent="web",
                    suggested_tool="nuclei",
                ))

            # Port-based hypotheses
            if 3389 in ports:
                hypotheses.append(Hypothesis(
                    title=f"RDP exploitation on {target}",
                    rationale="Shodan shows RDP (3389) open",
                    probability=0.6, impact=0.9,
                    suggested_agent="remote_access",
                ))
            if 27017 in ports or 6379 in ports or 9200 in ports:
                hypotheses.append(Hypothesis(
                    title=f"Exposed database on {target}",
                    rationale="Shodan shows database port(s) open",
                    probability=0.7, impact=0.95,
                    suggested_agent="database",
                ))

        # Phase 2: Shodan search for related infrastructure
        search_results = await self._shodan_search(target)
        for result in search_results:
            ip = result.get("ip_str", "")
            port = result.get("port", 0)
            product = result.get("product", "")
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Related host: {ip}:{port} ({product})",
                severity=Severity.INFO,
                evidence_type=EvidenceType.OSINT,
                description=f"Shodan found {ip}:{port} running {product} associated with {target}",
                response=json.dumps(result, indent=2)[:2048],
                tags=["threat-intel", "shodan", "infrastructure"],
            ))

        # Phase 3: CVE lookup for detected services
        nuclei_results = await self._run_nuclei_cve(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            template_id = nf.get("template-id", "")
            matched = nf.get("matched-at", target)

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"CVE: {name} — {matched}",
                severity=severity,
                evidence_type=EvidenceType.EXPLOIT,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                cvss_score=nf.get("info", {}).get("classification", {}).get("cvss-score"),
                tags=["threat-intel", "cve", template_id],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "shodan_ports": len(shodan_data.get("ports", [])) if shodan_data else 0,
                "cves_found": len([f for f in findings if "cve" in str(f.tags)]),
            },
        )

    async def _run_shodan(self, target: str) -> dict[str, Any] | None:
        if not shutil.which("shodan"):
            return None
        proc = await asyncio.create_subprocess_exec(
            "shodan", "host", target, "--format", "json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            return json.loads(stdout.decode())
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return None

    async def _shodan_search(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("shodan"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "shodan", "search", f"hostname:{target}", "--format", "json", "--limit", "20",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            results: list[dict[str, Any]] = []
            for line in stdout.decode().splitlines():
                if line.strip():
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            return results
        except asyncio.TimeoutError:
            return []

    async def _run_nuclei_cve(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "cve",
            "-severity", "critical,high",
            "-rate-limit", rate, "-jsonl", "-silent",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=3600)
        results: list[dict[str, Any]] = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
