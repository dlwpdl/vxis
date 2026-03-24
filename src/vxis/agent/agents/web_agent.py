"""L7-05 WebAgent — OWASP Top 10, authentication, session, business logic testing."""

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

# Nuclei severity → our Severity enum
_NUCLEI_SEV_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

# Nuclei template tags to select for web scanning
_WEB_TAGS = "owasp,cve,xss,sqli,ssrf,rce,lfi,rfi,auth-bypass,default-login,exposure,misconfig"


@register
class WebAgent(BaseAgent):
    agent_id = "web"
    description = "OWASP Top 10, authentication flaws, session management, business logic"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Determine rate limit based on mission config
        depth = context.mission.depth.value
        rate_limit = {"passive": 5, "normal": 50, "aggressive": 150, "elite": 300}.get(depth, 50)

        # Run nuclei for web vulnerabilities
        nuclei_findings = await self._run_nuclei(target, rate_limit, context.mission.stealth)
        for nf in nuclei_findings:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            severity = _NUCLEI_SEV_MAP.get(sev_str, Severity.INFO)
            template_id = nf.get("template-id", "unknown")
            matched_at = nf.get("matched-at", target)
            name = nf.get("info", {}).get("name", template_id)
            desc = nf.get("info", {}).get("description", "")
            tags = nf.get("info", {}).get("tags", [])
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",")]

            ev = Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {matched_at}",
                severity=severity,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=desc or f"Nuclei template {template_id} matched",
                request=nf.get("request", None),
                response=nf.get("response", None),
                tags=["web", "nuclei", template_id] + tags,
            )
            findings.append(ev)

            # Chain hypotheses from significant findings
            if severity in (Severity.CRITICAL, Severity.HIGH):
                if any(t in template_id for t in ("sqli", "sql")):
                    hypotheses.append(Hypothesis(
                        title=f"Database exfiltration via SQLi at {matched_at}",
                        rationale=f"SQL injection found: {name}",
                        probability=0.85, impact=0.95,
                        suggested_agent="database",
                    ))
                if any(t in template_id for t in ("rce", "command")):
                    hypotheses.append(Hypothesis(
                        title=f"OS access via RCE at {matched_at}",
                        rationale=f"Remote code execution found: {name}",
                        probability=0.9, impact=1.0,
                        suggested_agent="os_host",
                    ))
                if "ssrf" in template_id:
                    hypotheses.append(Hypothesis(
                        title=f"Cloud metadata access via SSRF at {matched_at}",
                        rationale=f"SSRF found: {name}",
                        probability=0.7, impact=0.9,
                        suggested_agent="cloud",
                    ))

        # Run ffuf for content discovery (non-passive modes)
        if depth not in ("passive",):
            ffuf_findings = await self._run_ffuf(target, context.mission.stealth)
            for path_info in ffuf_findings:
                url = path_info.get("url", "")
                status = path_info.get("status", 0)
                length = path_info.get("length", 0)
                if status in (200, 301, 302, 403):
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Content discovered: {url} (HTTP {status})",
                        severity=Severity.LOW if status != 403 else Severity.INFO,
                        evidence_type=EvidenceType.HTTP_EXCHANGE,
                        description=f"Status: {status}, Length: {length}",
                        response=json.dumps(path_info),
                        tags=["web", "content-discovery"],
                    ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"nuclei_matches": len(nuclei_findings)},
        )

    async def _run_nuclei(
        self, target: str, rate_limit: int, stealth: bool
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        cmd = [
            "nuclei", "-u", target,
            "-severity", "critical,high,medium,low",
            "-tags", _WEB_TAGS,
            "-rate-limit", str(rate_limit),
            "-jsonl", "-silent", "-irr",
        ]
        if stealth:
            cmd.extend(["-rate-limit", "10", "-delay", "2"])
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5400)
        results = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results

    async def _run_ffuf(self, target: str, stealth: bool) -> list[dict[str, Any]]:
        if not shutil.which("ffuf"):
            return []
        rate = "10" if stealth else "100"
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        cmd = [
            "ffuf", "-u", f"{target}/FUZZ",
            "-w", wordlist,
            "-rate", rate,
            "-mc", "200,301,302,403",
            "-o", "/dev/stdout", "-of", "json",
            "-s",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
            data = json.loads(stdout.decode())
            return data.get("results", [])
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return []
