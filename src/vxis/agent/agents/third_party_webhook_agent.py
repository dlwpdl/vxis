"""L7-28 ThirdPartyWebhookAgent — Webhook forgery, OAuth apps, SaaS integration."""

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

_WEBHOOK_PATHS = [
    "/webhook", "/webhooks", "/api/webhook", "/api/webhooks",
    "/hooks", "/callback", "/api/callback",
    "/.well-known/oauth-authorization-server",
    "/oauth/authorize", "/oauth/token",
]


@register
class ThirdPartyWebhookAgent(BaseAgent):
    agent_id = "third_party_webhook"
    description = "Webhook forgery, OAuth app abuse, SaaS integration security"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        if shutil.which("curl"):
            tasks = [self._probe_path(target, p) for p in _WEBHOOK_PATHS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for path, result in zip(_WEBHOOK_PATHS, results):
                if isinstance(result, dict) and result.get("exposed"):
                    sev = Severity.HIGH if "oauth" in path else Severity.MEDIUM
                    findings.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Webhook/OAuth endpoint exposed: {target}{path}",
                        severity=sev,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=f"Endpoint {path} is publicly accessible (HTTP {result.get('status')})",
                        tags=["third-party", "webhook", "oauth"],
                    ))

        # Nuclei OAuth/webhook templates
        nuclei_results = await self._run_nuclei(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{nf.get('info', {}).get('name', '')} — {nf.get('matched-at', target)}",
                severity=sev_map.get(sev_str, Severity.INFO),
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=nf.get("info", {}).get("description", ""),
                tags=["third-party", "nuclei"],
            ))

        if findings:
            hypotheses.append(Hypothesis(
                title="Supply chain attack via webhook/OAuth abuse",
                rationale=f"{len(findings)} webhook/OAuth endpoints found",
                probability=0.6, impact=0.85,
                suggested_agent="supply_chain",
            ))

        return AgentResult(
            agent_id=self.agent_id, findings=findings, hypotheses=hypotheses,
            status="completed", metadata={"endpoints_found": len(findings)},
        )

    async def _probe_path(self, target: str, path: str) -> dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", f"{target}{path}", "--max-time", "5",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            status = int(stdout.decode().strip())
            if status in (200, 301, 302, 405):
                return {"exposed": True, "status": status}
        except (asyncio.TimeoutError, ValueError):
            pass
        return {"exposed": False}

    async def _run_nuclei(self, target: str, stealth: bool) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-u", target, "-tags", "oauth,webhook,ssrf,redirect",
            "-severity", "critical,high,medium", "-rate-limit", rate, "-jsonl", "-silent",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
        results = []
        for line in stdout.decode().splitlines():
            if line.strip():
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results
