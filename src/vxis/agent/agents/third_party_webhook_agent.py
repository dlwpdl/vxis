"""L7 ThirdPartyWebhookAgent — Webhook forgery, OAuth apps, SaaS integration analysis."""

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
    "/api/v1/webhook", "/hooks", "/callback",
    "/api/callback", "/api/v1/callback",
    "/stripe/webhook", "/github/webhook", "/gitlab/webhook",
    "/api/payments/webhook", "/api/events",
]

_OAUTH_PATHS = [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/oauth/authorize", "/oauth/token",
    "/auth/authorize", "/api/oauth/authorize",
]


@register
class ThirdPartyWebhookAgent(BaseAgent):
    agent_id = "third_party_webhook"
    description = "Webhook forgery, OAuth app abuse, SaaS integration security analysis"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Webhook endpoint discovery
        webhook_endpoints = await self._discover_webhooks(target)
        for wh in webhook_endpoints:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Webhook endpoint: {wh['path']} on {target}",
                severity=wh.get("severity", Severity.MEDIUM),
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=f"Webhook endpoint at {wh['path']} responds with HTTP {wh.get('status', '?')}",
                tags=["third-party", "webhook"],
            ))

        # Phase 2: Webhook signature verification test
        sig_results = await self._test_webhook_signatures(target, webhook_endpoints)
        for sr in sig_results:
            if sr.get("no_verification"):
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Webhook forgery: no signature verification on {sr['path']}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=(
                        f"Webhook endpoint {sr['path']} accepts payloads without "
                        f"signature verification, allowing request forgery."
                    ),
                    request=sr.get("request", ""),
                    response=sr.get("response", ""),
                    tags=["third-party", "webhook", "forgery"],
                ))
                hypotheses.append(Hypothesis(
                    title=f"Webhook-triggered actions via forgery on {target}",
                    rationale=f"Webhook at {sr['path']} lacks signature verification",
                    probability=0.8, impact=0.85,
                    suggested_agent="web",
                ))

        # Phase 3: OAuth configuration
        oauth_results = await self._check_oauth(target)
        for or_ in oauth_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=or_["title"],
                severity=or_["severity"],
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=or_["description"],
                response=or_.get("detail", ""),
                tags=["third-party", "oauth"] + or_.get("tags", []),
            ))
            if or_["severity"] in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"OAuth token theft on {target}",
                    rationale=or_["description"],
                    probability=0.65, impact=0.9,
                    suggested_agent="identity_ad",
                ))

        # Phase 4: Third-party integration tokens in page source
        token_results = await self._check_exposed_tokens(target)
        for tr in token_results:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=tr["title"],
                severity=tr["severity"],
                evidence_type=EvidenceType.SECRET,
                description=tr["description"],
                tags=["third-party", "token-exposure"] + tr.get("tags", []),
            ))

        # Phase 5: Nuclei OAuth/webhook templates
        nuclei_results = await self._run_nuclei(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{nf.get('info', {}).get('name', '')} — {nf.get('matched-at', target)}",
                severity=sev_map.get(sev_str, Severity.INFO),
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["third-party", "nuclei", nf.get("template-id", "")],
            ))

        if findings:
            hypotheses.append(Hypothesis(
                title=f"Supply chain attack via webhook/OAuth abuse on {target}",
                rationale=f"{len(findings)} webhook/OAuth endpoints found",
                probability=0.6, impact=0.85,
                suggested_agent="supply_chain",
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "webhook_endpoints": len(webhook_endpoints),
                "no_sig_verification": len([s for s in sig_results if s.get("no_verification")]),
            },
        )

    async def _discover_webhooks(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        for path in _WEBHOOK_PATHS:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-X", "POST", f"{target}{path}",
                "-H", "Content-Type: application/json",
                "-d", '{"test": true}',
                "-w", "\n%{http_code}", "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                status = lines[-1].strip()
                if status in ("200", "400", "401", "403", "405"):
                    sev = Severity.MEDIUM if status == "200" else Severity.INFO
                    results.append({"path": path, "status": status, "severity": sev})
            except asyncio.TimeoutError:
                continue
        return results

    async def _test_webhook_signatures(
        self, target: str, endpoints: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        for ep in endpoints:
            if ep.get("status") not in ("200", "400"):
                continue
            path = ep["path"]
            payload = json.dumps({"event": "test", "data": {"id": 1}})
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-X", "POST", f"{target}{path}",
                "-H", "Content-Type: application/json",
                "-H", "X-Hub-Signature-256: sha256=invalid",
                "-H", "X-Stripe-Signature: t=0,v1=invalid",
                "-d", payload,
                "-w", "\n%{http_code}", "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                results.append({
                    "path": path,
                    "no_verification": status == "200",
                    "request": f"POST {target}{path} with invalid signature",
                    "response": f"HTTP {status}\n{body[:1024]}",
                })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_oauth(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        for path in _OAUTH_PATHS:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", f"{target}{path}", "-w", "\n%{http_code}",
                "--max-time", "5",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                output = stdout.decode(errors="replace")
                lines = output.rsplit("\n", 1)
                body = lines[0] if len(lines) > 1 else ""
                status = lines[-1].strip()
                if status in ("200", "301", "302") and len(body) > 20:
                    sev = Severity.MEDIUM
                    tags: list[str] = []
                    if "openid-configuration" in path:
                        try:
                            data = json.loads(body)
                            grants = data.get("grant_types_supported", [])
                            if "implicit" in grants:
                                sev = Severity.MEDIUM
                                tags.append("implicit-grant")
                        except json.JSONDecodeError:
                            pass
                    results.append({
                        "title": f"OAuth/OIDC endpoint: {path}",
                        "severity": sev,
                        "description": f"OAuth endpoint at {path} (HTTP {status})",
                        "detail": body[:2048],
                        "tags": tags,
                    })
            except asyncio.TimeoutError:
                continue
        return results

    async def _check_exposed_tokens(self, target: str) -> list[dict[str, Any]]:
        if not shutil.which("curl"):
            return []
        results: list[dict[str, Any]] = []
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", target, "--max-time", "15",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            body = stdout.decode(errors="replace")
            import re
            # Google Maps API key
            gmap_keys = re.findall(r'AIza[0-9A-Za-z_-]{35}', body)
            for key in set(gmap_keys[:2]):
                results.append({
                    "title": f"Google API key exposed on {target}",
                    "severity": Severity.MEDIUM,
                    "description": f"Google API key in page source: {key[:15]}...",
                    "tags": ["google-api"],
                })
            # Slack webhook
            slack_hooks = re.findall(r'https://hooks\.slack\.com/services/[A-Za-z0-9/]+', body)
            for hook in set(slack_hooks[:2]):
                results.append({
                    "title": f"Slack webhook exposed on {target}",
                    "severity": Severity.HIGH,
                    "description": f"Slack incoming webhook in page source",
                    "tags": ["slack"],
                })
            # Stripe keys
            stripe_keys = re.findall(r'pk_(?:live|test)_[0-9a-zA-Z]{24,}', body)
            for key in set(stripe_keys[:2]):
                sev = Severity.HIGH if "pk_live" in key else Severity.LOW
                results.append({
                    "title": f"Stripe key exposed on {target}",
                    "severity": sev,
                    "description": f"Stripe publishable key in page source",
                    "tags": ["stripe"],
                })
        except asyncio.TimeoutError:
            pass
        return results

    async def _run_nuclei(self, target: str, stealth: bool) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        proc = await asyncio.create_subprocess_exec(
            "nuclei", "-u", target,
            "-tags", "oauth,webhook,ssrf,redirect",
            "-severity", "critical,high,medium",
            "-rate-limit", rate, "-jsonl", "-silent",
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
