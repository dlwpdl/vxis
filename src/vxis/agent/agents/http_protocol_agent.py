"""L7-07 HTTPProtocolAgent — Request Smuggling, Desync, Cache Poisoning, CORS."""

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

# CORS misconfiguration test origins
_CORS_TEST_ORIGINS = [
    "https://evil.com",
    "null",
    "https://{domain}.evil.com",  # reflected origin
]


@register
class HTTPProtocolAgent(BaseAgent):
    agent_id = "http_protocol"
    description = "HTTP Request Smuggling, Desync, Cache Poisoning, CORS misconfiguration"

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # 1. Nuclei HTTP protocol templates
        nuclei_results = await self._run_nuclei_http(target, context.mission.stealth)
        for nf in nuclei_results:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", "")
            matched = nf.get("matched-at", target)

            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"{name} — {matched}",
                    severity=severity,
                    evidence_type=EvidenceType.HTTP_EXCHANGE,
                    description=nf.get("info", {}).get("description", ""),
                    request=nf.get("request"),
                    response=nf.get("response"),
                    tags=["http-protocol", "nuclei", nf.get("template-id", "")],
                )
            )

            if "smuggling" in name.lower() or "desync" in name.lower():
                hypotheses.append(
                    Hypothesis(
                        title=f"Cache poisoning via request smuggling at {matched}",
                        rationale=f"HTTP smuggling detected: {name}",
                        probability=0.7,
                        impact=0.9,
                        suggested_agent="http_protocol",
                    )
                )

        # 2. CORS misconfiguration check
        cors_findings = await self._check_cors(target)
        findings.extend(cors_findings)
        for cf in cors_findings:
            if cf.severity in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(
                    Hypothesis(
                        title=f"Credential theft via CORS misconfiguration on {target}",
                        rationale="CORS allows arbitrary origin with credentials",
                        probability=0.8,
                        impact=0.85,
                        suggested_agent="web",
                    )
                )

        # 3. HTTP security headers check
        header_findings = await self._check_security_headers(target)
        findings.extend(header_findings)

        # 4. Cache poisoning probe (Host header injection)
        cache_findings = await self._check_cache_poisoning(target)
        findings.extend(cache_findings)

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"total_findings": len(findings)},
        )

    async def _run_nuclei_http(
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
            "smuggling,desync,cache,cors,host-header,crlf,redirect",
            "-severity",
            "critical,high,medium",
            "-rate-limit",
            rate,
            "-jsonl",
            "-silent",
            "-irr",
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

    async def _check_cors(self, target: str) -> list[Evidence]:
        if not shutil.which("curl"):
            return []
        findings: list[Evidence] = []
        domain = target.split("//")[-1].split("/")[0]
        for origin_template in _CORS_TEST_ORIGINS:
            origin = origin_template.replace("{domain}", domain)
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-sS",
                "-I",
                target,
                "-H",
                f"Origin: {origin}",
                "--max-time",
                "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                headers = stdout.decode().lower()
                if f"access-control-allow-origin: {origin.lower()}" in headers:
                    creds = "access-control-allow-credentials: true" in headers
                    sev = Severity.HIGH if creds else Severity.MEDIUM
                    findings.append(
                        Evidence(
                            agent_id=self.agent_id,
                            title=f"CORS misconfiguration: reflects {origin}",
                            severity=sev,
                            evidence_type=EvidenceType.HTTP_EXCHANGE,
                            description=(
                                f"Target reflects arbitrary Origin header ({origin})"
                                + (". Credentials allowed!" if creds else "")
                            ),
                            request=f"Origin: {origin}",
                            response=stdout.decode()[:2048],
                            tags=["http-protocol", "cors", "misconfiguration"],
                        )
                    )
            except asyncio.TimeoutError:
                continue
        return findings

    async def _check_security_headers(self, target: str) -> list[Evidence]:
        if not shutil.which("curl"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "curl",
            "-sS",
            "-I",
            target,
            "--max-time",
            "10",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            headers_raw = stdout.decode().lower()
            findings: list[Evidence] = []

            required_headers = {
                "strict-transport-security": "HSTS header missing",
                "x-content-type-options": "X-Content-Type-Options missing",
                "x-frame-options": "X-Frame-Options missing",
                "content-security-policy": "Content-Security-Policy missing",
                "x-xss-protection": "X-XSS-Protection missing",
            }
            missing = []
            for header, desc in required_headers.items():
                if header not in headers_raw:
                    missing.append(desc)

            if missing:
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"Missing security headers on {target}",
                        severity=Severity.LOW,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description="; ".join(missing),
                        response=stdout.decode()[:2048],
                        tags=["http-protocol", "headers", "misconfiguration"],
                    )
                )
            return findings
        except asyncio.TimeoutError:
            return []

    async def _check_cache_poisoning(self, target: str) -> list[Evidence]:
        """Check for Host header injection / cache poisoning."""
        if not shutil.which("curl"):
            return []
        proc = await asyncio.create_subprocess_exec(
            "curl",
            "-sS",
            target,
            "-H",
            "Host: evil.com",
            "-H",
            "X-Forwarded-Host: evil.com",
            "--max-time",
            "10",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            body = stdout.decode()
            findings: list[Evidence] = []
            if "evil.com" in body:
                findings.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"Host header injection on {target}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.HTTP_EXCHANGE,
                        description="Injected Host/X-Forwarded-Host reflected in response body — cache poisoning possible",
                        request="Host: evil.com / X-Forwarded-Host: evil.com",
                        response=body[:2048],
                        tags=["http-protocol", "cache-poisoning", "host-injection"],
                    )
                )
            return findings
        except asyncio.TimeoutError:
            return []
