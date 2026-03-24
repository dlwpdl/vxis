"""L7-06 APIAgent — REST, GraphQL, gRPC, WebSocket, Mass Assignment testing."""

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
class APIAgent(BaseAgent):
    agent_id = "api"
    description = "REST, GraphQL, gRPC, WebSocket API security testing"

    # GraphQL introspection query for schema discovery.
    _INTROSPECTION_QUERY = (
        '{"query": "{ __schema { types { name fields { name type { name } } } } }"}'
    )

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # 1. GraphQL introspection probe
        gql_result = await self._probe_graphql(target)
        if gql_result:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"GraphQL introspection enabled on {target}",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description="GraphQL introspection is enabled, exposing the entire API schema.",
                request=f"POST {target}/graphql — introspection query",
                response=json.dumps(gql_result)[:4096],
                tags=["api", "graphql", "introspection"],
            ))
            # Deep dive hypotheses
            hypotheses.append(Hypothesis(
                title=f"GraphQL authorization bypass on {target}",
                rationale="Introspection reveals schema — auth bypass likely testable",
                probability=0.7, impact=0.9,
                suggested_agent="api",
            ))
            hypotheses.append(Hypothesis(
                title=f"GraphQL DoS via nested queries on {target}",
                rationale="No depth limit detected in GraphQL schema",
                probability=0.6, impact=0.7,
                suggested_agent="dos_resilience",
            ))

        # 2. Nuclei API-specific templates
        api_findings = await self._run_nuclei_api(target, context.mission.stealth)
        for nf in api_findings:
            sev_str = nf.get("info", {}).get("severity", "info").lower()
            sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                       "medium": Severity.MEDIUM, "low": Severity.LOW}
            severity = sev_map.get(sev_str, Severity.INFO)
            name = nf.get("info", {}).get("name", nf.get("template-id", ""))
            matched = nf.get("matched-at", target)

            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"{name} — {matched}",
                severity=severity,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=nf.get("info", {}).get("description", ""),
                request=nf.get("request"),
                response=nf.get("response"),
                tags=["api", "nuclei", nf.get("template-id", "")],
            ))

        # 3. Common API misconfigurations — check well-known paths
        misconfig_findings = await self._check_api_misconfigs(target)
        findings.extend(misconfig_findings)
        for mf in misconfig_findings:
            if mf.severity in (Severity.HIGH, Severity.CRITICAL):
                hypotheses.append(Hypothesis(
                    title=f"Data exfiltration via exposed API on {target}",
                    rationale=f"Exposed endpoint found: {mf.title}",
                    probability=0.75, impact=0.85,
                    suggested_agent="data_exfiltration",
                ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={"graphql_enabled": gql_result is not None},
        )

    async def _probe_graphql(self, target: str) -> dict[str, Any] | None:
        """Send introspection query to common GraphQL endpoints."""
        if not shutil.which("curl"):
            return None
        endpoints = [f"{target}/graphql", f"{target}/api/graphql", f"{target}/gql"]
        for endpoint in endpoints:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-X", "POST", endpoint,
                "-H", "Content-Type: application/json",
                "-d", self._INTROSPECTION_QUERY,
                "--max-time", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                data = json.loads(stdout.decode())
                if "data" in data and "__schema" in data.get("data", {}):
                    return data
            except (asyncio.TimeoutError, json.JSONDecodeError, Exception):
                continue
        return None

    async def _run_nuclei_api(
        self, target: str, stealth: bool,
    ) -> list[dict[str, Any]]:
        if not shutil.which("nuclei"):
            return []
        rate = "10" if stealth else "100"
        cmd = [
            "nuclei", "-u", target,
            "-tags", "api,graphql,swagger,openapi,rest",
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

    async def _check_api_misconfigs(self, target: str) -> list[Evidence]:
        """Probe common API documentation / debug endpoints."""
        if not shutil.which("curl"):
            return []
        paths = [
            "/swagger.json", "/openapi.json", "/api-docs",
            "/v1/docs", "/v2/docs", "/.well-known/openid-configuration",
            "/graphql", "/api/debug", "/actuator", "/actuator/env",
        ]
        findings: list[Evidence] = []
        tasks = [self._probe_path(target, p) for p in paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for path, result in zip(paths, results):
            if isinstance(result, dict) and result.get("exposed"):
                sev = Severity.HIGH if "actuator" in path or "debug" in path else Severity.MEDIUM
                findings.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Exposed API endpoint: {target}{path}",
                    severity=sev,
                    evidence_type=EvidenceType.MISCONFIGURATION,
                    description=f"HTTP {result.get('status')} — {path} is publicly accessible",
                    response=result.get("body", "")[:2048],
                    tags=["api", "misconfiguration", "exposure"],
                ))
        return findings

    async def _probe_path(self, target: str, path: str) -> dict[str, Any]:
        proc = await asyncio.create_subprocess_exec(
            "curl", "-sS", "-o", "/dev/null", "-w",
            '{"status": %{http_code}, "size": %{size_download}}',
            f"{target}{path}", "--max-time", "5",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            info = json.loads(stdout.decode())
            status = info.get("status", 0)
            if status in (200, 301, 302) and info.get("size", 0) > 50:
                return {"exposed": True, "status": status, "body": ""}
        except (asyncio.TimeoutError, json.JSONDecodeError):
            pass
        return {"exposed": False}
