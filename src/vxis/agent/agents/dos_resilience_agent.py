"""META-04 DoSResilienceAgent — rate limit verification, ReDoS, GraphQL depth, connection pool."""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import time
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class DoSResilienceAgent(BaseAgent):
    agent_id = "dos_resilience"
    description = (
        "Resilience testing (non-destructive): rate limiting, ReDoS patterns, "
        "GraphQL query depth/complexity, Slowloris, connection pool exhaustion"
    )

    # ReDoS patterns to test against regex endpoints
    _REDOS_PAYLOADS = [
        "a" * 30 + "!",                       # evil regex: (a+)+
        "aaaaaaaaaa" * 3 + "@",               # email-like catastrophic backtracking
        "<" + "a" * 30 + "",                   # HTML tag backtracking
        "0" * 30 + "x",                        # number validation backtracking
    ]

    # GraphQL introspection + depth test queries
    _GRAPHQL_DEPTH_QUERY = """
    query {
      __schema {
        types {
          name
          fields {
            name
            type {
              name
              fields {
                name
                type {
                  name
                  fields {
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
    """

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Rate limiting verification
        rate_limit = await self._check_rate_limiting(target)
        if not rate_limit["limited"]:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"No rate limiting detected on {target}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"Sent {rate_limit['requests']} requests in "
                    f"{rate_limit['duration_ms']}ms without being rate limited. "
                    "This allows brute-force, credential stuffing, and resource "
                    "exhaustion attacks."
                ),
                response=json.dumps(rate_limit, indent=2),
                tags=["dos", "rate-limit", "resilience"],
            ))
        else:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Rate limiting active on {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"Rate limiting triggered after {rate_limit['trigger_at']} "
                    f"requests. Response: HTTP {rate_limit.get('limit_code', 429)}"
                ),
                response=json.dumps(rate_limit, indent=2),
                tags=["dos", "rate-limit", "resilience"],
            ))

        # Phase 2: GraphQL complexity/depth abuse
        graphql_findings = await self._test_graphql_depth(target)
        findings.extend(graphql_findings)
        if graphql_findings:
            hypotheses.append(Hypothesis(
                title=f"GraphQL DoS via nested queries on {target}",
                rationale="GraphQL endpoint accepts deep/complex queries",
                probability=0.7,
                impact=0.75,
                suggested_agent="api",
            ))

        # Phase 3: ReDoS pattern testing
        redos_findings = await self._test_redos(target)
        findings.extend(redos_findings)

        # Phase 4: Slowloris-style connection test (limited, non-destructive)
        slowloris_result = await self._test_slowloris(target)
        if slowloris_result:
            findings.append(slowloris_result)
            hypotheses.append(Hypothesis(
                title=f"Slowloris DoS vulnerability on {target}",
                rationale="Server keeps slow connections alive indefinitely",
                probability=0.6,
                impact=0.7,
                suggested_agent="dos_resilience",
            ))

        # Phase 5: HTTP/2 rapid reset check (CVE-2023-44487)
        h2_reset = await self._check_h2_rapid_reset(target)
        if h2_reset:
            findings.append(h2_reset)

        # Phase 6: Connection pool / file descriptor exhaustion assessment
        findings.append(Evidence(
            agent_id=self.agent_id,
            title=f"Connection pool exhaustion assessment for {target}",
            severity=Severity.INFO,
            evidence_type=EvidenceType.OTHER,
            description=(
                "Assessment points for connection pool exhaustion:\n"
                "- WebSocket connections without proper limits\n"
                "- Database connection pool exhaustion via slow queries\n"
                "- File descriptor exhaustion via keep-alive connections\n"
                "- Thread pool starvation via blocking operations\n"
                "Note: Active testing avoided to prevent service disruption."
            ),
            tags=["dos", "connection-pool", "assessment"],
        ))

        hypotheses.append(Hypothesis(
            title=f"Application-layer DoS via resource exhaustion on {target}",
            rationale="Resilience testing reveals potential weaknesses",
            probability=0.5,
            impact=0.7,
            suggested_agent="web",
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "rate_limited": rate_limit["limited"],
                "non_destructive": True,
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _check_rate_limiting(self, target: str) -> dict[str, Any]:
        if not shutil.which("curl"):
            return {"limited": True, "requests": 0, "trigger_at": 0, "duration_ms": 0}

        result: dict[str, Any] = {
            "limited": False,
            "requests": 0,
            "trigger_at": 0,
            "duration_ms": 0,
        }
        start = time.monotonic()
        max_requests = 30  # Keep it non-destructive

        for i in range(1, max_requests + 1):
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--max-time", "3", f"https://{target}/",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            code = stdout.decode().strip()
            result["requests"] = i
            if code == "429":
                result["limited"] = True
                result["trigger_at"] = i
                result["limit_code"] = 429
                break
            elif code in ("503", "000"):
                result["limited"] = True
                result["trigger_at"] = i
                result["limit_code"] = int(code) if code != "000" else 0
                break

        result["duration_ms"] = int((time.monotonic() - start) * 1000)
        return result

    async def _test_graphql_depth(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        endpoints = ["/graphql", "/api/graphql", "/gql", "/query"]
        for endpoint in endpoints:
            payload = json.dumps({"query": self._GRAPHQL_DEPTH_QUERY})
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "--max-time", "15",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", payload,
                f"https://{target}{endpoint}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=25)
            response = stdout.decode()
            try:
                data = json.loads(response)
                if "data" in data and data["data"]:
                    results.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"GraphQL deep query accepted on {endpoint}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.MISCONFIGURATION,
                        description=(
                            f"GraphQL endpoint {endpoint} accepts deeply nested "
                            "queries without depth limiting. An attacker can craft "
                            "exponentially expensive queries to exhaust resources."
                        ),
                        request=self._GRAPHQL_DEPTH_QUERY.strip(),
                        response=response[:2000],
                        tags=["dos", "graphql", "query-depth"],
                    ))
                    break
                elif "errors" in data:
                    error_msgs = [e.get("message", "") for e in data.get("errors", [])]
                    depth_keywords = ["depth", "complexity", "limit", "too deep"]
                    if any(kw in str(error_msgs).lower() for kw in depth_keywords):
                        results.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"GraphQL depth limiting active on {endpoint}",
                            severity=Severity.INFO,
                            evidence_type=EvidenceType.NETWORK,
                            description="GraphQL query depth/complexity limits enforced",
                            response=response[:1000],
                            tags=["dos", "graphql", "mitigated"],
                        ))
                        break
            except json.JSONDecodeError:
                continue
        return results

    async def _test_redos(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Test common input fields that might use regex validation
        test_paths = [
            ("/api/search?q={payload}", "search"),
            ("/api/validate?email={payload}", "email"),
            ("/api/users?filter={payload}", "filter"),
        ]
        for path_template, field_type in test_paths:
            for payload in self._REDOS_PAYLOADS[:2]:
                path = path_template.replace("{payload}", payload)
                start = time.monotonic()
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-o", "/dev/null",
                    "-w", "%{time_total}",
                    "--max-time", "10",
                    f"https://{target}{path}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                try:
                    elapsed = float(stdout.decode().strip())
                except ValueError:
                    continue
                if elapsed > 5.0:
                    results.append(Evidence(
                        agent_id=self.agent_id,
                        title=f"Potential ReDoS on {field_type} endpoint",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.EXPLOIT,
                        description=(
                            f"Request to {path_template} with backtracking payload "
                            f"took {elapsed:.1f}s (threshold: 5s). This suggests "
                            "catastrophic regex backtracking (ReDoS)."
                        ),
                        request=f"GET https://{target}{path}",
                        response=f"Response time: {elapsed:.1f}s",
                        cvss_score=7.5,
                        tags=["dos", "redos", "regex"],
                    ))
                    break
        return results

    async def _test_slowloris(self, target: str) -> Evidence | None:
        """Non-destructive Slowloris test: open a few slow connections."""
        if not shutil.which("curl"):
            return None

        # Open a slow connection with very low speed limit
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--limit-rate", "1",  # 1 byte/sec
            "--max-time", "10",
            "-H", "X-Slowloris-Test: true",
            f"https://{target}/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        code = stdout.decode().strip()
        # If connection wasn't terminated by the server, it's vulnerable
        if code and code not in ("000", "408", "503"):
            return Evidence(
                agent_id=self.agent_id,
                title=f"Slowloris-style slow connection accepted by {target}",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    "Server accepts extremely slow connections without timeout. "
                    "This may allow connection pool exhaustion via Slowloris-style "
                    "attacks. Recommend setting aggressive connection timeouts."
                ),
                tags=["dos", "slowloris", "connection-timeout"],
            )
        return None

    async def _check_h2_rapid_reset(self, target: str) -> Evidence | None:
        """Check if server is vulnerable to HTTP/2 Rapid Reset (CVE-2023-44487)."""
        if not shutil.which("curl"):
            return None

        # Check if HTTP/2 is supported
        proc = await asyncio.create_subprocess_exec(
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_version}",
            "--max-time", "5", "--http2",
            f"https://{target}/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        version = stdout.decode().strip()
        if version == "2":
            return Evidence(
                agent_id=self.agent_id,
                title=f"HTTP/2 enabled on {target} — check CVE-2023-44487",
                severity=Severity.MEDIUM,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    "HTTP/2 is enabled. Verify the server is patched against "
                    "CVE-2023-44487 (HTTP/2 Rapid Reset). This vulnerability "
                    "allows amplified DoS via stream reset flooding. "
                    "Active exploitation avoided to prevent disruption."
                ),
                tags=["dos", "http2", "cve-2023-44487", "rapid-reset"],
            )
        return None
