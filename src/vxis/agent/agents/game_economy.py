"""GameEconomyAgent — 게임 경제 분석 및 익스플로잇 에이전트.

가상 경제 시스템의 보안 취약점을 체계적으로 탐색.
통화 조작, 아이템 복제, 가격 변조, 경쟁 조건 등을 자동 탐지.
"""

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
class GameEconomyAgent(BaseAgent):
    agent_id = "game_economy"
    description = (
        "Game economy security analysis: currency manipulation, item duplication, "
        "price tampering, race conditions, transaction rollback vulnerabilities"
    )

    async def run(self, context: AgentContext) -> AgentResult:
        target = context.mission.target
        findings: list[Evidence] = []
        hypotheses: list[Hypothesis] = []

        # Phase 1: 경제 엔드포인트 탐색
        economy_endpoints = await self._discover_economy_endpoints(target)

        for ep in economy_endpoints:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Game economy endpoint: {ep['path']} [{ep.get('type')}]",
                severity=Severity.INFO,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                description=(
                    f"Economy endpoint accessible: {ep['path']} "
                    f"(type: {ep.get('type')}, status: {ep.get('status')})"
                ),
                tags=["game", "economy", ep.get("type", "transaction")],
            ))

        # Phase 2: 음수 금액 테스트
        neg_vulns = await self._test_negative_amounts(target, economy_endpoints)
        for vuln in neg_vulns:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="CRITICAL: Negative amount accepted — free currency gain",
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"Economy endpoint {vuln['endpoint']} accepted negative amount "
                    f"({vuln.get('amount')}). Free item/currency acquisition possible. "
                    f"Response: {vuln.get('response', '')[:200]}"
                ),
                request=json.dumps(vuln.get("payload", {})),
                response=vuln.get("response", ""),
                tags=["game", "economy", "negative-amount", "critical"],
            ))
            hypotheses.append(Hypothesis(
                title=f"Unlimited currency via negative amount on {target}",
                rationale=(
                    f"Endpoint {vuln['endpoint']} accepts negative values — "
                    f"attacker can gain unlimited currency by repeated negative purchases"
                ),
                probability=0.95, impact=1.0,
                suggested_agent="game_economy",
            ))

        # Phase 3: 경쟁 조건 (아이템 복제) 테스트
        race_vulns = await self._test_race_conditions(target, economy_endpoints)
        for vuln in race_vulns:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Race condition — item duplication possible at {vuln['endpoint']}",
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"Race condition in {vuln['endpoint']}: "
                    f"{vuln.get('success_count')}/{vuln.get('total_requests')} "
                    f"concurrent requests succeeded. Item duplication feasible."
                ),
                tags=["game", "economy", "race-condition", "duplication"],
            ))
            hypotheses.append(Hypothesis(
                title=f"Item duplication exploit via race condition on {target}",
                rationale=(
                    f"Concurrent requests to {vuln['endpoint']} succeed multiple times — "
                    f"item can be duplicated by simultaneous transfer requests"
                ),
                probability=0.8, impact=0.9,
                suggested_agent="game_economy",
            ))

        # Phase 4: 가격 변조 테스트
        price_vulns = await self._test_price_tampering(target, economy_endpoints)
        for vuln in price_vulns:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title="Price tampering — server trusts client-supplied price",
                severity=Severity.CRITICAL,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"Server at {vuln['endpoint']} accepted purchase with "
                    f"price={vuln.get('tampered_price')} (expected: {vuln.get('real_price')}). "
                    f"Client price is not verified server-side."
                ),
                request=json.dumps(vuln.get("payload", {})),
                response=vuln.get("response", ""),
                tags=["game", "economy", "price-tampering"],
            ))

        # Phase 5: 정수 오버플로우 테스트
        overflow_vulns = await self._test_overflow(target, economy_endpoints)
        for vuln in overflow_vulns:
            findings.append(Evidence(
                agent_id=self.agent_id,
                title=f"Integer overflow in economy endpoint: {vuln['endpoint']}",
                severity=Severity.HIGH,
                evidence_type=EvidenceType.MISCONFIGURATION,
                description=(
                    f"Integer overflow at {vuln['endpoint']}: "
                    f"value {vuln.get('overflow_value')} processed without bounds check. "
                    f"Response status: {vuln.get('status')}"
                ),
                tags=["game", "economy", "integer-overflow"],
            ))

        return AgentResult(
            agent_id=self.agent_id,
            findings=findings,
            hypotheses=hypotheses,
            status="completed",
            metadata={
                "economy_endpoints": len(economy_endpoints),
                "negative_vulns": len(neg_vulns),
                "race_vulns": len(race_vulns),
                "price_vulns": len(price_vulns),
                "overflow_vulns": len(overflow_vulns),
            },
        )

    async def _discover_economy_endpoints(self, target: str) -> list[dict[str, Any]]:
        """경제 관련 엔드포인트 탐색."""
        if not shutil.which("curl"):
            return []

        economy_paths = [
            ("/api/v1/purchase", "purchase"),
            ("/api/v1/buy", "purchase"),
            ("/api/v1/shop/buy", "purchase"),
            ("/api/v1/currency/add", "currency"),
            ("/api/v1/currency/transfer", "transfer"),
            ("/api/v1/item/transfer", "transfer"),
            ("/api/v1/trade", "trade"),
            ("/api/v1/exchange", "exchange"),
            ("/api/v1/checkout", "checkout"),
            ("/api/v1/transaction", "transaction"),
            ("/api/v1/wallet/transfer", "transfer"),
        ]

        results: list[dict[str, Any]] = []
        for path, ep_type in economy_paths:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                f"{target}{path}", "--max-time", "5", "--insecure",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
                status = stdout.decode().strip()
                if status.isdigit() and int(status) not in (404, 0):
                    results.append({
                        "path": path,
                        "type": ep_type,
                        "status": int(status),
                    })
            except asyncio.TimeoutError:
                pass

        return results

    async def _test_negative_amounts(
        self,
        target: str,
        endpoints: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """음수 금액 취약점 테스트."""
        if not shutil.which("curl"):
            return []

        vulns: list[dict[str, Any]] = []
        purchase_endpoints = [e for e in endpoints if e.get("type") in ("purchase", "transaction", "currency")]

        for ep in purchase_endpoints[:5]:
            path = ep["path"]
            payloads = [
                {"amount": -1, "item_id": "sword_001"},
                {"quantity": -1, "item_id": "gem_001"},
                {"gold": -9999, "action": "spend"},
                {"cost": -100, "item": "premium_pack"},
            ]

            for payload in payloads:
                payload_str = json.dumps(payload)
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sS", "-X", "POST",
                    f"{target}{path}",
                    "-H", "Content-Type: application/json",
                    "-d", payload_str,
                    "--max-time", "10", "--insecure",
                    "-w", "\\nHTTP_STATUS:%{http_code}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                    output = stdout.decode(errors="replace")
                    if "HTTP_STATUS:" in output:
                        parts = output.rsplit("HTTP_STATUS:", 1)
                        body = parts[0]
                        status = int(parts[1].strip()) if parts[1].strip().isdigit() else 0
                        if status in (200, 201):
                            vulns.append({
                                "endpoint": path,
                                "amount": payload.get("amount", payload.get("quantity", "N/A")),
                                "payload": payload,
                                "response": body[:300],
                                "status": status,
                            })
                            break
                except (asyncio.TimeoutError, ValueError):
                    pass

        return vulns

    async def _test_race_conditions(
        self,
        target: str,
        endpoints: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """경쟁 조건 (아이템 복제) 테스트."""
        if not shutil.which("curl"):
            return []

        vulns: list[dict[str, Any]] = []
        transfer_eps = [e for e in endpoints if e.get("type") in ("transfer", "trade")]

        for ep in transfer_eps[:2]:
            path = ep["path"]
            payload = json.dumps({"item_id": "sword_001", "quantity": 1, "to_user": "test_user"})

            async def send() -> int:
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sS", "-X", "POST",
                    f"{target}{path}",
                    "-H", "Content-Type: application/json",
                    "-d", payload,
                    "--max-time", "10", "--insecure",
                    "-w", "\\nHTTP_STATUS:%{http_code}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                    output = stdout.decode(errors="replace")
                    if "HTTP_STATUS:" in output:
                        return int(output.split("HTTP_STATUS:")[-1].strip())
                except (asyncio.TimeoutError, ValueError):
                    pass
                return 0

            tasks = [send() for _ in range(10)]
            statuses = await asyncio.gather(*tasks, return_exceptions=True)
            success = sum(1 for s in statuses if isinstance(s, int) and s in (200, 201))

            if success >= 2:
                vulns.append({
                    "endpoint": path,
                    "success_count": success,
                    "total_requests": 10,
                })

        return vulns

    async def _test_price_tampering(
        self,
        target: str,
        endpoints: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """가격 변조 취약점 테스트."""
        if not shutil.which("curl"):
            return []

        vulns: list[dict[str, Any]] = []
        purchase_eps = [e for e in endpoints if e.get("type") in ("purchase", "checkout")]

        for ep in purchase_eps[:3]:
            path = ep["path"]
            tampered = {"item_id": "premium_sword", "price": 0, "total": 0, "quantity": 1}
            payload_str = json.dumps(tampered)

            proc = await asyncio.create_subprocess_exec(
                "curl", "-sS", "-X", "POST",
                f"{target}{path}",
                "-H", "Content-Type: application/json",
                "-d", payload_str,
                "--max-time", "10", "--insecure",
                "-w", "\\nHTTP_STATUS:%{http_code}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                output = stdout.decode(errors="replace")
                if "HTTP_STATUS:" in output:
                    parts = output.rsplit("HTTP_STATUS:", 1)
                    body = parts[0].lower()
                    status = int(parts[1].strip()) if parts[1].strip().isdigit() else 0
                    if status in (200, 201) and any(
                        k in body for k in ["success", "purchased", "added", "item"]
                    ):
                        vulns.append({
                            "endpoint": path,
                            "tampered_price": 0,
                            "real_price": "unknown",
                            "payload": tampered,
                            "response": parts[0][:300],
                        })
            except (asyncio.TimeoutError, ValueError):
                pass

        return vulns

    async def _test_overflow(
        self,
        target: str,
        endpoints: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """정수 오버플로우 취약점 테스트."""
        if not shutil.which("curl"):
            return []

        vulns: list[dict[str, Any]] = []

        for ep in endpoints[:3]:
            path = ep["path"]
            overflow_payloads = [
                ({"amount": 2147483648, "item_id": "test"}, 2147483648),
                ({"quantity": 4294967296, "item_id": "test"}, 4294967296),
            ]

            for payload, overflow_val in overflow_payloads:
                payload_str = json.dumps(payload)
                proc = await asyncio.create_subprocess_exec(
                    "curl", "-sS", "-X", "POST",
                    f"{target}{path}",
                    "-H", "Content-Type: application/json",
                    "-d", payload_str,
                    "--max-time", "10", "--insecure",
                    "-w", "\\nHTTP_STATUS:%{http_code}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                    output = stdout.decode(errors="replace")
                    if "HTTP_STATUS:" in output:
                        status = int(output.split("HTTP_STATUS:")[-1].strip())
                        if status in (200, 201, 500):
                            vulns.append({
                                "endpoint": path,
                                "overflow_value": overflow_val,
                                "status": status,
                            })
                            break
                except (asyncio.TimeoutError, ValueError):
                    pass

        return vulns
