"""EconomyTesterPlugin — 게임 경제 조작 벡터 테스트.

가상 통화, 아이템, 거래 시스템의 보안 취약점을 체계적으로 테스트.

공격 벡터:
    1. 음수 금액 거래 (Negative Amount)
    2. 정수 오버플로우 / 언더플로우
    3. 아이템 복제 (Race Condition)
    4. 서버 측 가격 검증 부재 (Price Tampering)
    5. 통화 롤백 (Transaction Rollback)
    6. 대량 구매 한도 우회 (Purchase Limit Bypass)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

logger = logging.getLogger(__name__)


class EconomyTesterPlugin(BasePlugin):
    """게임 경제 조작 취약점 테스터.

    tool_binary는 "curl"로 설정 (HTTP 테스트에 사용 가능).
    """

    _meta = PluginMeta(
        name="economy_tester",
        version="1.0.0",
        tool_binary="curl",
        category="game",
        tier=2,  # 실제 API 요청 발생
        produces=("economy_vulnerabilities", "manipulation_vectors"),
        timeout_seconds=600,
    )

    @property
    def meta(self) -> PluginMeta:
        return self._meta

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        """Economy API 프로브 명령어."""
        economy_endpoint = tool_config.get("economy_endpoint", "/api/v1/purchase")
        return (
            f'curl -s -X POST "{target}{economy_endpoint}" '
            f'-H "Content-Type: application/json" '
            f'-d \'{{"amount": -1, "item_id": "test"}}\' '
            f'-w "\\nHTTP_STATUS:%{{http_code}}"'
        )

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """curl 출력 파싱."""
        findings: list[dict[str, Any]] = []
        status_code = 0

        if "HTTP_STATUS:" in raw_stdout:
            parts = raw_stdout.rsplit("HTTP_STATUS:", 1)
            parts[0].strip()
            try:
                status_code = int(parts[1].strip())
            except ValueError:
                pass

            if status_code in (200, 201):
                findings.append({
                    "type": "negative_amount_accepted",
                    "severity": "critical",
                    "description": "Server accepted negative transaction amount",
                    "response_status": status_code,
                })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"status_code": status_code},
            findings=findings,
        )

    # ── 핵심 테스트 메서드 ──────────────────────────────────────────

    async def run_full_economy_test(
        self,
        base_url: str,
        transaction_endpoints: list[str],
        auth_headers: dict[str, str] | None = None,
        item_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        """전체 경제 취약점 테스트 스위트 실행.

        Args:
            base_url: 게임 서버 베이스 URL.
            transaction_endpoints: 거래 API 엔드포인트 목록.
            auth_headers: 인증 헤더 (있으면 인증된 사용자로 테스트).
            item_ids: 테스트할 아이템 ID 목록.

        Returns:
            발견된 취약점 및 테스트 결과 딕셔너리.
        """
        results: dict[str, Any] = {
            "vulnerabilities": [],
            "test_summary": {},
            "tested_endpoints": [],
        }

        test_items = item_ids or ["sword_001", "gem_pack_100", "armor_001", "potion_001"]

        for endpoint in transaction_endpoints[:10]:
            endpoint_results: dict[str, Any] = {
                "endpoint": endpoint,
                "tests": [],
            }

            # 1. 음수 금액 테스트
            neg_result = await self._test_negative_amount(
                base_url, endpoint, test_items[0], auth_headers
            )
            endpoint_results["tests"].append(neg_result)
            if neg_result.get("vulnerable"):
                results["vulnerabilities"].append({
                    "type": "negative_amount",
                    "endpoint": endpoint,
                    "severity": "critical",
                    "detail": neg_result,
                })

            # 2. 정수 오버플로우 테스트
            overflow_result = await self._test_integer_overflow(
                base_url, endpoint, test_items[0], auth_headers
            )
            endpoint_results["tests"].append(overflow_result)
            if overflow_result.get("vulnerable"):
                results["vulnerabilities"].append({
                    "type": "integer_overflow",
                    "endpoint": endpoint,
                    "severity": "high",
                    "detail": overflow_result,
                })

            # 3. 가격 변조 테스트
            price_result = await self._test_price_tampering(
                base_url, endpoint, test_items, auth_headers
            )
            endpoint_results["tests"].append(price_result)
            if price_result.get("vulnerable"):
                results["vulnerabilities"].append({
                    "type": "price_tampering",
                    "endpoint": endpoint,
                    "severity": "critical",
                    "detail": price_result,
                })

            # 4. 경쟁 조건 (아이템 복제) 테스트
            race_result = await self._test_race_condition(
                base_url, endpoint, test_items[0], auth_headers
            )
            endpoint_results["tests"].append(race_result)
            if race_result.get("vulnerable"):
                results["vulnerabilities"].append({
                    "type": "race_condition",
                    "endpoint": endpoint,
                    "severity": "critical",
                    "detail": race_result,
                })

            # 5. 구매 한도 우회 테스트
            limit_result = await self._test_purchase_limit_bypass(
                base_url, endpoint, test_items[0], auth_headers
            )
            endpoint_results["tests"].append(limit_result)
            if limit_result.get("vulnerable"):
                results["vulnerabilities"].append({
                    "type": "limit_bypass",
                    "endpoint": endpoint,
                    "severity": "medium",
                    "detail": limit_result,
                })

            results["tested_endpoints"].append(endpoint_results)

        results["test_summary"] = {
            "total_endpoints": len(transaction_endpoints),
            "tested": len(results["tested_endpoints"]),
            "vulnerabilities_found": len(results["vulnerabilities"]),
            "critical": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "critical"),
            "high": sum(1 for v in results["vulnerabilities"] if v.get("severity") == "high"),
        }

        return results

    async def _test_negative_amount(
        self,
        base_url: str,
        endpoint: str,
        item_id: str,
        auth_headers: dict[str, str] | None,
    ) -> dict[str, Any]:
        """음수 금액 거래 테스트."""
        import httpx

        payloads = [
            {"amount": -1, "quantity": -1, "item_id": item_id},
            {"amount": -9999, "item_id": item_id, "price": -100},
            {"gold": -1000, "item_id": item_id},
        ]

        for payload in payloads:
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    headers = {"Content-Type": "application/json"}
                    if auth_headers:
                        headers.update(auth_headers)
                    resp = await client.post(f"{base_url}{endpoint}", json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        return {
                            "test": "negative_amount",
                            "vulnerable": True,
                            "payload": payload,
                            "status": resp.status_code,
                            "response_preview": resp.text[:200],
                        }
            except Exception:
                pass

        return {"test": "negative_amount", "vulnerable": False}

    async def _test_integer_overflow(
        self,
        base_url: str,
        endpoint: str,
        item_id: str,
        auth_headers: dict[str, str] | None,
    ) -> dict[str, Any]:
        """정수 오버플로우 테스트."""
        import httpx

        overflow_values = [
            2147483648,   # INT32_MAX + 1
            4294967296,   # UINT32_MAX + 1
            9223372036854775808,  # INT64_MAX + 1
            -2147483649,  # INT32_MIN - 1
        ]

        for val in overflow_values:
            try:
                payload = {"amount": val, "quantity": val, "item_id": item_id}
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    headers = {"Content-Type": "application/json"}
                    if auth_headers:
                        headers.update(auth_headers)
                    resp = await client.post(f"{base_url}{endpoint}", json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        return {
                            "test": "integer_overflow",
                            "vulnerable": True,
                            "overflow_value": val,
                            "status": resp.status_code,
                        }
                    # 500 오류도 취약 — 서버가 크래시됨
                    if resp.status_code == 500:
                        return {
                            "test": "integer_overflow",
                            "vulnerable": True,
                            "type": "server_crash",
                            "overflow_value": val,
                            "status": resp.status_code,
                        }
            except Exception:
                pass

        return {"test": "integer_overflow", "vulnerable": False}

    async def _test_price_tampering(
        self,
        base_url: str,
        endpoint: str,
        item_ids: list[str],
        auth_headers: dict[str, str] | None,
    ) -> dict[str, Any]:
        """가격 변조 테스트 (클라이언트 가격을 서버가 신뢰하는지)."""
        import httpx

        tampered_payloads = [
            {"item_id": item_ids[0], "price": 0, "total": 0},
            {"item_id": item_ids[0], "price": 1, "cost": 1},
            {"item_id": item_ids[0], "amount": 1, "client_price": 0},
        ]

        for payload in tampered_payloads:
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    headers = {"Content-Type": "application/json"}
                    if auth_headers:
                        headers.update(auth_headers)
                    resp = await client.post(f"{base_url}{endpoint}", json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        resp_text = resp.text.lower()
                        if any(k in resp_text for k in ["success", "purchased", "item", "inventory"]):
                            return {
                                "test": "price_tampering",
                                "vulnerable": True,
                                "payload": payload,
                                "status": resp.status_code,
                            }
            except Exception:
                pass

        return {"test": "price_tampering", "vulnerable": False}

    async def _test_race_condition(
        self,
        base_url: str,
        endpoint: str,
        item_id: str,
        auth_headers: dict[str, str] | None,
    ) -> dict[str, Any]:
        """경쟁 조건 (아이템 복제) 테스트.

        동일한 거래를 동시에 여러 번 전송하여 중복 처리 여부 확인.
        """
        import httpx

        payload = {"item_id": item_id, "quantity": 1, "action": "transfer"}
        concurrent_count = 10

        async def send_request() -> int:
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    headers = {"Content-Type": "application/json"}
                    if auth_headers:
                        headers.update(auth_headers)
                    resp = await client.post(f"{base_url}{endpoint}", json=payload, headers=headers)
                    return resp.status_code
            except Exception:
                return 0

        # 동시 요청 발송
        tasks = [send_request() for _ in range(concurrent_count)]
        statuses = await asyncio.gather(*tasks, return_exceptions=True)

        success_count = sum(1 for s in statuses if isinstance(s, int) and s in (200, 201))

        # 2개 이상 성공 → 경쟁 조건 가능성
        if success_count >= 2:
            return {
                "test": "race_condition",
                "vulnerable": True,
                "concurrent_requests": concurrent_count,
                "success_count": success_count,
                "description": f"{success_count}/{concurrent_count} concurrent requests succeeded",
            }

        return {
            "test": "race_condition",
            "vulnerable": False,
            "concurrent_requests": concurrent_count,
            "success_count": success_count,
        }

    async def _test_purchase_limit_bypass(
        self,
        base_url: str,
        endpoint: str,
        item_id: str,
        auth_headers: dict[str, str] | None,
    ) -> dict[str, Any]:
        """구매 한도 우회 테스트 (일일/총 구매 제한)."""
        import httpx

        # 비정상적으로 많은 수량
        large_quantity_payloads = [
            {"item_id": item_id, "quantity": 99999},
            {"item_id": item_id, "quantity": 1000000},
        ]

        for payload in large_quantity_payloads:
            try:
                async with httpx.AsyncClient(verify=False, timeout=10) as client:
                    headers = {"Content-Type": "application/json"}
                    if auth_headers:
                        headers.update(auth_headers)
                    resp = await client.post(f"{base_url}{endpoint}", json=payload, headers=headers)
                    if resp.status_code in (200, 201):
                        return {
                            "test": "purchase_limit_bypass",
                            "vulnerable": True,
                            "payload": payload,
                            "status": resp.status_code,
                        }
            except Exception:
                pass

        return {"test": "purchase_limit_bypass", "vulnerable": False}
