"""Skill: test_business_logic — negative quantities, price manipulation, state skipping."""
from __future__ import annotations
import asyncio
import logging
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

LOGIC_TESTS = _load_ds("test_business_logic", "logic_tests")  # ADR-007 Phase 3-9 — data in data/payloads/test_business_logic.json


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
