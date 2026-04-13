"""Skill: test_idor — test Insecure Direct Object Reference."""
from __future__ import annotations
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


async def execute(url_pattern: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test IDOR by iterating IDs on an endpoint.

    url_pattern should contain {id}, e.g. http://target/api/Users/{id}

    Tests:
    1. Sequential ID access (1-20)
    2. With/without auth token comparison
    3. Cross-user data access detection

    Returns:
        {
            "vulnerable": bool,
            "accessible_ids": [int, ...],
            "auth_bypass_ids": [int, ...],  # accessible without token
            "data_samples": [{"id": int, "preview": str}, ...],
            "total_tested": int,
        }
    """
    import httpx

    accessible_ids: list[int] = []
    auth_bypass_ids: list[int] = []
    data_samples: list[dict] = []
    max_id = int(kwargs.get("max_id", 20))

    headers_auth = {}
    if token:
        headers_auth = {"Authorization": f"Bearer {token}", "Cookie": f"token={token}"}

    async with httpx.AsyncClient(timeout=10, verify=False,
                                  limits=httpx.Limits(max_connections=15)) as c:
        sem = asyncio.Semaphore(15)

        async def check(uid: int) -> None:
            async with sem:
                url = url_pattern.replace("{id}", str(uid))
                try:
                    # With auth
                    if headers_auth:
                        r_auth = await c.get(url, headers=headers_auth)
                        if r_auth.status_code == 200:
                            accessible_ids.append(uid)
                            if uid <= 5:
                                data_samples.append({
                                    "id": uid, "preview": r_auth.text[:300],
                                })

                    # Without auth
                    r_noauth = await c.get(url)
                    if r_noauth.status_code == 200 and len(r_noauth.content) > 50:
                        auth_bypass_ids.append(uid)
                except Exception:
                    pass

        await asyncio.gather(*[check(i) for i in range(1, max_id + 1)])

    accessible_ids.sort()
    auth_bypass_ids.sort()

    vulnerable = len(accessible_ids) > 1 or len(auth_bypass_ids) > 0

    logger.info("test_idor: %d accessible, %d without auth, vulnerable=%s",
                len(accessible_ids), len(auth_bypass_ids), vulnerable)

    return {
        "vulnerable": vulnerable,
        "accessible_ids": accessible_ids,
        "auth_bypass_ids": auth_bypass_ids,
        "data_samples": data_samples,
        "total_tested": max_id,
        "url_pattern": url_pattern,
    }
