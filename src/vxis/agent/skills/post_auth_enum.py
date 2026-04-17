"""Skill: post_auth_enum — enumerate all endpoints with an auth token."""
from __future__ import annotations
import asyncio
import logging
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

AUTH_PATHS = _load_ds("post_auth_enum", "auth_paths")  # ADR-007 Phase 3-9 — data in data/payloads/post_auth_enum.json


async def execute(target_url: str, token: str, **kwargs: Any) -> dict[str, Any]:
    """Enumerate authenticated endpoints and detect access control issues.

    Returns:
        {
            "accessible": [{"path", "status", "size", "was_401_without_auth"}, ...],
            "new_endpoints": [...],  # accessible WITH auth but 401 WITHOUT
            "user_data_exposed": [...],  # endpoints returning user/admin data
            "total_tested": int,
        }
    """
    import httpx

    target = target_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}", "Cookie": f"token={token}"}

    accessible: list[dict] = []
    new_endpoints: list[dict] = []
    user_data_exposed: list[dict] = []

    async with httpx.AsyncClient(base_url=target, timeout=10, verify=False,
                                  limits=httpx.Limits(max_connections=15)) as c:
        sem = asyncio.Semaphore(15)

        async def check(path: str) -> None:
            async with sem:
                try:
                    # Test with auth
                    r_auth = await c.get(path, headers=headers)
                    if r_auth.status_code == 404:
                        return

                    # Test without auth
                    r_noauth = await c.get(path)

                    entry = {
                        "path": path,
                        "status_auth": r_auth.status_code,
                        "status_noauth": r_noauth.status_code,
                        "size_auth": len(r_auth.content),
                        "size_noauth": len(r_noauth.content),
                    }

                    if r_auth.status_code == 200:
                        entry["preview"] = r_auth.text[:300]
                        accessible.append(entry)

                        # Detect broken access control: should need auth but doesn't
                        if r_noauth.status_code == 200 and r_noauth.text == r_auth.text:
                            entry["issue"] = "no_auth_required"

                        # Detect IDOR-able data
                        body = r_auth.text.lower()
                        if any(kw in body for kw in ["email", "password", "role", "token", "secret"]):
                            user_data_exposed.append(entry)

                    # Track newly accessible (auth unlocks)
                    if r_auth.status_code == 200 and r_noauth.status_code == 401:
                        new_endpoints.append(entry)

                except Exception:
                    pass

        await asyncio.gather(*[check(p) for p in AUTH_PATHS])

    accessible.sort(key=lambda x: x.get("size_auth", 0), reverse=True)

    logger.info("post_auth_enum: %d accessible, %d new (auth-only), %d with user data",
                len(accessible), len(new_endpoints), len(user_data_exposed))

    return {
        "accessible": accessible,
        "new_endpoints": new_endpoints,
        "user_data_exposed": user_data_exposed,
        "total_tested": len(AUTH_PATHS),
    }
