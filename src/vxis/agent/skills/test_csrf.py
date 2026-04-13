"""Skill: test_csrf — CSRF token validation and SameSite cookie testing."""
from __future__ import annotations
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

STATE_CHANGING_PATHS = [
    ("/api/users", "POST", "Create user"),
    ("/api/profile", "PUT", "Update profile"),
    ("/api/password", "POST", "Change password"),
    ("/api/transfer", "POST", "Transfer funds"),
    ("/api/settings", "POST", "Update settings"),
    ("/api/admin/users", "DELETE", "Delete user"),
    ("/api/orders", "POST", "Create order"),
    ("/api/comments", "POST", "Post comment"),
    ("/api/account", "PUT", "Update account"),
    ("/api/email", "POST", "Change email"),
    ("/profile/update", "POST", "Update profile"),
    ("/account/delete", "POST", "Delete account"),
    ("/cart/checkout", "POST", "Checkout"),
    ("/api/tokens", "POST", "Create token"),
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]


async def execute(target_url: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test CSRF protection on state-changing endpoints.

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
        # Check SameSite cookie attribute
        try:
            r = await client.get(target, headers=auth_headers)
            cookies_header = r.headers.get("set-cookie", "")
            if cookies_header and "samesite" not in cookies_header.lower():
                findings.append({
                    "type": "missing_samesite",
                    "payload": "Cookie without SameSite",
                    "evidence": f"Set-Cookie header lacks SameSite: {cookies_header[:200]}",
                    "severity": "medium",
                })
        except Exception:
            pass

        async def test_endpoint(path: str, method: str, desc: str) -> None:
            nonlocal tested
            async with sem:
                tested += 1
                url = f"{target}{path}"
                dummy_body = {"test": "csrf_probe"}

                try:
                    # Request without any CSRF token
                    if method == "POST":
                        r = await client.post(url, json=dummy_body, headers=auth_headers)
                    elif method == "PUT":
                        r = await client.put(url, json=dummy_body, headers=auth_headers)
                    elif method == "DELETE":
                        r = await client.delete(url, headers=auth_headers)
                    else:
                        return

                    # If endpoint accepts request without CSRF token (not 403/419)
                    if r.status_code not in (403, 419, 405, 404, 401):
                        # Try with wrong CSRF token
                        csrf_headers = {**auth_headers, "X-CSRF-Token": "invalid_token_12345"}
                        if method == "POST":
                            r2 = await client.post(url, json=dummy_body, headers=csrf_headers)
                        elif method == "PUT":
                            r2 = await client.put(url, json=dummy_body, headers=csrf_headers)
                        else:
                            r2 = await client.delete(url, headers=csrf_headers)

                        if r2.status_code not in (403, 419, 405, 404, 401):
                            findings.append({
                                "type": "csrf_no_protection",
                                "payload": f"{method} {path}",
                                "evidence": f"{desc}: accepted without CSRF token (status {r.status_code}), "
                                            f"accepted with invalid token (status {r2.status_code})",
                                "severity": "high",
                            })
                            logger.info("CSRF: no protection on %s %s", method, path)
                except Exception:
                    pass

        await asyncio.gather(*[test_endpoint(p, m, d) for p, m, d in STATE_CHANGING_PATHS])

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
