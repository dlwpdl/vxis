"""Skill: test_api_security — mass assignment, rate limiting, verb tampering, param pollution."""
from __future__ import annotations
import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)

MASS_ASSIGN_FIELDS: list[dict[str, str]] = [
    {"field": "role", "value": "admin", "desc": "Role escalation"},
    {"field": "isAdmin", "value": "true", "desc": "Admin flag"},
    {"field": "is_staff", "value": "true", "desc": "Staff flag"},
    {"field": "verified", "value": "true", "desc": "Email verification bypass"},
    {"field": "balance", "value": "999999", "desc": "Balance manipulation"},
    {"field": "discount", "value": "100", "desc": "Discount override"},
    {"field": "price", "value": "0", "desc": "Price override"},
    {"field": "permissions", "value": "all", "desc": "Permissions escalation"},
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]

VERB_TAMPER_PATHS = [
    "/api/users",
    "/api/admin",
    "/api/config",
    "/api/settings",
    "/api/roles",
    "/api/permissions",
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]


async def execute(target_url: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test API security: mass assignment, rate limiting, verb tampering.

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
        # --- Mass assignment ---
        reg_paths = ["/api/users", "/api/register", "/api/signup", "/api/account"]
        for path in reg_paths:
            for field_info in MASS_ASSIGN_FIELDS:
                tested += 1
                async with sem:
                    try:
                        body = {"username": "testuser", "email": "test@test.com",
                                "password": "Test1234!", field_info["field"]: field_info["value"]}
                        r = await client.post(f"{target}{path}", json=body, headers=auth_headers)
                        if r.status_code in (200, 201):
                            resp = r.text.lower()
                            if field_info["field"].lower() in resp and field_info["value"].lower() in resp:
                                findings.append({
                                    "type": "mass_assignment",
                                    "payload": f"{field_info['field']}={field_info['value']} on {path}",
                                    "evidence": f"{field_info['desc']}: field accepted (status {r.status_code})",
                                    "response_preview": r.text[:300],
                                    "severity": "high",
                                })
                                logger.info("Mass assignment: %s on %s", field_info["field"], path)
                    except Exception:
                        pass

        # --- Rate limiting ---
        rate_paths = ["/api/login", "/api/auth/login", "/login"]
        for path in rate_paths:
            tested += 1
            async with sem:
                statuses = []
                try:
                    for _ in range(10):
                        r = await client.post(
                            f"{target}{path}",
                            json={"username": "admin", "password": "wrong"},
                            headers=auth_headers,
                        )
                        statuses.append(r.status_code)
                    if 429 not in statuses and all(s != 404 for s in statuses):
                        findings.append({
                            "type": "no_rate_limit",
                            "payload": f"10 rapid requests to {path}",
                            "evidence": f"No 429 response after 10 attempts. Statuses: {statuses}",
                            "severity": "medium",
                        })
                except Exception:
                    pass

        # --- HTTP verb tampering ---
        async def test_verb(path: str) -> None:
            nonlocal tested
            async with sem:
                methods = ["GET", "PUT", "DELETE", "PATCH", "OPTIONS"]
                accessible: list[str] = []
                for method in methods:
                    tested += 1
                    try:
                        r = await client.request(method, f"{target}{path}", headers=auth_headers)
                        if r.status_code not in (404, 405, 401, 403):
                            accessible.append(f"{method}({r.status_code})")
                    except Exception:
                        pass
                if len(accessible) >= 3:
                    findings.append({
                        "type": "verb_tampering",
                        "payload": f"Multiple methods on {path}",
                        "evidence": f"Accepted: {', '.join(accessible)}",
                        "severity": "medium",
                    })

        await asyncio.gather(*[test_verb(p) for p in VERB_TAMPER_PATHS])

        # --- Parameter pollution ---
        tested += 1
        async with sem:
            try:
                r = await client.get(f"{target}/api/users?id=1&id=2", headers=auth_headers)
                if r.status_code == 200:
                    findings.append({
                        "type": "param_pollution",
                        "payload": "id=1&id=2",
                        "evidence": f"Duplicate params accepted (status {r.status_code})",
                        "response_preview": r.text[:300],
                        "severity": "low",
                    })
            except Exception:
                pass

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
