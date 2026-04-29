"""Skill: test_api_security — mass assignment, rate limiting, verb tampering, param pollution."""
from __future__ import annotations
import asyncio
import logging
import time
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

MASS_ASSIGN_FIELDS = _load_ds("test_api_security", "mass_assign_fields")  # ADR-007 Phase 3-9 — data in data/payloads/test_api_security.json

VERB_TAMPER_PATHS = _load_ds("test_api_security", "verb_tamper_paths")  # ADR-007 Phase 3-9 — data in data/payloads/test_api_security.json


async def execute(target_url: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test API security: mass assignment, rate limiting, verb tampering.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int}
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    auth_headers: dict[str, str] = {}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)

    # --- Mass assignment ---
    reg_paths = ["/api/users", "/api/register", "/api/signup", "/api/account"]
    for path in reg_paths:
        for field_info in MASS_ASSIGN_FIELDS:
            tested += 1
            async with sem:
                try:
                    body = {"username": "testuser", "email": "test@test.com",
                            "password": "Test1234!", field_info["field"]: field_info["value"]}
                    r = await _session.request(
                        "POST", f"{target}{path}", json_data=body, headers=auth_headers
                    )
                    if r.status in (200, 201):
                        resp = r.text.lower()
                        if field_info["field"].lower() in resp and field_info["value"].lower() in resp:
                            findings.append({
                                "type": "mass_assignment",
                                "payload": f"{field_info['field']}={field_info['value']} on {path}",
                                "evidence": f"{field_info['desc']}: field accepted (status {r.status})",
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
                    r = await _session.request(
                        "POST",
                        f"{target}{path}",
                        json_data={"username": "admin", "password": "wrong"},
                        headers=auth_headers,
                    )
                    statuses.append(r.status)
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
                    r = await _session.request(method, f"{target}{path}", headers=auth_headers)
                    if r.status not in (404, 405, 401, 403):
                        accessible.append(f"{method}({r.status})")
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
            r = await _session.request(
                "GET", f"{target}/api/users?id=1&id=2", headers=auth_headers
            )
            if r.status == 200:
                findings.append({
                    "type": "param_pollution",
                    "payload": "id=1&id=2",
                    "evidence": f"Duplicate params accepted (status {r.status})",
                    "response_preview": r.text[:300],
                    "severity": "low",
                })
        except Exception:
            pass

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
