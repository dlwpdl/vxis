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
            "control_evidence": {"auth_only": [...], "same_data_without_auth": [...]},
            "total_tested": int,
        }
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    auth_headers = {"Authorization": f"Bearer {token}", "Cookie": f"token={token}"}

    accessible: list[dict] = []
    new_endpoints: list[dict] = []
    user_data_exposed: list[dict] = []
    auth_only: list[dict] = []
    same_data_without_auth: list[dict] = []

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)
    sem = asyncio.Semaphore(15)

    async def check(path: str) -> None:
        async with sem:
            try:
                # Test with auth
                r_auth = await _session.request("GET", path, headers=auth_headers)
                if r_auth.status == 404:
                    return

                # Test without auth
                r_noauth = await _session.request("GET", path)

                entry = {
                    "path": path,
                    "status_auth": r_auth.status,
                    "status_noauth": r_noauth.status,
                    "size_auth": r_auth.body_length,
                    "size_noauth": r_noauth.body_length,
                    "preview_auth": r_auth.text[:240],
                    "preview_noauth": r_noauth.text[:240],
                }

                if r_auth.status == 200:
                    entry["preview"] = r_auth.text[:300]
                    accessible.append(entry)

                    # Detect broken access control: should need auth but doesn't
                    if r_noauth.status == 200 and r_noauth.text == r_auth.text:
                        entry["issue"] = "no_auth_required"
                        same_data_without_auth.append(entry)

                    # Detect IDOR-able data
                    body = r_auth.text.lower()
                    if any(kw in body for kw in ["email", "password", "role", "token", "secret"]):
                        user_data_exposed.append(entry)

                # Track newly accessible (auth unlocks)
                if r_auth.status == 200 and r_noauth.status == 401:
                    new_endpoints.append(entry)
                    auth_only.append(entry)

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
        "control_evidence": {
            "auth_only": auth_only[:5],
            "same_data_without_auth": same_data_without_auth[:5],
        },
        "total_tested": len(AUTH_PATHS),
    }
