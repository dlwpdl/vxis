"""Internal helpers for API security attack execution loops."""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any

from ._api_security_crown import _baseline_token_from_identities
from ._api_security_crown import _verify_mass_assignment_login
from ._api_security_crown import _verify_self_write_mass_assignment
from ._api_security_self_write import _adapt_self_write_body
from .attempt_auth import _discover_asset_auth_paths

logger = logging.getLogger(__name__)

_REGISTRATION_PATHS = ["/api/users", "/api/register", "/api/signup", "/api/account"]
_RATE_LIMIT_PATHS = ["/api/login", "/api/auth/login", "/login"]
_VERB_TAMPER_METHODS = ["GET", "PUT", "DELETE", "PATCH", "OPTIONS"]


def _is_privileged_mass_assign_field(field_info: dict[str, Any]) -> bool:
    blob = f"{field_info.get('field') or ''} {field_info.get('value') or ''}".lower()
    return any(
        token in blob
        for token in ("role", "admin", "isadmin", "is_admin", "privilege", "permission", "staff")
    )


async def _registration_paths(session: Any) -> list[str]:
    paths = list(_REGISTRATION_PATHS)
    try:
        for path in await _discover_asset_auth_paths(session):
            lower = path.lower()
            if any(marker in lower for marker in ("signup", "register")) and path not in paths:
                paths.append(path)
    except Exception:
        pass
    return paths


async def _run_mass_assignment_checks(
    session: Any,
    *,
    target: str,
    auth_headers: dict[str, str],
    mass_assign_fields: list[dict[str, Any]],
    self_write_candidates: list[dict[str, Any]],
    self_write_seed_values: dict[str, str],
    privileged_probe_paths: list[Any],
    login_paths: list[str],
    foothold_token: str | None,
    identities: Any,
) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)
    reg_paths = await _registration_paths(session)

    for path in reg_paths:
        for field_info in mass_assign_fields:
            tested += 1
            async with sem:
                try:
                    suffix = secrets.token_hex(4)
                    username = f"user_{suffix}"
                    email = f"{suffix}@example.test"
                    password = f"Test1234!{suffix}"
                    body = {
                        "username": username,
                        "email": email,
                        "password": password,
                        field_info["field"]: field_info["value"],
                    }
                    response = await session.request(
                        "POST",
                        f"{target}{path}",
                        json_data=body,
                        headers=auth_headers,
                    )
                    if response.status not in (200, 201):
                        continue
                    response_text = response.text.lower()
                    if (
                        field_info["field"].lower() not in response_text
                        or field_info["value"].lower() not in response_text
                    ):
                        continue
                    evidence = f"{field_info['desc']}: field accepted (status {response.status})"
                    finding = {
                        "type": "mass_assignment",
                        "payload": f"{field_info['field']}={field_info['value']} on {path}",
                        "endpoint": path,
                        "evidence": evidence,
                        "response_preview": response.text[:300],
                        "severity": "high",
                    }
                    privilege_blob = f"{field_info['field']} {field_info['value']}".lower()
                    if any(
                        token in privilege_blob
                        for token in ("role", "admin", "isadmin", "is_admin", "privilege")
                    ):
                        finding["control"] = (
                            "A self-service account flow should ignore or reject privileged "
                            "fields such as role/admin."
                        )
                        baseline_account: dict[str, str] | None = None
                        control_suffix = secrets.token_hex(4)
                        control_account = {
                            "email": f"{control_suffix}@example.test",
                            "password": f"Test1234!{control_suffix}",
                            "username": f"user_{control_suffix}",
                        }
                        try:
                            baseline_registration = await session.request(
                                "POST",
                                f"{target}{path}",
                                json_data=control_account,
                                headers=auth_headers,
                            )
                            if baseline_registration.status in (200, 201):
                                baseline_account = control_account
                        except Exception:
                            baseline_account = None
                        credential_evidence = await _verify_mass_assignment_login(
                            session,
                            target=target,
                            registration_path=path,
                            email=email,
                            username=username,
                            password=password,
                            persisted_role=str(field_info["value"]),
                            foothold_token=foothold_token,
                            baseline_account=baseline_account,
                            candidate_paths=privileged_probe_paths,
                            login_paths=login_paths,
                        )
                        if credential_evidence:
                            finding["credential_evidence"] = credential_evidence
                            finding["evidence"] = (
                                f"{evidence}; relogin succeeded via "
                                f"{credential_evidence['login_endpoint']}"
                            )
                            privileged_access = credential_evidence.get("privileged_access_proof") or {}
                            if privileged_access:
                                baseline_status = (
                                    privileged_access.get("baseline_status")
                                    or privileged_access.get("noauth_status")
                                )
                                finding["evidence"] += (
                                    f"; privileged probe {privileged_access.get('endpoint', '')} "
                                    f"{baseline_status}->{privileged_access.get('elevated_status', '')}"
                                )
                    findings.append(finding)
                    logger.info("Mass assignment: %s on %s", field_info["field"], path)
                except Exception:
                    pass

    baseline_token = _baseline_token_from_identities(foothold_token, identities)
    for candidate in self_write_candidates:
        for field_info in mass_assign_fields:
            if not _is_privileged_mass_assign_field(field_info):
                continue
            tested += 1
            async with sem:
                try:
                    body = dict(candidate.get("json_body") or {})
                    body[str(field_info["field"])] = field_info["value"]
                    response = await session.request(
                        str(candidate.get("method") or "POST"),
                        f"{target}{candidate['path']}",
                        json_data=body,
                        headers=auth_headers or None,
                    )
                    if response.status in (400, 422):
                        adapted_body = _adapt_self_write_body(
                            candidate["path"],
                            body,
                            getattr(response, "text", ""),
                            seed_values=self_write_seed_values,
                        )
                        if adapted_body and adapted_body != body:
                            body = adapted_body
                            response = await session.request(
                                str(candidate.get("method") or "POST"),
                                f"{target}{candidate['path']}",
                                json_data=body,
                                headers=auth_headers or None,
                            )
                    if response.status not in (200, 201, 202):
                        continue
                    response_text = response.text.lower()
                    field_reflected = (
                        field_info["field"].lower() in response_text
                        and field_info["value"].lower() in response_text
                    )
                    credential_evidence = await _verify_self_write_mass_assignment(
                        session,
                        target=target,
                        candidate=candidate,
                        request_body=body,
                        response=response,
                        field_info=field_info,
                        foothold_token=foothold_token,
                        baseline_token=baseline_token,
                        candidate_paths=privileged_probe_paths,
                        seed_values=self_write_seed_values,
                        login_paths=login_paths,
                    )
                    if not field_reflected and not credential_evidence:
                        continue
                    evidence = (
                        f"{field_info['desc']}: field accepted on authenticated self-write surface "
                        f"(status {response.status})"
                        if field_reflected
                        else (
                            f"{field_info['desc']}: authenticated self-write mutation preserved "
                            f"crown proof after adaptive request shaping (status {response.status})"
                        )
                    )
                    finding = {
                        "type": "mass_assignment",
                        "payload": f"{field_info['field']}={field_info['value']} on {candidate['path']}",
                        "endpoint": candidate["path"],
                        "method": str(candidate.get("method") or "POST"),
                        "evidence": evidence,
                        "response_preview": response.text[:300],
                        "severity": "high",
                        "control": (
                            "An authenticated self-service mutation should ignore or reject "
                            "privileged fields such as role/admin."
                        ),
                    }
                    if credential_evidence:
                        finding["credential_evidence"] = credential_evidence
                        privileged_access = credential_evidence.get("privileged_access_proof") or {}
                        finding["evidence"] += (
                            f"; privileged probe {privileged_access.get('endpoint', '')} "
                            f"{privileged_access.get('baseline_status') or privileged_access.get('noauth_status')}->"
                            f"{privileged_access.get('elevated_status', '')}"
                        )
                    findings.append(finding)
                    logger.info("Mass assignment: %s on %s", field_info["field"], candidate["path"])
                    break
                except Exception:
                    pass

    return findings, tested


async def _run_protocol_checks(
    session: Any,
    *,
    target: str,
    auth_headers: dict[str, str],
    verb_tamper_paths: list[str],
) -> tuple[list[dict[str, Any]], int]:
    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    for path in _RATE_LIMIT_PATHS:
        tested += 1
        async with sem:
            statuses: list[int] = []
            try:
                for _ in range(10):
                    response = await session.request(
                        "POST",
                        f"{target}{path}",
                        json_data={"username": "admin", "password": "wrong"},
                        headers=auth_headers,
                    )
                    statuses.append(response.status)
                if 429 not in statuses and any(status not in (404, 405) for status in statuses):
                    findings.append(
                        {
                            "type": "no_rate_limit",
                            "payload": f"10 rapid requests to {path}",
                            "evidence": f"No 429 response after 10 attempts. Statuses: {statuses}",
                            "severity": "medium",
                        }
                    )
            except Exception:
                pass

    async def test_verb(path: str) -> tuple[list[dict[str, Any]], int]:
        checked = 0
        path_findings: list[dict[str, Any]] = []
        async with sem:
            accessible: list[str] = []
            for method in _VERB_TAMPER_METHODS:
                checked += 1
                try:
                    response = await session.request(method, f"{target}{path}", headers=auth_headers)
                    if response.status not in (404, 405, 401, 403):
                        accessible.append(f"{method}({response.status})")
                except Exception:
                    pass
            if len(accessible) >= 3:
                path_findings.append(
                    {
                        "type": "verb_tampering",
                        "payload": f"Multiple methods on {path}",
                        "evidence": f"Accepted: {', '.join(accessible)}",
                        "severity": "medium",
                    }
                )
        return path_findings, checked

    verb_results = await asyncio.gather(*(test_verb(path) for path in verb_tamper_paths))
    for path_findings, checked in verb_results:
        tested += checked
        findings.extend(path_findings)

    tested += 1
    async with sem:
        try:
            response = await session.request(
                "GET",
                f"{target}/api/users?id=1&id=2",
                headers=auth_headers,
            )
            if response.status == 200:
                findings.append(
                    {
                        "type": "param_pollution",
                        "payload": "id=1&id=2",
                        "evidence": f"Duplicate params accepted (status {response.status})",
                        "response_preview": response.text[:300],
                        "severity": "low",
                    }
                )
        except Exception:
            pass

    return findings, tested
