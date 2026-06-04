"""Skill: test_idor — test Insecure Direct Object Reference."""
from __future__ import annotations
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _as_str_set(values: Any) -> set[str]:
    if values is None:
        return set()
    if isinstance(values, (str, int)):
        return {str(values)}
    if isinstance(values, (list, tuple, set)):
        return {str(v) for v in values}
    return set()


def _principal_name(raw: dict[str, Any], index: int) -> str:
    for key in ("name", "identity", "id", "label", "email", "role"):
        value = str(raw.get(key) or "").strip()
        if value:
            return value
    return f"identity-{index + 1}"


def _normalize_principals(
    *,
    token: str | None,
    identities: Any,
    include_anonymous: bool,
) -> list[dict[str, Any]]:
    principals: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(raw: dict[str, Any]) -> None:
        name = _principal_name(raw, len(principals))
        if name in seen:
            return
        seen.add(name)
        principals.append(
            {
                "name": name,
                "role": str(raw.get("role") or ""),
                "token": str(raw.get("token") or raw.get("bearer") or ""),
                "headers": dict(raw.get("headers") or {}),
                "owned_ids": _as_str_set(
                    raw.get("owned_ids")
                    or raw.get("owner_ids")
                    or raw.get("allowed_ids")
                    or raw.get("subject_ids")
                ),
                "denied_ids": _as_str_set(
                    raw.get("denied_ids")
                    or raw.get("forbidden_ids")
                    or raw.get("blocked_ids")
                ),
            }
        )

    if include_anonymous:
        add({"name": "anonymous"})

    if isinstance(identities, dict):
        for name, value in identities.items():
            raw = dict(value or {}) if isinstance(value, dict) else {"token": value}
            raw.setdefault("name", name)
            add(raw)
    elif isinstance(identities, list):
        for item in identities:
            if isinstance(item, dict):
                add(item)

    if token and not any(p["token"] == token for p in principals):
        add({"name": "authenticated", "token": token, "role": "user"})

    return principals


def _headers_for(principal: dict[str, Any]) -> dict[str, str]:
    headers = {str(k): str(v) for k, v in dict(principal.get("headers") or {}).items()}
    token = str(principal.get("token") or "")
    if token:
        headers.setdefault("Authorization", f"Bearer {token}")
        headers.setdefault("Cookie", f"token={token}")
    return headers


def _data_bearing(status: int, size: int, preview: str, *, min_body_length: int) -> bool:
    if status != 200:
        return False
    if size >= min_body_length:
        return True
    body = str(preview or "").lower()
    return any(token in body for token in ("email", "user", "account", "order", "role", "token", "id"))


def _owner_map_from_inputs(
    owner_map: Any,
    principals: list[dict[str, Any]],
) -> dict[str, str]:
    owners: dict[str, str] = {}
    if isinstance(owner_map, dict):
        for obj_id, owner in owner_map.items():
            owners[str(obj_id)] = str(owner)
    for principal in principals:
        name = str(principal.get("name") or "")
        if not name or name == "anonymous":
            continue
        for obj_id in principal.get("owned_ids") or set():
            owners.setdefault(str(obj_id), name)
    return owners


async def execute(url_pattern: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test IDOR by iterating IDs on an endpoint.

    url_pattern should contain {id}, e.g. http://target/api/Users/{id}

    Tests:
    1. Sequential ID access (1-20)
    2. With/without auth token comparison
    3. Cross-user data access detection

    Returns:
        {
            "vulnerable": bool,
            "accessible_ids": [int, ...],
            "auth_bypass_ids": [int, ...],  # accessible without token
            "data_samples": [{"id": int, "preview": str}, ...],
            "comparisons": [{"id": int, "status_auth": int, "status_noauth": int, ...}, ...],
            "control_evidence": {"positive_cases": [...], "negative_cases": [...]},
            "total_tested": int,
        }
    """
    from vxis.interaction.hands import SessionManager
    from urllib.parse import urlparse as _urlparse

    accessible_ids: list[Any] = []
    auth_bypass_ids: list[Any] = []
    data_samples: list[dict] = []
    comparisons: list[dict[str, Any]] = []
    identity_comparisons: list[dict[str, Any]] = []
    cross_identity_access: list[dict[str, Any]] = []
    role_matrix_findings: list[dict[str, Any]] = []
    max_id = int(kwargs.get("max_id", 20))
    object_ids = kwargs.get("object_ids") or kwargs.get("ids")
    if object_ids is None:
        object_ids = list(range(1, max_id + 1))
    else:
        object_ids = list(object_ids)
        max_id = len(object_ids)
    min_body_length = int(kwargs.get("min_body_length", 20))

    identities = kwargs.get("identities") or kwargs.get("principals")
    include_anonymous = bool(kwargs.get("include_anonymous", True))
    principals = _normalize_principals(
        token=token,
        identities=identities,
        include_anonymous=include_anonymous,
    )
    owner_map = _owner_map_from_inputs(
        kwargs.get("object_owner_map") or kwargs.get("owner_map"),
        principals,
    )
    multi_identity_mode = bool(identities or owner_map)

    # Derive base URL from the url_pattern (strip path+{id} placeholder)
    _sample_url = url_pattern.replace("{id}", "1")
    _parsed = _urlparse(_sample_url)
    _base_url = f"{_parsed.scheme}://{_parsed.netloc}"

    _mgr = SessionManager()
    sessions = {
        principal["name"]: await _mgr.get_session(_base_url, identity=principal["name"])
        for principal in principals
    }
    sem = asyncio.Semaphore(15)

    async def check(uid: Any) -> None:
        async with sem:
            url = url_pattern.replace("{id}", str(uid))
            try:
                legacy_entry: dict[str, Any] = {"id": uid, "url": url}
                matrix_entry: dict[str, Any] = {"id": uid, "url": url, "principals": {}}
                expected_owner = owner_map.get(str(uid), "")

                for principal in principals:
                    name = str(principal["name"])
                    headers = _headers_for(principal)
                    response = await sessions[name].request(
                        "GET",
                        url,
                        headers=headers or None,
                    )
                    preview = response.text[:240]
                    record = {
                        "status": response.status,
                        "size": response.body_length,
                        "preview": preview,
                    }
                    matrix_entry["principals"][name] = record

                    if name == "anonymous":
                        legacy_entry["status_noauth"] = response.status
                        legacy_entry["size_noauth"] = response.body_length
                        legacy_entry["preview_noauth"] = preview
                        if response.status == 200 and response.body_length > 50:
                            auth_bypass_ids.append(uid)
                        continue

                    if "status_auth" not in legacy_entry:
                        legacy_entry["status_auth"] = response.status
                        legacy_entry["size_auth"] = response.body_length
                        legacy_entry["preview_auth"] = preview

                    if response.status == 200:
                        accessible_ids.append(uid)
                        if len(data_samples) < 5:
                            data_samples.append(
                                {
                                    "id": uid,
                                    "principal": name,
                                    "preview": response.text[:300],
                                }
                            )

                    is_data = _data_bearing(
                        response.status,
                        response.body_length,
                        preview,
                        min_body_length=min_body_length,
                    )
                    if expected_owner and expected_owner != name and is_data:
                        cross_identity_access.append(
                            {
                                "id": uid,
                                "requester": name,
                                "requester_role": principal.get("role", ""),
                                "expected_owner": expected_owner,
                                "status": response.status,
                                "size": response.body_length,
                                "preview": preview,
                            }
                        )
                    if str(uid) in (principal.get("denied_ids") or set()) and is_data:
                        role_matrix_findings.append(
                            {
                                "id": uid,
                                "requester": name,
                                "requester_role": principal.get("role", ""),
                                "expected": "deny",
                                "status": response.status,
                                "size": response.body_length,
                                "preview": preview,
                            }
                        )

                comparisons.append(legacy_entry)
                identity_comparisons.append(matrix_entry)
            except Exception:
                pass

    await asyncio.gather(*[check(i) for i in object_ids])

    accessible_ids = sorted(set(accessible_ids), key=str)
    auth_bypass_ids = sorted(set(auth_bypass_ids), key=str)
    comparisons.sort(key=lambda item: str(item.get("id", "")))
    identity_comparisons.sort(key=lambda item: str(item.get("id", "")))

    if multi_identity_mode:
        vulnerable = bool(auth_bypass_ids or cross_identity_access or role_matrix_findings)
    else:
        vulnerable = len(accessible_ids) > 1 or len(auth_bypass_ids) > 0
    positive_cases = [
        c for c in comparisons
        if c.get("status_auth") == 200 or c.get("status_noauth") == 200
    ][:5]
    negative_cases = [
        c for c in comparisons
        if c.get("status_noauth") in (401, 403, 404) or c.get("status_auth") in (401, 403, 404)
    ][:5]

    logger.info("test_idor: %d accessible, %d without auth, vulnerable=%s",
                len(accessible_ids), len(auth_bypass_ids), vulnerable)

    return {
        "vulnerable": vulnerable,
        "accessible_ids": accessible_ids,
        "auth_bypass_ids": auth_bypass_ids,
        "cross_identity_access": cross_identity_access[:20],
        "role_matrix_findings": role_matrix_findings[:20],
        "data_samples": data_samples,
        "comparisons": comparisons[:10],
        "identity_comparisons": identity_comparisons[:10],
        "principals": [
            {
                "name": p["name"],
                "role": p.get("role", ""),
                "has_token": bool(p.get("token")),
                "owned_ids": sorted(p.get("owned_ids") or [], key=str),
                "denied_ids": sorted(p.get("denied_ids") or [], key=str),
            }
            for p in principals
        ],
        "control_evidence": {
            "positive_cases": positive_cases,
            "negative_cases": negative_cases,
            "cross_identity_access": cross_identity_access[:5],
            "role_matrix_findings": role_matrix_findings[:5],
        },
        "total_tested": max_id,
        "url_pattern": url_pattern,
    }
