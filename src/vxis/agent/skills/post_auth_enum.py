"""Skill: post_auth_enum — enumerate all endpoints with an auth token."""
from __future__ import annotations
import asyncio
import json
import logging
import re
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

AUTH_PATHS = _load_ds("post_auth_enum", "auth_paths")  # ADR-007 Phase 3-9 — data in data/payloads/post_auth_enum.json


def _principal_name(raw: dict[str, Any], index: int) -> str:
    for key in ("name", "identity", "email", "id", "role"):
        value = str(raw.get(key) or "").strip()
        if value:
            return value[:100]
    return f"identity-{index + 1}"


def _normalize_principals(token: str, identities: Any) -> list[dict[str, Any]]:
    principals: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(raw: dict[str, Any]) -> None:
        name = _principal_name(raw, len(principals))
        if name in seen:
            return
        bearer = str(raw.get("token") or raw.get("bearer") or "").strip()
        headers = dict(raw.get("headers") or {})
        if not bearer and not headers:
            return
        seen.add(name)
        principal = {
            "name": name,
            "token": bearer,
            "role": str(raw.get("role") or ""),
            "email": str(raw.get("email") or ""),
            "headers": headers,
            "owned_ids": [str(v) for v in list(raw.get("owned_ids") or [])[:50]],
            "owned_objects": list(raw.get("owned_objects") or [])[:50],
        }
        principals.append(principal)

    if isinstance(identities, dict):
        for name, value in identities.items():
            raw = dict(value or {}) if isinstance(value, dict) else {"token": value}
            raw.setdefault("name", name)
            add(raw)
    elif isinstance(identities, list):
        for item in identities:
            if isinstance(item, dict):
                add(item)
    if token and not any(p.get("token") == token for p in principals):
        add({"name": "authenticated", "token": token, "role": "user"})
    return principals


def _headers_for(principal: dict[str, Any]) -> dict[str, str]:
    headers = {str(k): str(v) for k, v in dict(principal.get("headers") or {}).items()}
    token = str(principal.get("token") or "")
    if token:
        headers.setdefault("Authorization", f"Bearer {token}")
        headers.setdefault("Cookie", f"token={token}")
    return headers


def _json_value(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _id_values_from_json(value: Any) -> set[str]:
    ids: set[str] = set()
    id_key_re = re.compile(r"(^id$|_id$|id$|Id$|ID$)")

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                if id_key_re.search(str(key)) and isinstance(nested, (str, int)):
                    text = str(nested).strip()
                    if text and len(text) <= 80:
                        ids.add(text)
                walk(nested)
        elif isinstance(item, list):
            for nested in item[:100]:
                walk(nested)

    walk(value)
    return ids


def _id_values_from_text(text: str) -> set[str]:
    ids: set[str] = set()
    parsed = _json_value(text)
    if parsed is not None:
        ids |= _id_values_from_json(parsed)
    for match in re.finditer(
        r'"(?:id|[A-Za-z_]*(?:Id|ID|_id))"\s*:\s*"?([A-Za-z0-9_.:-]{1,80})"?',
        text or "",
    ):
        ids.add(match.group(1))
    return ids


def _pattern_for_path(target: str, path: str) -> str:
    clean = "/" + str(path or "").lstrip("/")
    if re.search(r"/[^/?]*\d+[^/?]*(?:/)?$", clean):
        pattern = re.sub(r"/[^/?]*\d+[^/?]*(?=(?:/)?$)", "/{id}", clean, count=1)
    elif clean.endswith("/"):
        pattern = clean.rstrip("/") + "/{id}"
    else:
        pattern = clean + "/{id}"
    return target.rstrip("/") + pattern


def _merge_object_patterns(
    *,
    target: str,
    identity_name: str,
    path: str,
    ids: set[str],
    patterns: dict[str, dict[str, Any]],
) -> None:
    if not ids:
        return
    url_pattern = _pattern_for_path(target, path)
    entry = patterns.setdefault(
        url_pattern,
        {
            "url_pattern": url_pattern,
            "object_ids": [],
            "owner_map": {},
            "source_paths": [],
        },
    )
    for obj_id in sorted(ids, key=str):
        if obj_id not in entry["object_ids"]:
            entry["object_ids"].append(obj_id)
        entry["owner_map"].setdefault(str(obj_id), identity_name)
    if path not in entry["source_paths"]:
        entry["source_paths"].append(path)


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
    principals = _normalize_principals(token, kwargs.get("identities") or kwargs.get("principals"))
    primary = principals[0] if principals else {"name": "authenticated", "token": token}

    accessible: list[dict] = []
    new_endpoints: list[dict] = []
    user_data_exposed: list[dict] = []
    auth_only: list[dict] = []
    same_data_without_auth: list[dict] = []
    identity_owned_objects: dict[str, list[dict[str, Any]]] = {}
    object_pattern_index: dict[str, dict[str, Any]] = {}

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)
    sem = asyncio.Semaphore(15)

    async def check(path: str, principal: dict[str, Any]) -> None:
        async with sem:
            try:
                identity_name = str(principal.get("name") or "authenticated")
                headers = _headers_for(principal)
                identity_session = await _mgr.get_session(target, identity=identity_name)
                # Test with auth
                r_auth = await identity_session.request("GET", path, headers=headers)
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
                    "identity": identity_name,
                }

                if r_auth.status == 200:
                    entry["preview"] = r_auth.text[:300]
                    if identity_name == str(primary.get("name") or "authenticated"):
                        accessible.append(entry)

                    # Detect broken access control: should need auth but doesn't
                    if r_noauth.status == 200 and r_noauth.text == r_auth.text:
                        entry["issue"] = "no_auth_required"
                        same_data_without_auth.append(entry)

                    # Detect IDOR-able data
                    body = r_auth.text.lower()
                    if any(kw in body for kw in ["email", "password", "role", "token", "secret"]):
                        user_data_exposed.append(entry)
                    object_ids = _id_values_from_text(r_auth.text)
                    if object_ids:
                        owned = {
                            "path": path,
                            "url_pattern": _pattern_for_path(target, path),
                            "ids": sorted(object_ids, key=str)[:50],
                            "status": r_auth.status,
                            "size": r_auth.body_length,
                        }
                        identity_owned_objects.setdefault(identity_name, []).append(owned)
                        current_ids = set(str(v) for v in principal.get("owned_ids") or [])
                        current_ids.update(str(v) for v in object_ids)
                        principal["owned_ids"] = sorted(current_ids, key=str)[:100]
                        owned_objects = list(principal.get("owned_objects") or [])
                        owned_objects.append(owned)
                        principal["owned_objects"] = owned_objects[:50]
                        _merge_object_patterns(
                            target=target,
                            identity_name=identity_name,
                            path=path,
                            ids=object_ids,
                            patterns=object_pattern_index,
                        )

                # Track newly accessible (auth unlocks)
                if r_auth.status == 200 and r_noauth.status == 401:
                    if identity_name == str(primary.get("name") or "authenticated"):
                        new_endpoints.append(entry)
                        auth_only.append(entry)

            except Exception:
                pass

    await asyncio.gather(*[check(p, principal) for principal in principals for p in AUTH_PATHS])

    accessible.sort(key=lambda x: x.get("size_auth", 0), reverse=True)
    object_patterns = sorted(
        object_pattern_index.values(),
        key=lambda item: (-len(item.get("object_ids") or []), item.get("url_pattern", "")),
    )
    owner_map: dict[str, str] = {}
    for item in object_patterns:
        owner_map.update({str(k): str(v) for k, v in dict(item.get("owner_map") or {}).items()})

    logger.info("post_auth_enum: %d accessible, %d new (auth-only), %d with user data",
                len(accessible), len(new_endpoints), len(user_data_exposed))

    return {
        "accessible": accessible,
        "new_endpoints": new_endpoints,
        "user_data_exposed": user_data_exposed,
        "identities": principals,
        "identity_owned_objects": identity_owned_objects,
        "object_patterns": object_patterns[:12],
        "object_ids": sorted(owner_map.keys(), key=str)[:100],
        "owner_map": owner_map,
        "control_evidence": {
            "auth_only": auth_only[:5],
            "same_data_without_auth": same_data_without_auth[:5],
            "identity_owned_objects": {
                key: value[:5] for key, value in identity_owned_objects.items()
            },
        },
        "total_tested": len(AUTH_PATHS) * max(1, len(principals)),
    }
