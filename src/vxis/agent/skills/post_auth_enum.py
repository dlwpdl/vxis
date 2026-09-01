"""Skill: post_auth_enum — enumerate all endpoints with an auth token."""
from __future__ import annotations
import asyncio
import json
import logging
import re
import secrets
from typing import Any
from .attempt_auth import _extract_js_paths
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

AUTH_PATHS = _load_ds("post_auth_enum", "auth_paths")  # ADR-007 Phase 3-9 — data in data/payloads/post_auth_enum.json
_ASSET_API_PATH_RE = re.compile(
    r"""["']((?:[A-Za-z0-9_-]+/)*(?:api|rest)[A-Za-z0-9_./-]{4,120})["']""",
    re.IGNORECASE,
)
_SERVICE_PREFIX_RE = re.compile(r"""["']([A-Za-z][A-Za-z0-9_-]{1,32}/)["']""")
_SKIP_ROUTE_MARKERS = (
    "login",
    "signin",
    "sign-in",
    "sign_in",
    "signup",
    "register",
    "forgot",
    "reset",
    "verify",
    "otp",
    "unlock",
)
_COLLECTION_SUFFIXES = ("all", "latest", "list", "recent")


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


def _normalize_asset_path(path: str) -> str:
    clean = "/" + str(path or "").strip().lstrip("/")
    clean = clean.split("?", 1)[0].split("#", 1)[0]
    return clean


def _is_candidate_post_auth_path(path: str) -> bool:
    lower = str(path or "").lower()
    if not lower or "://" in lower or lower.endswith(".js"):
        return False
    return not any(marker in lower for marker in _SKIP_ROUTE_MARKERS)


def _extract_asset_post_auth_paths(text: str) -> list[str]:
    seen: set[str] = set()
    paths: list[str] = []
    prefixes = list(dict.fromkeys(_SERVICE_PREFIX_RE.findall(text or "")))
    for match in _ASSET_API_PATH_RE.finditer(text or ""):
        fragment = _normalize_asset_path(match.group(1))
        candidates = [fragment]
        window = text[max(0, match.start() - 200) : min(len(text), match.end() + 200)]
        for prefix in [*_SERVICE_PREFIX_RE.findall(window), *prefixes]:
            candidates.append(_normalize_asset_path(f"{prefix}{fragment.lstrip('/')}"))
        for path in candidates:
            if path in seen or not _is_candidate_post_auth_path(path):
                continue
            seen.add(path)
            paths.append(path)
    return paths


async def _discover_asset_post_auth_paths(session: Any) -> list[str]:
    seen: set[str] = set()
    candidates: list[str] = []
    try:
        root = await session.request("GET", "/")
    except Exception:
        return []

    def add(paths: list[str]) -> None:
        for path in paths:
            if path in seen:
                continue
            seen.add(path)
            candidates.append(path)

    add(_extract_asset_post_auth_paths(root.text))
    for js_path in _extract_js_paths(root.text)[:5]:
        try:
            js = await session.request("GET", js_path)
        except Exception:
            continue
        add(_extract_asset_post_auth_paths(js.text))
    return candidates


def _is_baseline_shell(status: int, text: str, baseline_text: str) -> bool:
    return bool(baseline_text) and status == 200 and text == baseline_text


def _record_id_values(item: dict[str, Any]) -> set[str]:
    preferred: set[str] = set()
    fallback: set[str] = set()
    id_key_re = re.compile(r"(^id$|_id$|id$|Id$|ID$)")

    for key, nested in item.items():
        if not isinstance(nested, (str, int)):
            continue
        text = str(nested).strip()
        if not text or len(text) > 80:
            continue
        if str(key) in {"id", "_id", "Id", "ID"}:
            preferred.add(text)
        elif id_key_re.search(str(key)):
            fallback.add(text)
    return preferred or fallback


def _principal_markers(principal: dict[str, Any]) -> set[str]:
    markers: set[str] = set()
    for key in ("email", "name", "id"):
        value = str(principal.get(key) or "").strip().lower()
        if value:
            markers.add(value)
    return markers


def _value_matches_markers(value: Any, markers: set[str]) -> bool:
    if isinstance(value, dict):
        return any(_value_matches_markers(nested, markers) for nested in value.values())
    if isinstance(value, list):
        return any(_value_matches_markers(nested, markers) for nested in value[:20])
    if isinstance(value, (str, int)):
        return str(value).strip().lower() in markers
    return False


def _id_values_from_json(value: Any) -> set[str]:
    ids: set[str] = set()

    def walk(item: Any) -> None:
        if isinstance(item, list):
            for nested in item[:100]:
                if isinstance(nested, dict):
                    ids.update(_record_id_values(nested))
                    for child in nested.values():
                        if isinstance(child, list):
                            walk(child)
                elif isinstance(nested, list):
                    walk(nested)
        elif isinstance(item, dict):
            for nested in item.values():
                if isinstance(nested, list):
                    walk(nested)

    walk(value)
    return ids


def _owned_id_values_from_json(value: Any, principal: dict[str, Any]) -> set[str]:
    ids: set[str] = set()
    markers = _principal_markers(principal)
    if not markers:
        return ids

    def walk(item: Any) -> None:
        if isinstance(item, list):
            for nested in item[:100]:
                if isinstance(nested, dict):
                    if _value_matches_markers(nested, markers):
                        ids.update(_record_id_values(nested))
                    for child in nested.values():
                        if isinstance(child, list):
                            walk(child)
                elif isinstance(nested, list):
                    walk(nested)
        elif isinstance(item, dict):
            for nested in item.values():
                if isinstance(nested, list):
                    walk(nested)

    walk(value)
    return ids


def _id_values_from_text(text: str) -> set[str]:
    parsed = _json_value(text)
    if parsed is not None:
        return _id_values_from_json(parsed)
    ids: set[str] = set()
    for match in re.finditer(
        r'"(?:id|[A-Za-z_]*(?:Id|ID|_id))"\s*:\s*"?([A-Za-z0-9_.:-]{1,80})"?',
        text or "",
    ):
        ids.add(match.group(1))
    return ids


def _owned_id_values_from_text(text: str, principal: dict[str, Any]) -> set[str]:
    parsed = _json_value(text)
    if parsed is None:
        return set()
    return _owned_id_values_from_json(parsed, principal)


def _pattern_for_path(target: str, path: str, known_paths: set[str] | None = None) -> str:
    clean = _normalize_asset_path(path)
    if re.search(r"/[^/?]*\d+[^/?]*(?:/)?$", clean):
        pattern = re.sub(r"/[^/?]*\d+[^/?]*(?=(?:/)?$)", "/{id}", clean, count=1)
    else:
        base = clean.rstrip("/")
        tail = base.rsplit("/", 1)[-1].lower()
        if tail in _COLLECTION_SUFFIXES:
            parent = base.rsplit("/", 1)[0] or "/"
            base = parent
        pattern = base + "/{id}"
    return target.rstrip("/") + pattern


def _merge_object_patterns(
    *,
    target: str,
    identity_name: str,
    path: str,
    ids: set[str],
    owned_ids: set[str],
    known_paths: set[str],
    patterns: dict[str, dict[str, Any]],
) -> None:
    if not ids:
        return
    url_pattern = _pattern_for_path(target, path, known_paths)
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
        if obj_id in owned_ids:
            entry["owner_map"].setdefault(str(obj_id), identity_name)
    if path not in entry["source_paths"]:
        entry["source_paths"].append(path)


def _apply_cross_identity_visibility_owners(
    *,
    principals: list[dict[str, Any]],
    identity_owned_objects: dict[str, list[dict[str, Any]]],
    patterns: dict[str, dict[str, Any]],
    visibility: dict[str, dict[str, set[str]]],
) -> None:
    principal_map = {
        str(principal.get("name") or ""): principal
        for principal in principals
        if principal.get("name") and principal.get("token")
    }
    if len(principal_map) < 2:
        return

    for url_pattern, entry in patterns.items():
        seen_by = visibility.get(url_pattern, {})
        inferred: dict[str, list[str]] = {}
        for obj_id in entry.get("object_ids") or []:
            viewers = [name for name in principal_map if obj_id in seen_by.get(name, set())]
            if len(viewers) != 1:
                continue
            owner = viewers[0]
            entry["owner_map"].setdefault(str(obj_id), owner)
            inferred.setdefault(owner, []).append(str(obj_id))
        for owner, ids in inferred.items():
            principal = principal_map[owner]
            current_ids = set(str(v) for v in principal.get("owned_ids") or [])
            current_ids.update(ids)
            principal["owned_ids"] = sorted(current_ids, key=str)[:100]
            owned = {
                "path": ((entry.get("source_paths") or [""])[:1] or [""])[0],
                "url_pattern": url_pattern,
                "ids": sorted(set(ids), key=str)[:50],
                "inference": "cross_identity_exclusive",
            }
            owned_objects = list(principal.get("owned_objects") or [])
            owned_objects.append(owned)
            principal["owned_objects"] = owned_objects[:50]
            identity_owned_objects.setdefault(owner, []).append(owned)


def _seed_body_for_path(path: str, *, suffix: str) -> dict[str, Any] | None:
    lower = _normalize_asset_path(path).lower()
    if any(token in lower for token in ("post", "comment", "message", "review", "feedback")):
        return {
            "title": f"seed-{suffix}",
            "content": f"seed-{suffix}",
            "message": f"seed-{suffix}",
        }
    if any(token in lower for token in ("order", "cart", "basket")):
        return {"product_id": 1, "quantity": 1}
    if any(token in lower for token in ("vehicle", "car")):
        return {
            "vehicleid": f"VEH-{suffix}",
            "make": "Test",
            "model": "Seed",
            "year": "2024",
        }
    return None


def _stateful_seed_plans(paths: set[str]) -> list[dict[str, str]]:
    plans: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(paths):
        tail = path.rstrip("/").rsplit("/", 1)[-1].lower()
        if tail not in _COLLECTION_SUFFIXES:
            continue
        write_path = path.rstrip("/").rsplit("/", 1)[0] or "/"
        if not _seed_body_for_path(write_path, suffix="seed"):
            continue
        key = (path, write_path)
        if key in seen:
            continue
        seen.add(key)
        plans.append({"read_path": path, "write_path": write_path})
    return plans[:12]


async def _seed_stateful_objects(
    *,
    target: str,
    principals: list[dict[str, Any]],
    known_paths: set[str],
    mgr: Any,
    identity_owned_objects: dict[str, list[dict[str, Any]]],
    object_pattern_index: dict[str, dict[str, Any]],
    pattern_visibility: dict[str, dict[str, set[str]]],
) -> list[dict[str, Any]]:
    if len(principals) < 2:
        return []
    plans = _stateful_seed_plans(known_paths)
    if not plans:
        return []

    seeded: list[dict[str, Any]] = []
    for principal in principals[:3]:
        identity_name = str(principal.get("name") or "")
        if not identity_name or not principal.get("token"):
            continue
        headers = _headers_for(principal)
        session = await mgr.get_session(target, identity=identity_name)
        for plan in plans:
            body = _seed_body_for_path(plan["write_path"], suffix=secrets.token_hex(3))
            if not body:
                continue
            before_ids: set[str] = set()
            try:
                before = await session.request("GET", plan["read_path"], headers=headers or None)
                if before.status == 200:
                    before_ids = _id_values_from_text(before.text)
            except Exception:
                before_ids = set()
            try:
                created = await session.request(
                    "POST",
                    plan["write_path"],
                    json_data=body,
                    headers=headers or None,
                )
            except Exception:
                continue
            if created.status not in (200, 201, 202):
                continue
            after_ids: set[str] = set()
            try:
                after = await session.request("GET", plan["read_path"], headers=headers or None)
                if after.status == 200:
                    after_ids = _id_values_from_text(after.text)
            except Exception:
                after_ids = set()
            created_ids = {str(v) for v in after_ids if str(v) not in before_ids}
            if not created_ids:
                created_ids = {str(v) for v in _id_values_from_text(created.text) if str(v) not in before_ids}
            if not created_ids:
                continue
            url_pattern = _pattern_for_path(target, plan["read_path"], known_paths)
            pattern_visibility.setdefault(url_pattern, {}).setdefault(identity_name, set()).update(created_ids)
            current_ids = set(str(v) for v in principal.get("owned_ids") or [])
            current_ids.update(created_ids)
            principal["owned_ids"] = sorted(current_ids, key=str)[:100]
            owned = {
                "path": plan["read_path"],
                "write_path": plan["write_path"],
                "url_pattern": url_pattern,
                "ids": sorted(created_ids, key=str)[:50],
                "status": created.status,
                "inference": "stateful_seed",
            }
            identity_owned_objects.setdefault(identity_name, []).append(owned)
            owned_objects = list(principal.get("owned_objects") or [])
            owned_objects.append(owned)
            principal["owned_objects"] = owned_objects[:50]
            _merge_object_patterns(
                target=target,
                identity_name=identity_name,
                path=plan["read_path"],
                ids=created_ids,
                owned_ids=created_ids,
                known_paths=known_paths,
                patterns=object_pattern_index,
            )
            seeded.append(
                {
                    "identity": identity_name,
                    "read_path": plan["read_path"],
                    "write_path": plan["write_path"],
                    "status": created.status,
                    "created_ids": sorted(created_ids, key=str)[:50],
                }
            )
    return seeded


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
    pattern_visibility: dict[str, dict[str, set[str]]] = {}
    stateful_seeding: list[dict[str, Any]] = []

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)
    sem = asyncio.Semaphore(15)
    baseline_text = ""
    candidate_paths = [str(path) for path in AUTH_PATHS]
    discovered_paths: list[str] = []

    try:
        baseline = await _session.request("GET", "/definitely-not-real-xyz-probe")
        if baseline.status == 200:
            baseline_text = baseline.text
    except Exception:
        pass

    try:
        discovered_paths = list(await _discover_asset_post_auth_paths(_session))
        for path in discovered_paths:
            if path not in candidate_paths:
                candidate_paths.append(path)
    except Exception:
        pass
    known_paths = {_normalize_asset_path(path) for path in candidate_paths}

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

                if _is_baseline_shell(r_auth.status, r_auth.text, baseline_text) and _is_baseline_shell(
                    r_noauth.status, r_noauth.text, baseline_text
                ):
                    return

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
                    owned_ids = _owned_id_values_from_text(r_auth.text, principal)
                    if object_ids:
                        url_pattern = _pattern_for_path(target, path, known_paths)
                        pattern_visibility.setdefault(url_pattern, {}).setdefault(identity_name, set()).update(
                            str(v) for v in object_ids
                        )
                        if owned_ids:
                            owned = {
                                "path": path,
                                "url_pattern": url_pattern,
                                "ids": sorted(owned_ids, key=str)[:50],
                                "status": r_auth.status,
                                "size": r_auth.body_length,
                            }
                            identity_owned_objects.setdefault(identity_name, []).append(owned)
                            current_ids = set(str(v) for v in principal.get("owned_ids") or [])
                            current_ids.update(str(v) for v in owned_ids)
                            principal["owned_ids"] = sorted(current_ids, key=str)[:100]
                            owned_objects = list(principal.get("owned_objects") or [])
                            owned_objects.append(owned)
                            principal["owned_objects"] = owned_objects[:50]
                        _merge_object_patterns(
                            target=target,
                            identity_name=identity_name,
                            path=path,
                            ids=object_ids,
                            owned_ids=owned_ids,
                            known_paths=known_paths,
                            patterns=object_pattern_index,
                        )

                # Track newly accessible (auth unlocks)
                if r_auth.status == 200 and r_noauth.status == 401:
                    if identity_name == str(primary.get("name") or "authenticated"):
                        new_endpoints.append(entry)
                        auth_only.append(entry)

            except Exception:
                pass

    await asyncio.gather(*[check(p, principal) for principal in principals for p in candidate_paths])
    try:
        stateful_seeding = await _seed_stateful_objects(
            target=target,
            principals=principals,
            known_paths=known_paths,
            mgr=_mgr,
            identity_owned_objects=identity_owned_objects,
            object_pattern_index=object_pattern_index,
            pattern_visibility=pattern_visibility,
        )
    except Exception:
        stateful_seeding = []
    _apply_cross_identity_visibility_owners(
        principals=principals,
        identity_owned_objects=identity_owned_objects,
        patterns=object_pattern_index,
        visibility=pattern_visibility,
    )

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
        "discovered_paths": discovered_paths[:100],
        "user_data_exposed": user_data_exposed,
        "identities": principals,
        "identity_owned_objects": identity_owned_objects,
        "object_patterns": object_patterns[:12],
        "object_ids": sorted(owner_map.keys(), key=str)[:100],
        "owner_map": owner_map,
        "control_evidence": {
            "auth_only": auth_only[:5],
            "same_data_without_auth": same_data_without_auth[:5],
            "stateful_seeding": stateful_seeding[:8],
            "identity_owned_objects": {
                key: value[:5] for key, value in identity_owned_objects.items()
            },
        },
        "total_tested": len(candidate_paths) * max(1, len(principals)),
    }
