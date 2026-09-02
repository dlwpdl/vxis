"""Internal helpers for authenticated self-write API security flows."""

from __future__ import annotations

import json
import re
import secrets
from typing import Any

_SELF_WRITE_RESOURCE_HINTS = (
    "account",
    "profile",
    "user",
    "email",
    "phone",
    "number",
    "vehicle",
)
_SELF_WRITE_ACTION_HINTS = (
    "change",
    "update",
    "edit",
    "set",
    "add",
    "verify",
)
_SELF_WRITE_SKIP_HINTS = (
    "login",
    "logout",
    "signup",
    "register",
    "forgot",
    "forget",
    "reset",
    "dashboard",
    "shop",
    "product",
    "order",
    "comment",
    "post",
    "mechanic",
    "contact",
    "convert",
    "resend",
)

_ERROR_FIELD_RE = re.compile(r"""field ['"]([A-Za-z][A-Za-z0-9_-]{0,63})['"]""", re.IGNORECASE)
_MISSING_FIELD_RE = re.compile(
    r"""missing required (?:property|field) ['"]?([A-Za-z][A-Za-z0-9_-]{0,63})['"]?""",
    re.IGNORECASE,
)


def _normalize_path(path: str) -> str:
    if path.startswith("http://") or path.startswith("https://"):
        from urllib.parse import urlparse

        parsed = urlparse(path)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
    if not path.startswith("/"):
        path = f"/{path}"
    return path.split("#", 1)[0]


def _load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


def _merge_field_values(*sources: dict[str, str]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for source in sources:
        for key, value in dict(source or {}).items():
            text = str(value or "").strip()
            if text:
                merged.setdefault(str(key).lower(), text)
    return merged


def _looks_self_write_surface(path: str) -> bool:
    lower = _normalize_path(path).split("?", 1)[0].lower()
    if not lower or any(marker in lower for marker in _SELF_WRITE_SKIP_HINTS):
        return False
    return any(token in lower for token in _SELF_WRITE_RESOURCE_HINTS) and any(
        token in lower for token in _SELF_WRITE_ACTION_HINTS
    )


def _preview_field_values(preview: str) -> dict[str, str]:
    parsed = _load_json(preview)
    values: dict[str, str] = {}

    def walk(item: Any) -> None:
        if isinstance(item, dict):
            for key, nested in item.items():
                lower = str(key).lower()
                if lower in {"email", "phone", "number", "username", "name"} and isinstance(nested, (str, int)):
                    text = str(nested).strip()
                    if text:
                        values.setdefault(lower, text)
                elif isinstance(nested, (dict, list)):
                    walk(nested)
        elif isinstance(item, list):
            for nested in item[:3]:
                walk(nested)

    if parsed is not None:
        walk(parsed)
    return values


def _identity_field_values(identities: Any) -> dict[str, str]:
    values: dict[str, str] = {}
    raw_items: list[Any]
    if isinstance(identities, dict):
        raw_items = list(identities.values())
    elif isinstance(identities, list):
        raw_items = list(identities)
    else:
        raw_items = []
    for item in raw_items[:10]:
        if not isinstance(item, dict):
            continue
        for key in ("email", "phone", "number", "username", "name"):
            text = str(item.get(key) or "").strip()
            if text:
                values.setdefault(key, text)
    return values


def _credential_field_values(credentials: Any) -> dict[str, str]:
    values: dict[str, str] = {}
    raw_items: list[Any]
    if isinstance(credentials, dict):
        raw_items = list(credentials.values())
    elif isinstance(credentials, list):
        raw_items = list(credentials)
    else:
        raw_items = []
    for item in raw_items[:10]:
        if not isinstance(item, dict):
            continue
        for key in ("email", "username", "name", "password"):
            text = str(item.get(key) or "").strip()
            if text:
                values.setdefault(key, text)
    return values


def _self_write_seed_values(
    endpoints: Any,
    identities: Any,
    credentials: Any = None,
) -> dict[str, str]:
    values: dict[str, str] = {}
    for item in list(endpoints or [])[:60]:
        if not isinstance(item, dict):
            continue
        preview_values = _preview_field_values(str(item.get("preview_auth") or item.get("preview") or ""))
        values = _merge_field_values(values, preview_values)
    return _merge_field_values(
        values,
        _identity_field_values(identities),
        _credential_field_values(credentials),
    )


def _shifted_email(value: str, suffix: str) -> str:
    text = str(value or "").strip()
    if "@" not in text:
        return f"user.{suffix}@example.test"
    local, _, domain = text.partition("@")
    return f"{local}+{suffix}@{domain}"


def _shifted_phone(value: str, suffix: str) -> str:
    digits = re.sub(r"\D", "", str(value or ""))
    tail = f"{int(suffix[-4:], 16) % 10000:04d}"
    prefix = digits[:-4] if len(digits) > 4 else "555010"
    return f"{prefix}{tail}"


def _sample_self_write_field_value(field_name: str, seed_values: dict[str, str], suffix: str) -> Any:
    lower = str(field_name or "").lower()
    uses_current = any(token in lower for token in ("old", "current", "existing"))
    if "email" in lower:
        current = seed_values.get("email", "")
        if uses_current:
            return current or None
        return _shifted_email(current, suffix)
    if "number" in lower or "phone" in lower:
        current = seed_values.get("phone") or seed_values.get("number") or ""
        if uses_current:
            return current or None
        return _shifted_phone(current, suffix)
    if "name" in lower:
        current = seed_values.get("name") or seed_values.get("username") or "user"
        if uses_current:
            return current or None
        return f"{current}-{suffix}"
    if "vin" in lower:
        return f"VIN{suffix}".upper()
    if "pincode" in lower or lower == "pin":
        return "1234"
    if "password" in lower or lower in {"pass", "passwd", "pwd"}:
        current = seed_values.get("password", "")
        if uses_current:
            return current or None
        return f"Test1234!{suffix}"
    if "verified" in lower:
        return False
    return None


def _sample_self_write_body(
    path: str,
    preview: str = "",
    *,
    seed_values: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    lower = _normalize_path(path).split("?", 1)[0].lower()
    values = _merge_field_values(_preview_field_values(preview), dict(seed_values or {}))
    suffix = secrets.token_hex(4)
    body: dict[str, Any] = {}
    if "email" in lower:
        body["email"] = _shifted_email(values.get("email", ""), suffix)
    if "phone" in lower or "number" in lower:
        number = _shifted_phone(values.get("phone") or values.get("number") or "", suffix)
        body["number"] = number
        if "phone" in lower:
            body["phone"] = number
    if "vehicle" in lower:
        body.setdefault("vin", f"VIN{suffix}".upper())
        body.setdefault("pincode", "1234")
    if "password" in lower:
        body["password"] = f"Test1234!{suffix}"
    if "verify" in lower:
        if values.get("email") and "email" not in body:
            body["email"] = values["email"]
        body.setdefault("verified", False)
    if ("profile" in lower or "account" in lower or "/user/" in lower) and not body:
        if values.get("email"):
            body["email"] = values["email"]
        body["name"] = values.get("name") or f"user-{suffix}"
    return body or None


def _extract_required_fields(text: str) -> list[str]:
    parsed = _load_json(text)
    haystacks = [str(text or "")]
    if isinstance(parsed, dict):
        haystacks.extend(
            str(parsed.get(key) or "")
            for key in ("details", "message", "error", "errors")
        )
    fields: list[str] = []
    seen: set[str] = set()
    for regex in (_ERROR_FIELD_RE, _MISSING_FIELD_RE):
        for haystack in haystacks:
            for match in regex.finditer(haystack):
                field = str(match.group(1) or "").strip()
                if not field:
                    continue
                lowered = field.lower()
                if lowered in seen:
                    continue
                seen.add(lowered)
                fields.append(field)
    return fields[:8]


def _adapt_self_write_body(
    path: str,
    body: dict[str, Any],
    response_text: str,
    *,
    seed_values: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    required_fields = _extract_required_fields(response_text)
    if not required_fields:
        return None
    suffix = secrets.token_hex(4)
    adapted = dict(body)
    changed = False
    lowered_fields = {str(field).lower() for field in required_fields}
    lowered_keys = {str(field).lower() for field in adapted}
    password_change_context = any(
        ("password" in field and any(token in field for token in ("new", "repeat", "confirm")))
        for field in [*lowered_fields, *lowered_keys]
    ) and any("new" in field and "password" in field for field in [*lowered_fields, *lowered_keys])
    for field in required_fields:
        if adapted.get(field) not in (None, ""):
            continue
        lower = str(field).lower()
        if (
            "password" in lower
            and any(token in lower for token in ("confirm", "confirmation", "repeat"))
            and not password_change_context
        ):
            value = dict(seed_values or {}).get("password") or None
        else:
            value = _sample_self_write_field_value(field, dict(seed_values or {}), suffix)
        if value is None:
            continue
        adapted[field] = value
        changed = True
    if not changed:
        return None
    return adapted


def _self_write_methods(path: str) -> list[str]:
    lower = _normalize_path(path).split("?", 1)[0].lower()
    if any(token in lower for token in ("update", "edit")):
        return ["PUT", "PATCH", "POST"]
    if any(token in lower for token in ("change", "set", "add", "verify")):
        return ["POST", "PUT", "PATCH"]
    return ["POST"]


def _extract_discovered_self_write_candidates(
    endpoints: Any,
    *,
    seed_values: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in list(endpoints or [])[:60]:
        path = str(item.get("path") or item.get("url") or "") if isinstance(item, dict) else str(item or "")
        preview = str(item.get("preview_auth") or item.get("preview") or "") if isinstance(item, dict) else ""
        path = _normalize_path(path).split("?", 1)[0]
        if not path or not _looks_self_write_surface(path):
            continue
        body = _sample_self_write_body(path, preview, seed_values=seed_values)
        if not body:
            continue
        for method in _self_write_methods(path):
            candidate = {"kind": "http", "path": path, "method": method, "json_body": dict(body)}
            key = json.dumps(candidate, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(candidate)
    return candidates[:12]
