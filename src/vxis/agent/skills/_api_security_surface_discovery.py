"""Internal helpers for read-only API surface discovery."""

from __future__ import annotations

import html
import json
import re
from typing import Any

from ._api_security_self_write import _load_json
from ._api_security_self_write import _normalize_path

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


def _sample_openapi_path(path: str) -> str | None:
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
