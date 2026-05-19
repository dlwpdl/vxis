"""Skill: test_api_security — API authz, mass assignment, verb tampering."""
from __future__ import annotations
import asyncio
import html
import json
import logging
import re
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

MASS_ASSIGN_FIELDS = _load_ds("test_api_security", "mass_assign_fields")  # ADR-007 Phase 3-9 — data in data/payloads/test_api_security.json

VERB_TAMPER_PATHS = _load_ds("test_api_security", "verb_tamper_paths")  # ADR-007 Phase 3-9 — data in data/payloads/test_api_security.json


_NEXT_DATA_RE = re.compile(
    r"<script[^>]+id=[\"']__NEXT_DATA__[\"'][^>]*>(.*?)</script>",
    re.IGNORECASE | re.DOTALL,
)
_JS_REF_RE = re.compile(r"(?:src|href)=[\"']([^\"']+\.js(?:\?[^\"']*)?)[\"']", re.IGNORECASE)
_ADMIN_ROUTE_RE = re.compile(r"[\"'](/admin(?:/[A-Za-z0-9_.~:/?#\[\]@!$&'()*+,;=%-]*)?)[\"']\s*:")
_ADMIN_ROUTE_LOOSE_RE = re.compile(r"(?<![A-Za-z0-9_])(/admin/[A-Za-z0-9_.~:/?#\[\]@!$&'()*+,;=%-]+)")
_ACTION_ENDPOINT_RE = re.compile(r"[\"']([A-Za-z][A-Za-z0-9_-]*/R)[\"']")
_ACTION_NAME_RE = re.compile(r"[\"']?(Get[A-Za-z0-9_]{2,})[\"']?")


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

    auth_headers: dict[str, str] = {}
    if token:
        auth_headers["Authorization"] = f"Bearer {token}"

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)

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

    # --- Mass assignment ---
    reg_paths = ["/api/users", "/api/register", "/api/signup", "/api/account"]
    for path in reg_paths:
        for field_info in MASS_ASSIGN_FIELDS:
            tested += 1
            async with sem:
                try:
                    body = {"username": "testuser", "email": "test@test.com",
                            "password": "Test1234!", field_info["field"]: field_info["value"]}
                    r = await _session.request(
                        "POST", f"{target}{path}", json_data=body, headers=auth_headers
                    )
                    if r.status in (200, 201):
                        resp = r.text.lower()
                        if field_info["field"].lower() in resp and field_info["value"].lower() in resp:
                            findings.append({
                                "type": "mass_assignment",
                                "payload": f"{field_info['field']}={field_info['value']} on {path}",
                                "evidence": f"{field_info['desc']}: field accepted (status {r.status})",
                                "response_preview": r.text[:300],
                                "severity": "high",
                            })
                            logger.info("Mass assignment: %s on %s", field_info["field"], path)
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
                if 429 not in statuses and all(s != 404 for s in statuses):
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
