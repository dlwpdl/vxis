from __future__ import annotations

import fnmatch
import logging
import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from vxis.interaction.xray import CapturedFlow, FlowAnalyzer, MitmProxyManager

logger = logging.getLogger(__name__)


def _clip(value: str, limit: int = 200) -> str:
    value = str(value or "")
    if len(value) <= limit:
        return value
    return value[:limit] + "..."


def _mask_token(value: str) -> str:
    value = str(value or "")
    if len(value) <= 12:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _match_scope_pattern(pattern: str, *, url: str, host: str, path: str) -> bool:
    pat = pattern.strip()
    if not pat:
        return False
    url_l = url.lower()
    host_l = host.lower()
    path_l = path.lower()
    pat_l = pat.lower()
    if "://" in pat_l:
        return fnmatch.fnmatch(url_l, pat_l)
    if "/" in pat_l:
        return fnmatch.fnmatch(path_l, pat_l) or fnmatch.fnmatch(url_l, f"*{pat_l}*")
    return fnmatch.fnmatch(host_l, pat_l) or fnmatch.fnmatch(url_l, f"*{pat_l}*")


@dataclass
class ProxyScope:
    allowlist: list[str] = field(default_factory=list)
    denylist: list[str] = field(default_factory=list)

    def allows(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path or "/"
        if self.allowlist and not any(
            _match_scope_pattern(p, url=url, host=host, path=path)
            for p in self.allowlist
        ):
            return False
        if any(
            _match_scope_pattern(p, url=url, host=host, path=path)
            for p in self.denylist
        ):
            return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowlist": list(self.allowlist),
            "denylist": list(self.denylist),
        }


class CaidoProxyBackend:
    """Thin client for attaching VXIS to an already-running Caido instance."""

    def __init__(self) -> None:
        raw_url = (
            os.environ.get("VXIS_CAIDO_API_URL")
            or os.environ.get("VXIS_CAIDO_URL")
            or ""
        ).strip()
        if raw_url and not raw_url.startswith("http"):
            raw_url = f"http://{raw_url}"
        if raw_url.endswith("/graphql"):
            self.api_url = raw_url
            self.proxy_url = raw_url[: -len("/graphql")]
        else:
            self.proxy_url = raw_url.rstrip("/")
            self.api_url = f"{self.proxy_url}/graphql" if self.proxy_url else ""
        self.auth_token = os.environ.get("VXIS_CAIDO_API_TOKEN", "").strip()

    @property
    def configured(self) -> bool:
        return bool(self.api_url)

    def status(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "api_url": self.api_url,
            "proxy_url": self.proxy_url,
        }

    async def validate(self) -> dict[str, Any]:
        if not self.configured:
            return {"ok": False, "error": "caido_not_configured"}
        headers = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(
                    self.api_url,
                    headers=headers,
                    json={"query": "query { __typename }"},
                )
            ok = resp.status_code in (200, 400)
            return {"ok": ok, "status": resp.status_code}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    async def _graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        headers = {}
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                self.api_url,
                headers=headers,
                json={"query": query, "variables": variables},
            )
            resp.raise_for_status()
            payload = resp.json()
        if payload.get("errors"):
            raise RuntimeError(str(payload["errors"][0]))
        return payload.get("data", {}) or {}

    async def list_requests(
        self,
        *,
        httpql_filter: str = "",
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        data = await self._graphql(
            """
            query GetRequests($limit: Int, $offset: Int, $filter: HTTPQL) {
              requestsByOffset(limit: $limit, offset: $offset, filter: $filter) {
                edges {
                  node {
                    id
                    method
                    host
                    path
                    query
                    isTls
                    port
                    createdAt
                    source
                    response { statusCode length roundtripTime }
                  }
                }
                count { value }
              }
            }
            """,
            {
                "limit": page_size,
                "offset": max(page - 1, 0) * page_size,
                "filter": httpql_filter or None,
            },
        )
        block = data.get("requestsByOffset", {}) or {}
        rows = []
        for edge in block.get("edges", []) or []:
            node = edge.get("node", {}) or {}
            scheme = "https" if node.get("isTls") else "http"
            host = node.get("host") or ""
            port = node.get("port")
            path = node.get("path") or "/"
            query = node.get("query") or ""
            url = f"{scheme}://{host}"
            if port and port not in (80, 443):
                url += f":{port}"
            url += path
            if query:
                url += f"?{query}"
            rows.append(
                {
                    "id": node.get("id"),
                    "method": node.get("method", "GET"),
                    "url": url,
                    "host": host,
                    "path": path,
                    "status_code": ((node.get("response") or {}).get("statusCode") or 0),
                    "response_time_ms": ((node.get("response") or {}).get("roundtripTime") or 0),
                    "source": node.get("source") or "",
                }
            )
        return {
            "backend": "caido",
            "count": len(rows),
            "page": page,
            "page_size": page_size,
            "total_count": (((block.get("count") or {}).get("value")) or len(rows)),
            "requests": rows,
        }

    async def view_request(self, request_id: str, *, part: str = "request") -> dict[str, Any]:
        query = """
        query GetRequest($id: ID!) {
          request(id: $id) {
            id
            method
            host
            path
            query
            raw
            response { id statusCode raw }
          }
        }
        """
        data = await self._graphql(query, {"id": request_id})
        node = data.get("request") or {}
        raw = node.get("raw") if part == "request" else ((node.get("response") or {}).get("raw"))
        return {
            "backend": "caido",
            "request_id": request_id,
            "part": part,
            "method": node.get("method", ""),
            "path": node.get("path", ""),
            "status_code": ((node.get("response") or {}).get("statusCode") or 0),
            "raw_base64": raw or "",
        }

    async def list_sitemap(self) -> dict[str, Any]:
        data = await self._graphql(
            """
            query GetSitemapRoots {
              sitemapRootEntries {
                id
                label
                kind
              }
            }
            """,
            {},
        )
        entries = data.get("sitemapRootEntries", []) or []
        return {
            "backend": "caido",
            "entries": [
                {
                    "id": e.get("id"),
                    "label": e.get("label") or "",
                    "kind": e.get("kind") or "",
                }
                for e in entries
            ],
            "count": len(entries),
        }


class ProxyRuntime:
    def __init__(self) -> None:
        self.backend = ""
        self.scope = ProxyScope()
        self._xray: MitmProxyManager | None = None
        self._caido: CaidoProxyBackend | None = None
        self._last_error = ""

    def _analyzed_flows(self) -> list[CapturedFlow]:
        if self.backend != "xray" or self._xray is None:
            return []
        flows = self._xray.get_captured_flows()
        analyzer = FlowAnalyzer()
        analyzed: list[CapturedFlow] = []
        for flow in flows:
            analyzed.append(analyzer.add_flow(flow))
        return [f for f in analyzed if self.scope.allows(f.url)]

    def _flow_to_request_row(self, flow: CapturedFlow) -> dict[str, Any]:
        parsed = urlparse(flow.url)
        return {
            "id": flow.id,
            "method": flow.method or "GET",
            "url": flow.url,
            "host": parsed.netloc,
            "path": parsed.path or "/",
            "status_code": flow.status_code or 0,
            "request_size": len(flow.request_body or ""),
            "response_size": len(flow.response_body or ""),
            "content_type": flow.response_content_type or flow.request_content_type or "",
            "is_api_call": bool(flow.is_api_call),
            "has_auth_token": bool(flow.has_auth_token),
            "auth_type": flow.auth_type or "",
            "token_count": len(flow.detected_tokens),
            "secret_count": len(flow.detected_secrets),
            "vulnerabilities": list(flow.vulnerabilities),
            "request_preview": _clip(flow.request_body, 160),
            "response_preview": _clip(flow.response_body, 160),
        }

    def _filter_flows(self, flows: list[CapturedFlow], filter_expr: str) -> list[CapturedFlow]:
        expr = (filter_expr or "").strip()
        if not expr:
            return flows
        clauses = [c for c in expr.split() if c]
        filtered = flows
        for clause in clauses:
            key, _, value = clause.partition(":")
            if not _:
                needle = clause.lower()
                filtered = [
                    f for f in filtered
                    if needle in f.url.lower()
                    or needle in (f.request_body or "").lower()
                    or needle in (f.response_body or "").lower()
                ]
                continue
            key = key.lower()
            value = value.strip()
            if key == "method":
                filtered = [f for f in filtered if (f.method or "").lower() == value.lower()]
            elif key == "status":
                try:
                    status = int(value)
                except ValueError:
                    continue
                filtered = [f for f in filtered if f.status_code == status]
            elif key == "host":
                filtered = [f for f in filtered if value.lower() in urlparse(f.url).netloc.lower()]
            elif key == "path":
                filtered = [f for f in filtered if value.lower() in (urlparse(f.url).path or "/").lower()]
            elif key == "url":
                filtered = [f for f in filtered if value.lower() in f.url.lower()]
            elif key == "has":
                token = value.lower()
                if token == "auth":
                    filtered = [f for f in filtered if f.has_auth_token]
                elif token == "secret":
                    filtered = [f for f in filtered if bool(f.detected_secrets)]
                elif token == "vuln":
                    filtered = [f for f in filtered if bool(f.vulnerabilities)]
                elif token == "api":
                    filtered = [f for f in filtered if f.is_api_call]
        return filtered

    async def start(self, *, port: int = 8081, backend: str = "auto") -> dict[str, Any]:
        self._last_error = ""
        backend = (backend or "auto").strip().lower()
        if backend == "auto":
            env_backend = os.environ.get("VXIS_PROXY_BACKEND", "").strip().lower()
            if env_backend:
                backend = env_backend
        if backend in ("", "auto", "xray"):
            if self.backend == "xray" and self._xray is not None and self._xray.is_running:
                return self.status()
            if MitmProxyManager.is_available():
                self._xray = MitmProxyManager(port=port)
                proxy_url = await self._xray.start()
                self.backend = "xray"
                self._caido = None
                return {
                    **self.status(),
                    "proxy_url": proxy_url,
                    "started": True,
                }
            if backend == "xray":
                self._last_error = "mitmproxy_not_available"
                return self.status()
            backend = "caido"
        if backend == "caido":
            self._caido = CaidoProxyBackend()
            validation = await self._caido.validate()
            if validation.get("ok"):
                self.backend = "caido"
            else:
                self.backend = ""
                self._last_error = str(validation.get("error") or "caido_unavailable")
            return self.status()
        self._last_error = f"unsupported_backend:{backend}"
        return self.status()

    async def stop(self) -> dict[str, Any]:
        if self.backend == "xray" and self._xray is not None:
            await self._xray.stop()
        self.backend = ""
        self._xray = None
        self._caido = None
        return self.status()

    def status(self) -> dict[str, Any]:
        if self.backend == "xray" and self._xray is not None:
            flows = self._analyzed_flows()
            recent = [self._flow_to_request_row(f) for f in flows[-3:]]
            auth_count = sum(1 for f in flows if f.has_auth_token)
            return {
                "backend": "xray",
                "running": bool(self._xray.is_running),
                "proxy_url": self._xray.proxy_url,
                "flow_count": len(flows),
                "auth_flow_count": auth_count,
                "mitm_available": True,
                "capture_dir": getattr(self._xray, "_capture_dir", ""),
                "scope": self.scope.to_dict(),
                "recent_requests": recent,
                "last_error": self._last_error,
            }
        if self.backend == "caido" and self._caido is not None:
            st = self._caido.status()
            return {
                "backend": "caido",
                "running": st.get("configured", False),
                "proxy_url": st.get("proxy_url", ""),
                "flow_count": 0,
                "auth_flow_count": 0,
                "scope": self.scope.to_dict(),
                "recent_requests": [],
                "last_error": self._last_error,
            }
        return {
            "backend": "disabled",
            "running": False,
            "proxy_url": "",
            "flow_count": 0,
            "auth_flow_count": 0,
            "mitm_available": MitmProxyManager.is_available(),
            "scope": self.scope.to_dict(),
            "recent_requests": [],
            "last_error": self._last_error,
        }

    def active_proxy_url(self) -> str | None:
        status = self.status()
        if status.get("running"):
            return str(status.get("proxy_url") or "") or None
        return None

    async def list_requests(
        self,
        *,
        filter_expr: str = "",
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        if self.backend == "caido" and self._caido is not None:
            return await self._caido.list_requests(
                httpql_filter=filter_expr,
                page=page,
                page_size=page_size,
            )
        flows = self._filter_flows(self._analyzed_flows(), filter_expr)
        total = len(flows)
        start = max(page - 1, 0) * page_size
        rows = [self._flow_to_request_row(f) for f in flows[start:start + page_size]]
        return {
            "backend": "xray" if self.backend == "xray" else "disabled",
            "count": len(rows),
            "page": page,
            "page_size": page_size,
            "total_count": total,
            "requests": rows,
        }

    async def view_request(self, request_id: str, *, part: str = "request") -> dict[str, Any]:
        if self.backend == "caido" and self._caido is not None:
            return await self._caido.view_request(request_id, part=part)
        flow = next((f for f in self._analyzed_flows() if f.id == request_id), None)
        if flow is None:
            return {"error": f"request {request_id} not found"}
        if part == "response":
            headers = dict(flow.response_headers)
            body = flow.response_body or ""
        else:
            headers = dict(flow.request_headers)
            body = flow.request_body or ""
        return {
            "backend": "xray",
            "request_id": flow.id,
            "part": part,
            "method": flow.method,
            "url": flow.url,
            "status_code": flow.status_code,
            "headers": headers,
            "body": body,
            "body_preview": _clip(body, 1200),
        }

    async def repeat_request(
        self,
        request_id: str,
        *,
        overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        flow = next((f for f in self._analyzed_flows() if f.id == request_id), None)
        if flow is None:
            return {"ok": False, "error": f"request {request_id} not found"}
        overrides = dict(overrides or {})
        method = str(overrides.get("method") or flow.method or "GET").upper()
        url = str(overrides.get("url") or flow.url)
        headers = dict(flow.request_headers)
        headers.update({str(k): str(v) for k, v in (overrides.get("headers") or {}).items()})
        for name in overrides.get("remove_headers") or []:
            headers.pop(str(name), None)
        params = overrides.get("params")
        if params:
            parsed = urlparse(url)
            merged = dict(parse_qsl(parsed.query, keep_blank_values=True))
            merged.update({str(k): str(v) for k, v in dict(params).items()})
            url = urlunparse(parsed._replace(query=urlencode(merged, doseq=True)))
        body = overrides.get("body")
        if body is None:
            body = flow.request_body or ""
        body_replacements = overrides.get("body_replacements") or {}
        for old, new in dict(body_replacements).items():
            body = str(body).replace(str(old), str(new))
        json_payload = overrides.get("json")
        proxy_url = self.active_proxy_url()
        client_kwargs: dict[str, Any] = {
            "timeout": 20.0,
            "follow_redirects": True,
            "verify": False,
        }
        if proxy_url:
            client_kwargs["proxy"] = proxy_url
        async with httpx.AsyncClient(**client_kwargs) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=None if json_payload is not None else body,
                json=json_payload,
            )
        return {
            "ok": True,
            "request_id": request_id,
            "replayed_method": method,
            "url": str(resp.url),
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
            "body_preview": _clip(resp.text if hasattr(resp, "text") else "", 1200),
            "body_length": len(resp.text if hasattr(resp, "text") else ""),
        }

    async def scope_rules(
        self,
        *,
        action: str = "get",
        allowlist: list[str] | None = None,
        denylist: list[str] | None = None,
    ) -> dict[str, Any]:
        action = action.lower().strip()
        if action == "clear":
            self.scope = ProxyScope()
        elif action in {"set", "update"}:
            if allowlist is not None:
                self.scope.allowlist = [str(p).strip() for p in allowlist if str(p).strip()]
            if denylist is not None:
                self.scope.denylist = [str(p).strip() for p in denylist if str(p).strip()]
        return {
            "backend": self.backend or "disabled",
            "scope": self.scope.to_dict(),
            "flow_count": self.status().get("flow_count", 0),
        }

    async def list_sitemap(self) -> dict[str, Any]:
        if self.backend == "caido" and self._caido is not None:
            return await self._caido.list_sitemap()
        nodes: dict[tuple[str, str], dict[str, Any]] = {}
        for flow in self._analyzed_flows():
            parsed = urlparse(flow.url)
            host = parsed.netloc
            path = parsed.path or "/"
            key = (host, path)
            node = nodes.setdefault(
                key,
                {
                    "id": f"{host}{path}",
                    "host": host,
                    "path": path,
                    "request_count": 0,
                    "methods": set(),
                    "status_codes": set(),
                },
            )
            node["request_count"] += 1
            node["methods"].add(flow.method or "GET")
            if flow.status_code:
                node["status_codes"].add(flow.status_code)
        entries = []
        for node in sorted(nodes.values(), key=lambda item: (item["host"], item["path"])):
            entries.append(
                {
                    "id": node["id"],
                    "host": node["host"],
                    "path": node["path"],
                    "request_count": node["request_count"],
                    "methods": sorted(node["methods"]),
                    "status_codes": sorted(node["status_codes"]),
                }
            )
        return {
            "backend": "xray" if self.backend == "xray" else "disabled",
            "count": len(entries),
            "entries": entries,
        }

    async def view_sitemap_entry(self, entry_id: str) -> dict[str, Any]:
        if self.backend == "caido" and self._caido is not None:
            return {"error": "view_sitemap_entry not yet implemented for caido backend"}
        flows = [
            self._flow_to_request_row(flow)
            for flow in self._analyzed_flows()
            if f"{urlparse(flow.url).netloc}{urlparse(flow.url).path or '/'}" == entry_id
        ]
        if not flows:
            return {"error": f"sitemap entry {entry_id} not found"}
        return {
            "backend": "xray",
            "entry_id": entry_id,
            "request_count": len(flows),
            "requests": flows[:20],
        }


_RUNTIME: ProxyRuntime | None = None


def get_proxy_runtime() -> ProxyRuntime:
    global _RUNTIME
    if _RUNTIME is None:
        _RUNTIME = ProxyRuntime()
    return _RUNTIME


def get_active_proxy_url() -> str | None:
    return get_proxy_runtime().active_proxy_url()


def get_proxy_status_snapshot() -> dict[str, Any]:
    return get_proxy_runtime().status()


async def shutdown_proxy_runtime() -> None:
    runtime = get_proxy_runtime()
    if runtime.status().get("running"):
        await runtime.stop()


def reset_proxy_runtime_for_tests() -> None:
    global _RUNTIME
    _RUNTIME = None
