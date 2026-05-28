from __future__ import annotations

import json
import shlex
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from vxis.ghost.layer import ghost_layer


def mask_proxy_url(proxy: str | None) -> str:
    raw = str(proxy or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return raw[:80]
    if not parsed.username and not parsed.password:
        return raw[:120]
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    netloc = f"****@{host}{port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))[:120]


def build_ghost_identity(
    component: str,
    *,
    proxy: str | None = None,
    user_agent: str | None = None,
    rotate_proxy: bool = True,
    include_raw: bool = False,
) -> dict[str, Any]:
    if not ghost_layer.is_active():
        return {"active": False, "component": component}
    raw_proxy = proxy if proxy is not None else (ghost_layer.next_proxy() if rotate_proxy else None)
    ua = user_agent or ghost_layer.next_ua()
    identity: dict[str, Any] = {
        "active": True,
        "component": component,
        "proxy": mask_proxy_url(raw_proxy),
        "proxy_mode": "proxied" if raw_proxy else "direct",
        "user_agent": ua,
    }
    if include_raw:
        identity["_proxy_url"] = raw_proxy or ""
    return identity


def public_ghost_identity(identity: dict[str, Any] | None) -> dict[str, Any]:
    if not identity or not identity.get("active"):
        return {"active": False}
    allowed = {
        "active",
        "component",
        "proxy",
        "proxy_mode",
        "user_agent",
        "network_coverage",
    }
    return {
        key: value
        for key, value in identity.items()
        if not key.startswith("_") and key in allowed
    }


def ghost_process_env(identity: dict[str, Any] | None) -> dict[str, str]:
    if not identity or not identity.get("active"):
        return {}
    env = {
        "VXIS_GHOST_ACTIVE": "1",
        "VXIS_GHOST_COMPONENT": str(identity.get("component") or ""),
        "VXIS_GHOST_USER_AGENT": str(identity.get("user_agent") or ""),
    }
    proxy = str(identity.get("_proxy_url") or "").strip()
    if proxy:
        env.update(
            {
                "HTTP_PROXY": proxy,
                "HTTPS_PROXY": proxy,
                "ALL_PROXY": proxy,
                "http_proxy": proxy,
                "https_proxy": proxy,
                "all_proxy": proxy,
            }
        )
    return env


def wrap_shell_command_for_ghost(command: str, *, component: str) -> tuple[str, dict[str, Any]]:
    identity = build_ghost_identity(component, include_raw=True)
    env = ghost_process_env(identity)
    public = public_ghost_identity(identity)
    if not env:
        return command, public
    exports = "; ".join(f"export {key}={shlex.quote(value)}" for key, value in env.items())
    return f"{exports};\n{command}", public


def ghost_python_env_prelude(identity: dict[str, Any] | None) -> str:
    env = ghost_process_env(identity)
    if not env:
        return ""
    return (
        "import os as __vxis_ghost_os\n"
        "__vxis_ghost_os.environ.update("
        + json.dumps(env, ensure_ascii=False)
        + ")\n"
    )


def ghost_status_snapshot() -> dict[str, Any]:
    active = ghost_layer.is_active()
    proxy_pool = list(getattr(ghost_layer, "_proxy_pool", []) or [])
    coverage = {
        "target_session": "ghost_transport" if active else "off",
        "browser": "ghost_proxy_or_ua" if active else "off",
        "shell_exec": "env_proxy" if active and proxy_pool else ("ua_env_only" if active else "off"),
        "python_exec": "env_proxy" if active and proxy_pool else ("ua_env_only" if active else "off"),
        "nmap_scan": "direct_raw_socket" if active else "off",
    }
    return {
        "active": active,
        "proxy_count": len(proxy_pool),
        "proxies": [mask_proxy_url(proxy) for proxy in proxy_pool[:4]],
        "coverage": coverage,
        "warning": (
            "nmap_scan uses raw TCP/UDP sockets and is not anonymized by HTTP/SOCKS proxy env"
            if active
            else ""
        ),
    }
