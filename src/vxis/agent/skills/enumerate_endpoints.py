"""Skill: enumerate_endpoints — blast common paths, return accessible ones."""
from __future__ import annotations
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

# 120+ common web paths — covers REST APIs, admin panels, configs, debug endpoints
COMMON_PATHS = [
    # API patterns
    "/api/", "/api/v1/", "/api/v2/", "/api/Users/", "/api/users/",
    "/api/Products/", "/api/Orders/", "/api/Feedbacks/", "/api/Complaints/",
    "/api/SecurityQuestions/", "/api/BasketItems/", "/api/Cards/",
    "/api/Deliverys/", "/api/Recycles/", "/api/Quantitys/", "/api/Challenges/",
    "/api/Memories/", "/api/Wallets/", "/api/Addresses/",
    # REST patterns
    "/rest/", "/rest/admin/", "/rest/user/", "/rest/products/",
    "/rest/admin/application-configuration", "/rest/admin/application-version",
    "/rest/products/search?q=", "/rest/languages", "/rest/user/whoami",
    "/rest/user/change-password", "/rest/user/login", "/rest/user/reset-password",
    "/rest/basket/1", "/rest/basket/2", "/rest/wallet/balance",
    "/rest/deluxe-membership", "/rest/memories", "/rest/chatbot/status",
    "/rest/chatbot/respond", "/rest/track-order/1", "/rest/saveLoginIp",
    "/rest/repeat-notification", "/rest/continue-code",
    # Admin/debug
    "/admin/", "/administration/", "/dashboard/", "/debug/", "/console/",
    "/actuator/", "/actuator/health", "/actuator/env", "/actuator/info",
    "/status", "/health", "/healthz", "/info", "/env",
    "/server-status", "/server-info", "/_debug/", "/__debug__/",
    # Files & directories
    "/ftp/", "/files/", "/uploads/", "/backup/", "/backups/", "/data/",
    "/temp/", "/tmp/", "/logs/", "/log/", "/support/logs",
    "/encryptionkeys/", "/keys/", "/certs/", "/ssl/",
    # Configs
    "/.env", "/.git/", "/.git/HEAD", "/.git/config", "/.gitignore",
    "/config", "/config.json", "/config.yml", "/settings",
    "/wp-config.php", "/web.config", "/application.properties",
    "/.htaccess", "/.htpasswd", "/package.json", "/composer.json",
    # Docs
    "/api-docs/", "/swagger/", "/swagger.json", "/swagger-ui/",
    "/openapi.json", "/graphql", "/graphiql",
    # Metrics & monitoring
    "/metrics", "/prometheus", "/grafana/", "/kibana/",
    # Auth
    "/login", "/signin", "/signup", "/register", "/logout",
    "/forgot-password", "/reset-password", "/oauth/", "/auth/",
    "/token", "/.well-known/openid-configuration",
    # Common frameworks
    "/robots.txt", "/sitemap.xml", "/security.txt",
    "/.well-known/security.txt", "/favicon.ico",
    "/humans.txt", "/crossdomain.xml",
    # Misc
    "/redirect", "/redirect?to=https://evil.com", "/video",
    "/profile", "/account", "/settings", "/dataerasure",
    "/b2b/v2/orders", "/snippets", "/accounting",
]


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Enumerate all accessible endpoints on a target.

    Returns:
        {
            "accessible": [{"path": "/api/Users/", "status": 200, "size": 1234}, ...],
            "auth_required": [{"path": ..., "status": 401}, ...],
            "errors": [{"path": ..., "status": 500}, ...],
            "total_scanned": int,
            "baseline_size": int | None,
        }
    """
    import httpx

    target = target_url.rstrip("/")
    accessible: list[dict] = []
    auth_required: list[dict] = []
    errors: list[dict] = []
    baseline_size: int | None = None

    async with httpx.AsyncClient(
        base_url=target, timeout=5, verify=False, follow_redirects=False,
        limits=httpx.Limits(max_connections=20),
    ) as c:
        # Detect SPA baseline
        try:
            r = await c.get("/definitely-not-real-xyz-probe")
            if r.status_code == 200:
                baseline_size = len(r.content)
        except Exception:
            pass

        # Blast all paths concurrently (batches of 20)
        sem = asyncio.Semaphore(20)

        async def check(path: str) -> None:
            async with sem:
                try:
                    r = await c.get(path)
                    size = len(r.content)
                    # Skip SPA baseline responses
                    if baseline_size and size == baseline_size:
                        return
                    if r.status_code == 404:
                        return

                    entry = {"path": path, "status": r.status_code, "size": size}
                    if r.status_code == 200:
                        # Include a body preview for interesting responses
                        if size > 100:
                            entry["preview"] = r.text[:200]
                        accessible.append(entry)
                    elif r.status_code == 401:
                        auth_required.append(entry)
                    elif r.status_code == 500:
                        entry["error_preview"] = r.text[:200]
                        errors.append(entry)
                    elif r.status_code in (301, 302, 303, 307, 308):
                        entry["redirect"] = r.headers.get("location", "")
                        accessible.append(entry)
                except Exception:
                    pass

        await asyncio.gather(*[check(p) for p in COMMON_PATHS])

    # Sort by size descending (bigger = more interesting)
    accessible.sort(key=lambda x: x["size"], reverse=True)
    errors.sort(key=lambda x: x["size"], reverse=True)

    logger.info("enumerate_endpoints: %d accessible, %d auth-required, %d errors",
                len(accessible), len(auth_required), len(errors))

    return {
        "accessible": accessible,
        "auth_required": auth_required,
        "errors": errors,
        "total_scanned": len(COMMON_PATHS),
        "baseline_size": baseline_size,
    }
