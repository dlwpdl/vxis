"""Target fingerprinting tool — detect web stack + suggest playbooks.

Instead of relying on Brain to interpret raw curl headers and match them to
playbook names, this tool does the detection in code and returns a ranked
list of playbook recommendations. Brain just calls this once and gets a
clear next-step.
"""
from __future__ import annotations

import logging
from typing import Any

from vxis.agent.tool_registry import ToolResult

logger = logging.getLogger(__name__)


# Fingerprint signal library. Each entry: (playbook_name, list of (header_or_body_pattern, kind))
# kind: "header" checks response headers (case-insensitive substring),
#       "cookie" checks Set-Cookie values,
#       "body"   checks response body (case-insensitive substring),
#       "url"    checks the path/url of the response
_SIGNALS: dict[str, list[tuple[str, str]]] = {
    "spring_boot": [
        ("JSESSIONID", "cookie"),
        ("X-Application-Context", "header"),
        ("Whitelabel Error Page", "body"),
        ("Apache-Coyote", "header"),
        ("Server: Jetty", "header"),
        ("Server: Tomcat", "header"),
        ("Server: Undertow", "header"),
        (";jsessionid=", "url"),
    ],
    "express_node_spa": [
        ("X-Powered-By: Express", "header"),
        ("connect.sid=", "cookie"),
        ("io=", "cookie"),
        ("ng-version=", "body"),
        ('id="root"', "body"),
        ('id="app"', "body"),
        ('app-root', "body"),
        ("mat-app-background", "body"),  # Angular Material
        ("mat-typography", "body"),
        ("runtime.", "body"),  # Angular chunk name pattern
        ("main.js", "body"),
        ("polyfills.js", "body"),
        ("X-Recruiting", "header"),  # Juice Shop signature
    ],
    "php_wordpress": [
        ("X-Powered-By: PHP", "header"),
        ("PHPSESSID=", "cookie"),
        ("wp-content/", "body"),
        ("wp-includes/", "body"),
        ("wp-json/", "body"),
        ('name="generator" content="WordPress', "body"),
        ("laravel_session", "cookie"),
        ("XSRF-TOKEN", "cookie"),
    ],
    "django_python": [
        # csrftoken is a strong Django signal — sessionid alone is shared with
        # Spring/Rails/etc. Only count sessionid if csrftoken is also present.
        ("csrftoken=", "cookie"),
        ("X-Frame-Options: DENY", "header"),
        ("Django administration", "body"),
        ("Django tried these URL patterns", "body"),
        ("{% csrf_token %}", "body"),
        ("django-admin", "body"),
        ("csrfmiddlewaretoken", "body"),
    ],
    "rails": [
        ("Phusion Passenger", "header"),
        ("_session_id=", "cookie"),
        ("X-Runtime:", "header"),
        ("X-Request-Id:", "header"),
        ('name="csrf-token"', "body"),
        ("Server: WEBrick", "header"),
        ("Server: Puma", "header"),
        ("Server: Unicorn", "header"),
    ],
    "flask_fastapi": [
        ("Server: Werkzeug", "header"),
        ("Server: gunicorn", "header"),
        ("Server: uvicorn", "header"),
        ("session=", "cookie"),
        ("X-Process-Time:", "header"),
        ("<title>Swagger UI</title>", "body"),
    ],
    "go_web": [
        # Go services often omit Server header entirely — weakest signals
        ("Server: gin-gonic", "header"),
        ("Server: Fiber", "header"),
        ("X-Gin-Version", "header"),
    ],
    "aspnet": [
        ("X-Powered-By: ASP.NET", "header"),
        ("X-AspNet-Version", "header"),
        ("X-AspNetMvc-Version", "header"),
        ("ASP.NET_SessionId=", "cookie"),
        (".AspNetCore", "cookie"),
        ("Server: Microsoft-IIS", "header"),
        ("Server: Kestrel", "header"),
    ],
    "generic_rest_api": [
        ("Content-Type: application/json", "header"),
        ("Access-Control-Allow-Origin:", "header"),
        ("application/hal+json", "header"),
        ("application/vnd.api+json", "header"),
    ],
    # Additional stacks — re-use existing playbooks by aliasing in the
    # signal layer. Shopify/Next.js/Strapi/SvelteKit all map to
    # express_node_spa or generic_rest_api depending on their surface.
    "express_node_spa_additional": [
        # Next.js markers (recommends express_node_spa playbook)
        ("x-powered-by: next.js", "header"),
        ("__next_data__", "body"),
        ("_next/static", "body"),
        # Nuxt / Vue
        ("x-nuxt-fallback", "header"),
        ("_nuxt/", "body"),
        ("__nuxt__", "body"),
        # SvelteKit
        ("x-sveltekit", "header"),
        # Gatsby
        ("gatsby-plugin-", "body"),
        ("___gatsby", "body"),
    ],
    "spring_boot_additional": [
        # Spring variations
        ("X-Content-Type-Options: nosniff", "header"),  # weak
        ("Server: Jetty(", "header"),
        ("jolokia", "body"),
    ],
    "generic_rest_api_additional": [
        # Strapi CMS
        ("x-powered-by: strapi", "header"),
        ("strapi.io", "body"),
        # Ghost blog
        ("x-powered-by: ghost", "header"),
        # Directus
        ("x-directus-version", "header"),
        # Hasura
        ("x-hasura-role", "header"),
        # Shopify
        ("x-shopify-stage", "header"),
        ("shopify-checkout-api-token", "header"),
        ("x-shopid", "header"),
    ],
}


# Alias mapping: additional signal groups map back to existing playbooks
_PLAYBOOK_ALIASES: dict[str, str] = {
    "express_node_spa_additional": "express_node_spa",
    "spring_boot_additional": "spring_boot",
    "generic_rest_api_additional": "generic_rest_api",
}


# Strong signals (weight 3) are framework-exclusive. Weak signals (weight 1)
# are shared across stacks and only count as corroboration. Use substring
# matching (case-insensitive) against this set to assign weight.
_STRONG_SIGNALS: frozenset[str] = frozenset({
    # Spring Boot strong
    "jsessionid", "apache-coyote", "whitelabel error page", "x-application-context",
    # Express/Node strong
    "x-powered-by: express", "ng-version=", "mat-app-background",
    "connect.sid=", "app-root", "x-recruiting",
    # PHP/WP strong
    "x-powered-by: php", "phpsessid=", "wp-content", "wp-includes",
    'name="generator" content="wordpress', "laravel_session",
    # Django strong
    "csrftoken=", "django administration", "django tried these",
    "{% csrf_token %}", "csrfmiddlewaretoken", "django-admin",
    # Rails strong
    "phusion passenger", "x-runtime:", 'name="csrf-token"',
    "server: webrick", "server: puma", "server: unicorn",
    # Flask/FastAPI strong
    "server: werkzeug", "server: gunicorn", "server: uvicorn",
    "<title>swagger ui</title>", "x-process-time:",
    # Go strong
    "server: gin-gonic", "server: fiber", "x-gin-version",
    # ASP.NET strong
    "x-powered-by: asp.net", "x-aspnet-version", "x-aspnetmvc-version",
    "asp.net_sessionid=", ".aspnetcore", "server: microsoft-iis",
    "server: kestrel",
})


def _score_playbooks(
    headers: str,
    body: str,
    url: str,
) -> list[tuple[str, int, list[str]]]:
    """Return [(playbook_name, score, matched_signals), ...] sorted desc.

    Scoring: strong signals (framework-exclusive) = 3 points, weak signals
    (shared) = 1 point. This prevents false positives from cookie-name
    collisions like sessionid= matching both Django and Spring/Rails.
    """
    headers_l = headers.lower()
    body_l = body.lower()
    url_l = url.lower()
    results: list[tuple[str, int, list[str]]] = []

    # Accumulate scores per real playbook (aliases are merged here)
    agg: dict[str, tuple[int, list[str]]] = {}
    for playbook, signals in _SIGNALS.items():
        score = 0
        matched: list[str] = []
        for pattern, kind in signals:
            haystack = ""
            if kind == "header" or kind == "cookie":
                haystack = headers_l
            elif kind == "body":
                haystack = body_l
            elif kind == "url":
                haystack = url_l
            if pattern.lower() in haystack:
                weight = 3 if pattern.lower() in _STRONG_SIGNALS else 1
                score += weight
                matched.append(f"{pattern} (×{weight})")
        if score <= 0:
            continue
        # Merge alias groups back to the real playbook name
        real_name = _PLAYBOOK_ALIASES.get(playbook, playbook)
        if real_name in agg:
            prev_score, prev_matched = agg[real_name]
            agg[real_name] = (prev_score + score, prev_matched + matched)
        else:
            agg[real_name] = (score, matched)

    results = [(name, s, m) for name, (s, m) in agg.items()]
    results.sort(key=lambda x: x[1], reverse=True)
    return results


class FingerprintTargetTool:
    name = "fingerprint_target"
    description = (
        "Detect the web stack of a target by fetching the root page and "
        "inspecting headers/body. Returns a ranked list of recommended "
        "playbooks. Call this ONCE at the start of a scan — it replaces "
        "manual curl + header inspection and tells you exactly which "
        "playbooks to load_playbook for."
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "Full target URL including scheme and host (e.g. http://localhost:3000)",
            },
        },
        "required": ["url"],
    }

    async def run(self, **kwargs: Any) -> ToolResult:
        url = str(kwargs.get("url", "")).strip()
        if not url:
            return ToolResult(
                ok=False,
                summary="fingerprint_target: url is required",
                error="missing_url",
            )

        try:
            import httpx
        except ImportError:
            return ToolResult(
                ok=False,
                summary="fingerprint_target: httpx not installed",
                error="no_httpx",
            )

        # Fetch the root page + a known-fake path to detect SPA baseline
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=False, verify=False) as c:
                root = await c.get(url)
                fake = await c.get(url.rstrip("/") + "/definitely-not-real-xyz-probe")
        except Exception as e:
            return ToolResult(
                ok=False,
                summary=f"fingerprint_target: fetch failed: {type(e).__name__}: {e}",
                error="fetch_failed",
            )

        # Build the raw header block for signal matching
        header_block = "\n".join(f"{k}: {v}" for k, v in root.headers.items())
        # Also include Set-Cookie from fake request (some frameworks set cookies
        # on error paths too)
        if "set-cookie" in fake.headers:
            header_block += f"\nSet-Cookie(fake): {fake.headers.get('set-cookie', '')}"

        # Sample first 8k AND last 4k of body — Angular/React apps often
        # put their <app-root>/<div id="root"> near the end of the HTML
        body_text = root.text if root.text else ""
        if len(body_text) > 12000:
            body_sample = body_text[:8000] + "\n...\n" + body_text[-4000:]
        else:
            body_sample = body_text

        scored = _score_playbooks(header_block, body_sample, url)

        # SPA detection: same size on root and fake path
        is_spa = (len(root.content) == len(fake.content) and root.status_code == 200)
        spa_note = (
            f"SPA detected — baseline shell size = {len(root.content)} bytes. "
            f"Use -fs {len(root.content)} for ffuf filtering."
            if is_spa
            else "Not a SPA (responses differ for real vs fake paths)."
        )

        # Always append generic playbooks as final recommendations
        recommended = [p[0] for p in scored[:3]]
        if "generic_sensitive_files" not in recommended:
            recommended.append("generic_sensitive_files")
        if "injection_vectors" not in recommended:
            recommended.append("injection_vectors")

        return ToolResult(
            ok=True,
            data={
                "url": url,
                "root_status": root.status_code,
                "root_size": len(root.content),
                "fake_status": fake.status_code,
                "fake_size": len(fake.content),
                "is_spa": is_spa,
                "spa_note": spa_note,
                "headers": dict(root.headers),
                "matches": [
                    {"playbook": p, "score": s, "signals": sig}
                    for p, s, sig in scored
                ],
                "recommended_playbooks": recommended,
            },
            summary=(
                f"fingerprint: root={root.status_code} ({len(root.content)}B), "
                f"fake={fake.status_code} ({len(fake.content)}B), "
                f"spa={'yes' if is_spa else 'no'}. "
                f"Load these playbooks: {', '.join(recommended)}"
            ),
        )
