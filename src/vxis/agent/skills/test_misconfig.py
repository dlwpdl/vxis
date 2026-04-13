"""Skill: test_misconfig — security headers, CORS, debug endpoints, verbose errors."""
from __future__ import annotations
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)

REQUIRED_HEADERS = [
    ("content-security-policy", "CSP", "high"),
    ("strict-transport-security", "HSTS", "high"),
    ("x-frame-options", "X-Frame-Options", "medium"),
    ("x-content-type-options", "X-Content-Type-Options", "medium"),
    ("x-xss-protection", "X-XSS-Protection", "low"),
    ("referrer-policy", "Referrer-Policy", "low"),
    ("permissions-policy", "Permissions-Policy", "low"),
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]

DEBUG_PATHS = [
    ("/debug", "Debug endpoint"),
    ("/debug/", "Debug directory"),
    ("/_debug/", "Debug panel"),
    ("/actuator", "Spring Actuator"),
    ("/actuator/env", "Actuator environment"),
    ("/actuator/heapdump", "Actuator heap dump"),
    ("/actuator/mappings", "Actuator URL mappings"),
    ("/elmah.axd", "ELMAH error log"),
    ("/trace", "Trace endpoint"),
    ("/console", "H2 console"),
    ("/__debug__/", "Django debug toolbar"),
    ("/server-info", "Server info"),
    ("/info", "Info endpoint"),
    ("/health", "Health check"),
    ("/manage", "Management endpoint"),
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]

CORS_ORIGINS = [
    "https://evil.com",
    "null",
    "https://attacker.example.com",
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Test for security misconfigurations.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int}
    """
    import httpx

    target = target_url.rstrip("/")
    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        # --- Security headers check ---
        tested += 1
        try:
            r = await client.get(target)
            headers_lower = {k.lower(): v for k, v in r.headers.items()}
            missing: list[str] = []
            for header, name, severity in REQUIRED_HEADERS:
                if header not in headers_lower:
                    missing.append(name)
                    findings.append({
                        "type": "missing_security_header",
                        "payload": name,
                        "evidence": f"Header '{name}' not present in response",
                        "severity": severity,
                    })

            # Check for server version disclosure
            server = headers_lower.get("server", "")
            x_powered = headers_lower.get("x-powered-by", "")
            if server and any(c.isdigit() for c in server):
                findings.append({
                    "type": "server_version_disclosure",
                    "payload": f"Server: {server}",
                    "evidence": f"Server header discloses version: {server}",
                    "severity": "low",
                })
            if x_powered:
                findings.append({
                    "type": "tech_disclosure",
                    "payload": f"X-Powered-By: {x_powered}",
                    "evidence": f"Technology stack disclosed: {x_powered}",
                    "severity": "low",
                })
        except Exception:
            pass

        # --- CORS misconfiguration ---
        for origin in CORS_ORIGINS:
            tested += 1
            async with sem:
                try:
                    r = await client.get(target, headers={"Origin": origin})
                    acao = r.headers.get("access-control-allow-origin", "")
                    acac = r.headers.get("access-control-allow-credentials", "")
                    if acao == "*" or acao == origin:
                        severity = "high" if acac.lower() == "true" else "medium"
                        findings.append({
                            "type": "cors_misconfiguration",
                            "payload": f"Origin: {origin}",
                            "evidence": f"ACAO={acao}, ACAC={acac}",
                            "severity": severity,
                        })
                        logger.info("CORS misconfiguration: reflects %s", origin)
                except Exception:
                    pass

        # --- Debug endpoints ---
        async def check_debug(path: str, desc: str) -> None:
            nonlocal tested
            async with sem:
                tested += 1
                try:
                    r = await client.get(f"{target}{path}")
                    if r.status_code == 200 and len(r.content) > 100:
                        findings.append({
                            "type": "debug_endpoint_exposed",
                            "payload": path,
                            "evidence": f"{desc} accessible (status {r.status_code}, {len(r.content)}B)",
                            "response_preview": r.text[:300],
                            "severity": "high",
                        })
                except Exception:
                    pass

        await asyncio.gather(*[check_debug(p, d) for p, d in DEBUG_PATHS])

        # --- Verbose error messages ---
        tested += 1
        async with sem:
            try:
                r = await client.get(f"{target}/{'A' * 500}")
                body = r.text.lower()
                error_sigs = ["traceback", "stack trace", "exception", "at line", "debug", "sqlstate"]
                for sig in error_sigs:
                    if sig in body:
                        findings.append({
                            "type": "verbose_error",
                            "payload": "Long URL causing error",
                            "evidence": f"Error response contains '{sig}'",
                            "response_preview": r.text[:300],
                            "severity": "medium",
                        })
                        break
            except Exception:
                pass

    return {"vulnerable": len(findings) > 0, "findings": findings, "tested": tested}
