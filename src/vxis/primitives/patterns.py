"""Pattern-matching primitives — deterministic, rule-based. No LLM calls.

Every function here uses regex or string matching only. They are safe to call
thousands of times per scan without incurring any model cost.
"""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from typing import Any

from vxis.scope.pii_detector import PII_PATTERNS

# ── SQL injection signatures ──────────────────────────────────────

_SQL_ERROR_PATTERNS: tuple[tuple[str, str], ...] = (
    # MySQL
    (r"you have an error in your sql syntax", "mysql"),
    (r"warning.*mysql_", "mysql"),
    (r"mysql_fetch_(array|assoc|row|object)", "mysql"),
    (r"mysqli?_num_rows", "mysql"),
    (r"com\.mysql\.jdbc", "mysql"),
    # PostgreSQL
    (r"pg_query\(\)", "postgresql"),
    (r"postgresql.*error", "postgresql"),
    (r"pg_exec\(\)", "postgresql"),
    (r"unterminated quoted string at or near", "postgresql"),
    (r"org\.postgresql\.util\.psqlexception", "postgresql"),
    # MSSQL
    (r"microsoft.*odbc.*sql server", "mssql"),
    (r"unclosed quotation mark after the character string", "mssql"),
    (r"system\.data\.sqlclient\.sqlexception", "mssql"),
    (r"\[sql server\]", "mssql"),
    # Oracle
    (r"ora-\d{5}", "oracle"),
    (r"oracle.*driver", "oracle"),
    (r"oci_parse", "oracle"),
    # SQLite
    (r"sqlite3?\.(operational|database)error", "sqlite"),
    (r"sqlite_exception", "sqlite"),
    # Generic
    (r"sql syntax.*error", "generic"),
    (r"quoted string not properly terminated", "generic"),
)


def detect_sql_injection(response_body: str, status: int) -> dict:
    """Detect SQL injection vulnerability markers in an HTTP response.

    Args:
        response_body: Raw response body.
        status: HTTP status code.

    Returns:
        dict with keys: detected (bool), dbms (str), matches (list), confidence (float).
    """
    if not response_body:
        return {"detected": False, "dbms": "", "matches": [], "confidence": 0.0}

    body = response_body.lower()
    matches: list[str] = []
    dbms_hits: dict[str, int] = {}

    for pattern, dbms in _SQL_ERROR_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            matches.append(pattern)
            dbms_hits[dbms] = dbms_hits.get(dbms, 0) + 1

    if not matches:
        return {"detected": False, "dbms": "", "matches": [], "confidence": 0.0}

    top_dbms = max(dbms_hits.items(), key=lambda kv: kv[1])[0]
    confidence = min(1.0, 0.6 + 0.15 * len(matches))
    if status >= 500:
        confidence = min(1.0, confidence + 0.1)

    return {
        "detected": True,
        "dbms": top_dbms,
        "matches": matches,
        "confidence": round(confidence, 2),
    }


# ── XSS reflection ────────────────────────────────────────────────


def detect_xss_reflection(response_body: str, payload: str) -> dict:
    """Check whether an XSS payload reflects unescaped in the response body.

    Returns:
        dict with keys: detected, reflected, escaped, context.
    """
    if not payload or not response_body:
        return {"detected": False, "reflected": False, "escaped": False, "context": ""}

    raw_present = payload in response_body
    escaped_present = html.escape(payload) in response_body

    context = ""
    if raw_present:
        idx = response_body.find(payload)
        start = max(0, idx - 20)
        end = min(len(response_body), idx + len(payload) + 20)
        context = response_body[start:end]
        # Determine tag/attribute context
        before = response_body[:idx]
        last_lt = before.rfind("<")
        last_gt = before.rfind(">")
        if last_lt > last_gt:
            context_type = "tag"
        elif "=" in response_body[max(0, idx - 5) : idx]:
            context_type = "attribute"
        else:
            context_type = "text"
    else:
        context_type = "none"

    return {
        "detected": raw_present and not escaped_present,
        "reflected": raw_present,
        "escaped": escaped_present and not raw_present,
        "context": context,
        "context_type": context_type,
    }


# ── Path traversal ────────────────────────────────────────────────

_TRAVERSAL_MARKERS: tuple[str, ...] = (
    "root:x:0:0:",
    "root:*:0:0:",
    "daemon:x:",
    "[boot loader]",
    "[fonts]",
    "[extensions]",
    "for 16-bit app support",
    "# /etc/shadow",
    "# /etc/hosts",
    "# localhost name resolution",
)


def detect_path_traversal(response_body: str) -> dict:
    """Detect path traversal by searching for known system-file signatures."""
    if not response_body:
        return {"detected": False, "file": "", "matches": []}

    hits: list[str] = []
    identified = ""
    for marker in _TRAVERSAL_MARKERS:
        if marker.lower() in response_body.lower():
            hits.append(marker)
            if not identified:
                if "root:" in marker:
                    identified = "/etc/passwd"
                elif "boot loader" in marker:
                    identified = "boot.ini"
                elif "fonts" in marker or "extensions" in marker:
                    identified = "win.ini"
                elif "shadow" in marker:
                    identified = "/etc/shadow"
                elif "hosts" in marker:
                    identified = "/etc/hosts"

    return {
        "detected": bool(hits),
        "file": identified,
        "matches": hits,
    }


# ── SSRF ──────────────────────────────────────────────────────────

_SSRF_INDICATORS: tuple[str, ...] = (
    "169.254.169.254",           # AWS metadata
    "metadata.google.internal",  # GCP
    "metadata.azure.com",        # Azure
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "::1",
    "instance-identity",
    "iam/security-credentials",
    "computeMetadata",
)


def detect_ssrf(response_body: str, status: int, timing_ms: int) -> dict:
    """Detect SSRF indicators from body content, status, and response timing."""
    body = (response_body or "")[:50000]
    hits: list[str] = []
    for marker in _SSRF_INDICATORS:
        if marker.lower() in body.lower():
            hits.append(marker)

    # Private IP ranges in body
    priv_ip = re.findall(
        r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b",
        body,
    )

    slow = timing_ms > 5000
    detected = bool(hits) or bool(priv_ip) or (slow and status in (0, 500, 504))

    confidence = 0.0
    if hits:
        confidence = 0.9
    elif priv_ip:
        confidence = 0.6
    elif slow:
        confidence = 0.3

    return {
        "detected": detected,
        "indicators": hits,
        "private_ips": list(set(priv_ip)),
        "slow_response": slow,
        "confidence": round(confidence, 2),
    }


# ── WAF fingerprint ───────────────────────────────────────────────

_WAF_FINGERPRINTS: tuple[tuple[str, str, str], ...] = (
    # (waf_name, where, pattern)
    ("cloudflare", "header", r"cf-ray|__cfduid|cloudflare"),
    ("cloudflare", "body", r"attention required.*cloudflare|cloudflare ray id"),
    ("akamai", "header", r"akamaighost|x-akamai"),
    ("akamai", "body", r"akamai|reference #\d+\.[0-9a-f]+"),
    ("modsecurity", "header", r"mod_security|modsecurity"),
    ("modsecurity", "body", r"mod_security|not acceptable"),
    ("imperva", "header", r"x-iinfo|incap_ses|visid_incap"),
    ("imperva", "body", r"incapsula|imperva"),
    ("sucuri", "header", r"x-sucuri|sucuri"),
    ("sucuri", "body", r"sucuri website firewall"),
    ("f5_bigip", "header", r"bigipserver|f5-"),
    ("f5_bigip", "body", r"the requested url was rejected"),
    ("aws_waf", "header", r"x-amzn-requestid|x-amz-cf-id|awselb"),
    ("aws_waf", "body", r"aws.*waf"),
    ("barracuda", "header", r"barra_counter_session|barracuda"),
    ("fortinet", "header", r"fortigate|fortiweb"),
    ("fortinet", "body", r"fortinet|fortiweb"),
)


def detect_waf(response_body: str, status: int, headers: dict) -> dict:
    """Fingerprint the WAF (if any) from response headers and body."""
    header_blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items()).lower()
    body_blob = (response_body or "")[:8000].lower()

    detected: list[str] = []
    for name, where, pattern in _WAF_FINGERPRINTS:
        blob = header_blob if where == "header" else body_blob
        if re.search(pattern, blob):
            if name not in detected:
                detected.append(name)

    blocked = status in (403, 406, 419, 429, 501, 503) and bool(detected)
    return {
        "detected": bool(detected),
        "wafs": detected,
        "primary": detected[0] if detected else "",
        "blocked": blocked,
        "status": status,
    }


# ── Secrets extraction ────────────────────────────────────────────

_SECRET_PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key[\"'\s:=]+[A-Za-z0-9/+=]{40}",
    "github_token": r"gh[pousr]_[A-Za-z0-9]{36,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "google_api": r"AIza[0-9A-Za-z_\-]{35}",
    "stripe_live": r"sk_live_[0-9a-zA-Z]{24,}",
    "stripe_test": r"sk_test_[0-9a-zA-Z]{24,}",
    "jwt": r"eyJ[A-Za-z0-9_=\-]{10,}\.eyJ[A-Za-z0-9_=\-]{10,}\.[A-Za-z0-9_=\-]{10,}",
    "private_key": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "generic_api_key": r"(?i)(?:api[_-]?key|apikey)[\"'\s:=]+[A-Za-z0-9_\-]{20,}",
    "bearer_token": r"(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}",
    "password_assignment": r"(?i)(?:password|passwd|pwd)[\"'\s:=]+[\"'][^\"']{6,}[\"']",
}


def extract_secrets(text: str) -> dict[str, list[str]]:
    """Extract credentials, API keys, and tokens via regex.

    Returns:
        dict mapping secret_type → list of matches. Types with zero hits are omitted.
        Also merges PII types from vxis.scope.pii_detector.PII_PATTERNS.
    """
    if not text:
        return {}

    out: dict[str, list[str]] = {}
    for name, pattern in _SECRET_PATTERNS.items():
        hits = re.findall(pattern, text)
        if hits:
            out[name] = [h if isinstance(h, str) else "".join(h) for h in hits][:20]

    # Additionally scan for PII types that are not already in secret patterns.
    for name, pattern in PII_PATTERNS.items():
        if name in out:
            continue
        hits = re.findall(pattern, text)
        if hits:
            out[f"pii_{name}"] = [h if isinstance(h, str) else "".join(h) for h in hits][:20]

    return out


# ── HTML form parser ──────────────────────────────────────────────


class _FormExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        adict = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._current = {
                "action": adict.get("action", ""),
                "method": adict.get("method", "GET").upper(),
                "id": adict.get("id", ""),
                "inputs": [],
            }
        elif tag in ("input", "textarea", "select") and self._current is not None:
            self._current["inputs"].append(
                {
                    "tag": tag,
                    "name": adict.get("name", ""),
                    "type": adict.get("type", ""),
                    "value": adict.get("value", ""),
                    "required": "required" in adict,
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def parse_forms(html_text: str) -> list[dict]:
    """Parse HTML and extract all <form> elements with their inputs."""
    if not html_text:
        return []
    parser = _FormExtractor()
    try:
        parser.feed(html_text)
        if parser._current is not None:  # unclosed form
            parser.forms.append(parser._current)
    except Exception:
        return parser.forms
    return parser.forms


# ── OpenAPI / Swagger parser ──────────────────────────────────────


def parse_openapi(spec_text: str) -> dict:
    """Parse a JSON or YAML OpenAPI/Swagger spec and extract endpoints.

    Returns:
        dict with keys: version, title, base_path, endpoints (list of {path, method, params}).
    """
    if not spec_text:
        return {"version": "", "title": "", "base_path": "", "endpoints": []}

    import json

    spec: dict[str, Any] = {}
    try:
        spec = json.loads(spec_text)
    except Exception:
        try:
            import yaml  # type: ignore

            spec = yaml.safe_load(spec_text) or {}
        except Exception:
            return {"version": "", "title": "", "base_path": "", "endpoints": []}

    version = spec.get("openapi") or spec.get("swagger") or ""
    info = spec.get("info") or {}
    title = info.get("title", "")
    base_path = spec.get("basePath", "")
    servers = spec.get("servers") or []
    if servers and not base_path:
        base_path = servers[0].get("url", "") if isinstance(servers[0], dict) else ""

    endpoints: list[dict] = []
    paths = spec.get("paths") or {}
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in {"get", "post", "put", "delete", "patch", "head", "options"}:
                continue
            params = []
            if isinstance(op, dict):
                for p in op.get("parameters") or []:
                    if isinstance(p, dict):
                        params.append(
                            {
                                "name": p.get("name", ""),
                                "in": p.get("in", ""),
                                "required": p.get("required", False),
                            }
                        )
            endpoints.append(
                {
                    "path": path,
                    "method": method.upper(),
                    "params": params,
                }
            )

    return {
        "version": version,
        "title": title,
        "base_path": base_path,
        "endpoints": endpoints,
    }


# ── Response classifier ──────────────────────────────────────────


def classify_response(body: str, content_type: str) -> str:
    """Classify an HTTP response body into one of: json, html, xml, binary, error, text.

    Uses content-type first, falls back to body sniffing.
    """
    ct = (content_type or "").lower()
    if "json" in ct:
        return "json"
    if "html" in ct:
        return "html"
    if "xml" in ct:
        return "xml"
    if ct.startswith(("image/", "audio/", "video/", "application/octet-stream", "application/pdf")):
        return "binary"

    b = (body or "").lstrip()[:200]
    if not b:
        return "text"
    if b.startswith("{") or b.startswith("["):
        return "json"
    if b.lower().startswith("<!doctype html") or b.lower().startswith("<html"):
        return "html"
    if b.startswith("<?xml") or b.startswith("<"):
        return "xml"
    if re.search(r"error|exception|traceback|stack trace", b, re.IGNORECASE):
        return "error"
    return "text"
