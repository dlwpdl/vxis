"""Human pentest-category labels for the live displays.

The scan's internal identifiers — skill names (``test_ssrf``), vector codes
(``WEB-SQLI-001``), finding types (``sqli``), free vector ids (``web:auth-bypass``)
— are noise to an operator watching a scan. ``attack_category`` maps any of them
to the category a human recognises ("SQL Injection", "SSRF", …) so the TUI shows
*what is being pentested*, not an opaque id.

Two-pronged + ordered so short/ambiguous tokens can't over-match:
1. ``WEB-XXX-NNN`` / ``DESK-XXX-NNN`` codes → the middle token's label.
2. otherwise keyword rules (most-specific first) against the lowered id.
3. otherwise a humanised fallback (Title Case, prefixes/numbers stripped).

Pure: no I/O, no state.
"""
from __future__ import annotations

# Exact canonical WEB vector IDs whose middle token is intentionally broad
# (AC/API/AUTH) but the operator label should stay specific.
_CODE_EXACT: dict[str, str] = {
    "WEB-AC-001": "IDOR",
    "WEB-AC-002": "Broken Access Control",
    "WEB-AC-003": "Broken Access Control",
    "WEB-AC-004": "Path Traversal",
    "WEB-AC-005": "Recon",
    "WEB-AUTH-003": "Auth / JWT",
    "WEB-AUTH-004": "Auth / JWT",
    "WEB-AUTH-007": "OAuth / SSO",
    "WEB-API-001": "API Security",
    "WEB-API-002": "API Security",
    "WEB-API-003": "API Security",
    "WEB-API-005": "API Security",
    "WEB-API-008": "API Security",
    "WEB-API-009": "Broken Access Control",
    "WEB-BIZ-001": "Business Logic",
}

# Middle token of a WEB-XXX-NNN / DESK-XXX-NNN vector code → label.
_CODE_TOKEN: dict[str, str] = {
    "SQLI": "SQL Injection",
    "CMDI": "Command Injection / RCE",
    "RCE": "Command Injection / RCE",
    "SSRF": "SSRF",
    "XSS": "XSS",
    "IDOR": "IDOR",
    "JWT": "Auth / JWT",
    "AUTH": "Authentication",
    "AC": "Broken Access Control",
    "API": "API Security",
    "CSRF": "CSRF",
    "MISC": "Security Misconfiguration",
    "MISCONF": "Security Misconfiguration",
    "CRYPTO": "Cryptographic Failure",
    "LOGIC": "Business Logic",
    "BIZ": "Business Logic",
    "BAC": "Broken Access Control",
    "INFO": "Sensitive Data Exposure",
    "INFRA": "Infrastructure",
    "SSTI": "Server-Side Template Injection",
    "XXE": "XXE",
    "LFI": "Sensitive Data Exposure",
    "DESER": "Insecure Deserialization",
    "UPLOAD": "File Upload",
    "WSS": "WebSocket",
    "INJECT": "Injection",
}

# (keywords, label), most-specific first. Keys are matched as substrings of the
# lowered id, so distinctive tokens (sqli/ssrf/idor) are safe; ambiguous ones are
# kept long ("sensitive_files", "business_logic") to avoid false hits.
_KEYWORD_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("sensitive_files", "sensitive", "info_disclosure", "infoleak"), "Sensitive Data Exposure"),
    (("sqli", "sql_injection"), "SQL Injection"),
    (("cmdi", "command_inj", "rce", "code_exec"), "Command Injection / RCE"),
    (("ssrf",), "SSRF"),
    (("xss", "cross_site_script"), "XSS"),
    (("idor",), "IDOR"),
    (("auth_deep", "jwt"), "Auth / JWT"),
    (("csrf",), "CSRF"),
    (("misconfig",), "Security Misconfiguration"),
    (("crypto",), "Cryptographic Failure"),
    (("business_logic",), "Business Logic"),
    (("api_security", "broken_access", "access_control"), "Broken Access Control"),
    (("ssti", "template_inj"), "Server-Side Template Injection"),
    (("xxe",), "XXE"),
    (("infra",), "Infrastructure"),
    (("enumerate", "endpoint", "recon", "post_auth_enum"), "Recon"),
    (("auth",), "Authentication"),
    (("injection",), "SQL Injection"),  # bare test_injection → its primary class
)

_PREFIXES = ("skill:", "finding:", "vector:", "web:", "scan:", "desk:", "test_")


def _humanise(text: str) -> str:
    s = text.strip()
    for p in _PREFIXES:
        if s.lower().startswith(p):
            s = s[len(p):]
            break
    for sep in (":", "-", "_"):
        s = s.replace(sep, " ")
    parts = [p for p in s.split() if not p.isdigit()]
    return " ".join(parts).title() if parts else "General"


def attack_category(raw: str | None) -> str:
    """Map an internal id to a human pentest-category label.

    Blank/None → "General". Unknown ids → a humanised Title-Case form (never the
    raw id with its ``skill:``/``WEB-…`` scaffolding).
    """
    if not raw:
        return "General"
    text = str(raw).strip()
    if not text:
        return "General"

    # 1) Canonical exact code overrides, then WEB-XXX-NNN / DESK-XXX-NNN
    # code → middle token.
    upper = text.upper()
    exact = _CODE_EXACT.get(upper)
    if exact:
        return exact

    upper_parts = upper.split("-")
    if len(upper_parts) >= 2 and upper_parts[1] in _CODE_TOKEN:
        return _CODE_TOKEN[upper_parts[1]]

    # 2) keyword rules against the lowered id.
    low = text.lower()
    for keys, label in _KEYWORD_RULES:
        if any(k in low for k in keys):
            return label

    # 3) humanised fallback.
    return _humanise(text)


__all__ = ["attack_category"]
