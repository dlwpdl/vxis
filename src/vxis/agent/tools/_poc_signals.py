"""Canonical PoC / evidence signal sets — single source of truth.

Both finding_tools and verifier_tools previously defined near-identical
marker tuples independently and they diverged (e.g. verifier_tools was
missing 'observed_delta').  This module holds the authoritative union;
both modules import from here.

Naming:
- POC_RESULT_MARKERS   — tokens that indicate an observed server result
- POC_ATTEMPT_MARKERS  — tokens that indicate an exploit attempt was made
- CONTROL_MARKERS      — tokens that indicate a control/baseline run
- HTTP_MARKERS         — HTTP method/version line prefixes
- CONTROL_REQUIRED_TYPES — finding-type substrings that require a control run
- finding_type_needs_control(ft) — predicate driven by CONTROL_REQUIRED_TYPES
"""

from __future__ import annotations

# ── HTTP verb / version markers (also indicate exploit attempts) ─────────────

HTTP_MARKERS: tuple[str, ...] = (
    "HTTP/1.",
    "HTTP/2",
    "GET ",
    "POST ",
    "PUT ",
    "PATCH ",
    "DELETE ",
)

# ── PoC attempt markers — signals that an exploit attempt was made ───────────

POC_ATTEMPT_MARKERS: tuple[str, ...] = (
    "GET ",
    "POST ",
    "PUT ",
    "PATCH ",
    "DELETE ",
    "curl ",
    "sqlmap",
    "payload",
    "request:",
    "control",
    "baseline",
)

# ── Result markers — signals of an observed server response ──────────────────
# Union of finding_tools._POC_RESULT_MARKERS and verifier_tools._RESULT_MARKERS.
# finding_tools had: response_status, status_code, response_excerpt, observed_delta,
#   Location:, sql error, Set-Cookie:, "token", "role", "data", "status",
#   stack trace, Traceback, sqlmap identified, dumped
# verifier_tools had: 200 OK, 201 Created, 202 Accepted, 500 Internal Server Error,
#   Set-Cookie:, "token", "role", "data", "status", stack trace, Traceback,
#   sqlmap identified, dumped  (was MISSING observed_delta, Location:, sql error)

POC_RESULT_MARKERS: tuple[str, ...] = (
    # HTTP status line strings (from verifier_tools)
    "200 OK",
    "201 Created",
    "202 Accepted",
    "500 Internal Server Error",
    # Key/value-style result fields (from finding_tools)
    "response_status",
    "status_code",
    "response_excerpt",
    "observed_delta",  # was missing from verifier_tools
    # Response headers
    "Set-Cookie:",
    "Location:",  # was missing from verifier_tools
    # JSON data fields
    '"token"',
    '"role"',
    '"data"',
    '"status"',
    # Error / exploit-output signals
    "stack trace",
    "Traceback",
    "sql error",  # was missing from verifier_tools
    "sqlmap identified",
    "dumped",
)

# ── Control / baseline markers ───────────────────────────────────────────────
# Union of finding_tools._CONTROL_MARKERS and verifier_tools._CONTROL_MARKERS.
# finding_tools had: control, baseline, negative, without auth, with auth,
#   unauthenticated, authenticated, observed_delta, before:, after:
# verifier_tools had: control, negative, baseline, unauthenticated, authenticated,
#   without auth, with auth, token:null, token="", id=1, id=2, before:, after:
#   (was MISSING observed_delta)

CONTROL_MARKERS: tuple[str, ...] = (
    "control",
    "baseline",
    "negative",
    "without auth",
    "with auth",
    "unauthenticated",
    "authenticated",
    "observed_delta",  # was missing from verifier_tools
    "before:",
    "after:",
    # Extra markers from verifier_tools
    "token:null",
    'token=""',
    "id=1",
    "id=2",
)

# ── Control-required finding types ───────────────────────────────────────────
# Union of finding_tools._CONTROL_REQUIRED_TYPES and the needles in
# verifier_tools._finding_type_needs_control().
# finding_tools had: auth, idor, access, privilege, csrf, business_logic
# verifier_tools had: auth, idor, access, privilege, sql, xss, ssrf, csrf
# Union adds: sql, xss, ssrf (from verifier_tools), business_logic (from finding_tools)

CONTROL_REQUIRED_TYPES: tuple[str, ...] = (
    "auth",
    "idor",
    "access",
    "privilege",
    "csrf",
    "business_logic",  # from finding_tools
    "sql",  # from verifier_tools
    "xss",  # from verifier_tools
    "ssrf",  # from verifier_tools
)


def finding_type_needs_control(finding_type: str) -> bool:
    """Return True iff a PoC for this finding_type must include a control/baseline.

    Injection, auth bypass, IDOR, access-control, and similar differential findings
    require a control run to rule out false positives.  Misconfig and disclosure
    findings — where the raw evidence (e.g. exposed credentials, missing header) is
    self-evident — do not need a separate control run.
    """
    ft = str(finding_type or "").lower()
    return any(needle in ft for needle in CONTROL_REQUIRED_TYPES)
