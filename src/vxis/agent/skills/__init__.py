"""Skills — executable attack capabilities for the Brain.

Each skill is a self-contained async function that performs a complete
attack test and returns structured results. Brain decides WHICH skill
to run WHERE — the skill handles HOW.

One skill call = dozens of payloads tested = one LLM decision.
"""
from __future__ import annotations

from vxis.agent.skills.enumerate_endpoints import execute as enumerate_endpoints
from vxis.agent.skills.test_injection import execute as test_injection
from vxis.agent.skills.attempt_auth import execute as attempt_auth
from vxis.agent.skills.post_auth_enum import execute as post_auth_enum
from vxis.agent.skills.test_sensitive_files import execute as test_sensitive_files
from vxis.agent.skills.test_idor import execute as test_idor
from vxis.agent.skills.test_xss import execute as test_xss
from vxis.agent.skills.test_auth_deep import execute as test_auth_deep
from vxis.agent.skills.test_csrf import execute as test_csrf
from vxis.agent.skills.test_ssrf import execute as test_ssrf
from vxis.agent.skills.test_api_security import execute as test_api_security
from vxis.agent.skills.test_misconfig import execute as test_misconfig
from vxis.agent.skills.test_business_logic import execute as test_business_logic
from vxis.agent.skills.test_crypto import execute as test_crypto
from vxis.agent.skills.test_infra import execute as test_infra

# Desktop skills — phase-J slice (macOS-only). Phase-F (Windows full
# desktop pipeline) ships the remaining 7. We import lazily so that
# environments without the desktop adapter installed still work.
try:
    from vxis.agent.skills.desktop.test_local_storage_secrets import (
        execute as test_local_storage_secrets,
    )
except ImportError:  # pragma: no cover — desktop skill optional today
    test_local_storage_secrets = None  # type: ignore[assignment]

try:
    from vxis.agent.skills.desktop.test_electron_misconfig import (
        execute as test_electron_misconfig,
    )
except ImportError:  # pragma: no cover — desktop skill optional today
    test_electron_misconfig = None  # type: ignore[assignment]

SKILL_REGISTRY: dict[str, dict] = {
    "enumerate_endpoints": {
        "fn": enumerate_endpoints,
        "description": "Scan 100+ common paths on a target. Returns all accessible endpoints with status/size.",
        "args": "target_url (required)",
    },
    "test_injection": {
        "fn": test_injection,
        "description": "Test SQLi/XSS/SSTI on a URL+parameter. Tries 40+ payloads, detects error-based, blind, and reflected injection.",
        "args": "url (required, with parameter e.g. http://x/search?q=), param_name (optional)",
    },
    "attempt_auth": {
        "fn": attempt_auth,
        "description": "Try to authenticate: default creds, SQLi bypass, password reset. Returns token if successful.",
        "args": "target_url (required)",
    },
    "post_auth_enum": {
        "fn": post_auth_enum,
        "description": "With an auth token, enumerate all authenticated endpoints and test access controls.",
        "args": "target_url (required), token (required)",
    },
    "test_sensitive_files": {
        "fn": test_sensitive_files,
        "description": "Scan for sensitive files: backups, configs, keys, logs, git, env, etc.",
        "args": "target_url (required)",
    },
    "test_idor": {
        "fn": test_idor,
        "description": "Test IDOR on an endpoint by iterating IDs with/without auth.",
        "args": "url_pattern (required, with {id} placeholder), token (optional)",
    },
    "test_xss": {
        "fn": test_xss,
        "description": "Test XSS (reflected, stored, DOM) with 20+ payloads on URL+parameter.",
        "args": "url (required, with parameter), param_name (optional)",
    },
    "test_auth_deep": {
        "fn": test_auth_deep,
        "description": "Deep auth testing: JWT alg:none, RS256->HS256 confusion, session fixation, password reset poisoning.",
        "args": "target_url (required), token (optional, JWT for alg attacks)",
    },
    "test_csrf": {
        "fn": test_csrf,
        "description": "CSRF testing on state-changing endpoints: missing tokens, SameSite cookies.",
        "args": "target_url (required), token (optional)",
    },
    "test_ssrf": {
        "fn": test_ssrf,
        "description": "SSRF testing: internal IPs, cloud metadata, file://, DNS rebinding on URL params.",
        "args": "url (required, with URL-accepting parameter), param_name (optional)",
    },
    "test_api_security": {
        "fn": test_api_security,
        "description": "API security: mass assignment, rate limiting, HTTP verb tampering, parameter pollution.",
        "args": "target_url (required), token (optional)",
    },
    "test_misconfig": {
        "fn": test_misconfig,
        "description": "Misconfiguration: security headers, CORS, debug endpoints, verbose errors.",
        "args": "target_url (required)",
    },
    "test_business_logic": {
        "fn": test_business_logic,
        "description": "Business logic: negative quantities, price manipulation, state skipping, race conditions.",
        "args": "target_url (required), token (optional)",
    },
    "test_crypto": {
        "fn": test_crypto,
        "description": "Crypto weaknesses: TLS versions, hardcoded secrets in JS, weak password hashes.",
        "args": "target_url (required)",
    },
    "test_infra": {
        "fn": test_infra,
        "description": "Infrastructure: exposed .git, .env, cloud metadata, Firebase, subdomain enumeration.",
        "args": "target_url (required)",
    },
}

if test_local_storage_secrets is not None:
    SKILL_REGISTRY["test_local_storage_secrets"] = {
        "fn": test_local_storage_secrets,
        "description": (
            "Desktop-only: walk the .app bundle / directory / parent-of-binary "
            "and match each text file against hardcoded-secret patterns "
            "(AWS, GitHub, JWT, private keys, generic api_key='...'). Use when "
            "target.kind == desktop."
        ),
        "args": "target_url (required — path to .app / dir / binary)",
    }

if test_electron_misconfig is not None:
    SKILL_REGISTRY["test_electron_misconfig"] = {
        "fn": test_electron_misconfig,
        "description": (
            "Desktop-only: detect Electron-specific misconfigurations "
            "(nodeIntegration, contextIsolation, webSecurity). Use when "
            "target.kind == desktop and the app uses Electron framework."
        ),
        "args": (
            "target_url (required — path to .app bundle or directory containing "
            "Electron app)"
        ),
    }
