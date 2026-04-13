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
}
