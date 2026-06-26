"""attack_category — turn internal ids (skill names, WEB-*-NNN vector codes,
finding types, vector ids) into the human pentest-category label the TUI shows
per sub-agent (Strix-style: "SQL Injection", "SSRF", …)."""
import pytest

from vxis.agent.attack_taxonomy import attack_category


@pytest.mark.parametrize("raw,expected", [
    # skill names
    ("skill:test_injection", "SQL Injection"),
    ("test_injection", "SQL Injection"),
    ("skill:test_ssrf", "SSRF"),
    ("test_xss", "XSS"),
    ("skill:test_idor", "IDOR"),
    ("test_auth_deep", "Auth / JWT"),
    ("test_csrf", "CSRF"),
    ("test_misconfig", "Security Misconfiguration"),
    ("test_business_logic", "Business Logic"),
    ("test_crypto", "Cryptographic Failure"),
    ("test_sensitive_files", "Sensitive Data Exposure"),
    ("test_api_security", "Broken Access Control"),
    ("enumerate_endpoints", "Recon"),
    # WEB-*-NNN vector codes
    ("WEB-SQLI-001", "SQL Injection"),
    ("WEB-CMDI-001", "Command Injection / RCE"),
    ("WEB-SSRF-001", "SSRF"),
    ("WEB-XSS-002", "XSS"),
    ("WEB-AC-001", "IDOR"),
    ("WEB-AUTH-003", "Auth / JWT"),
    ("WEB-API-009", "Broken Access Control"),
    ("WEB-BIZ-001", "Business Logic"),
    # finding-style ids
    ("finding:sqli", "SQL Injection"),
    ("finding:ssrf", "SSRF"),
])
def test_known_categories(raw, expected):
    assert attack_category(raw) == expected


def test_unknown_id_is_humanized_not_raw():
    # No category match → readable Title Case, never the raw token / prefix.
    out = attack_category("web:auth-bypass")
    assert out and ":" not in out and out[0].isupper()


def test_blank_is_general():
    assert attack_category("") == "General"
    assert attack_category(None) == "General"  # type: ignore[arg-type]
