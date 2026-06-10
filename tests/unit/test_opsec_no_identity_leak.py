"""Regression tests: VXIS-identifying strings must NOT appear in target-facing source paths.

These tests guard against re-introduction of tool-attribution identifiers that
would reach target systems on the wire (passwords, GraphQL op names, User-Agent
headers, etc.).
"""

from __future__ import annotations

from pathlib import Path

# Absolute paths to source files that are on target-facing code paths.
_REPO_ROOT = Path(__file__).resolve().parents[2]

_ATTEMPT_AUTH = _REPO_ROOT / "src" / "vxis" / "agent" / "skills" / "attempt_auth.py"
_TEST_API_SEC = _REPO_ROOT / "src" / "vxis" / "agent" / "skills" / "test_api_security.py"
_EVIDENCE = _REPO_ROOT / "src" / "vxis" / "agent" / "evidence.py"
_SCAN_LOOP_AUTO = _REPO_ROOT / "src" / "vxis" / "agent" / "scan_loop_run_auto.py"
_WAF_BYPASS_DB = _REPO_ROOT / "src" / "vxis" / "primitives" / "waf_bypass_db.json"
_DEFENSE_SIM = _REPO_ROOT / "src" / "vxis" / "synthesis" / "defense_simulator.py"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# attempt_auth.py
# ---------------------------------------------------------------------------


def test_no_pwned_by_vxis_in_attempt_auth() -> None:
    """'pwned_by_vxis' must not appear in attempt_auth — it was POSTed to the target."""
    assert "pwned_by_vxis" not in _read(_ATTEMPT_AUTH)


def test_no_vxis_negative_control_in_attempt_auth() -> None:
    """'vxis-negative-control' must not appear — it was sent as login email to target."""
    assert "vxis-negative-control" not in _read(_ATTEMPT_AUTH)


def test_negative_control_email_is_generic() -> None:
    """The negative-control email constant must use the generic non-identifying address."""
    assert "baseline-check@example.invalid" in _read(_ATTEMPT_AUTH)


def test_reset_password_uses_secrets_token() -> None:
    """Password reset must use secrets.token_hex for a random, non-identifying password."""
    content = _read(_ATTEMPT_AUTH)
    assert "secrets.token_hex" in content
    assert "import secrets" in content


# ---------------------------------------------------------------------------
# test_api_security.py
# ---------------------------------------------------------------------------


def test_no_vxis_introspection_op_name_in_api_security() -> None:
    """GraphQL op name 'VXISIntrospection' must not appear — it was sent to the target."""
    assert "VXISIntrospection" not in _read(_TEST_API_SEC)


def test_introspection_query_uses_standard_op_name() -> None:
    """GraphQL introspection must use the standard 'IntrospectionQuery' operation name."""
    assert "IntrospectionQuery" in _read(_TEST_API_SEC)


# ---------------------------------------------------------------------------
# evidence.py
# ---------------------------------------------------------------------------


def test_no_vxis_scanner_ua_in_evidence() -> None:
    """'VXIS-SecurityScanner' User-Agent must not appear in evidence.py."""
    assert "VXIS-SecurityScanner" not in _read(_EVIDENCE)


def test_evidence_uses_generic_ua_constant() -> None:
    """evidence.py must define and use a generic Chrome UA constant."""
    content = _read(_EVIDENCE)
    assert "_GENERIC_UA" in content
    assert "Chrome/124.0.0.0 Safari/537.36" in content


# ---------------------------------------------------------------------------
# scan_loop_run_auto.py — sqlmap fingerprint
# ---------------------------------------------------------------------------


def test_sqlmap_uses_random_agent() -> None:
    """sqlmap invocation must include --random-agent to avoid sqlmap UA fingerprint."""
    assert "--random-agent" in _read(_SCAN_LOOP_AUTO)


# ---------------------------------------------------------------------------
# waf_bypass_db.json and defense_simulator.py — burpcollaborator.net
# ---------------------------------------------------------------------------


def test_no_burpcollaborator_in_waf_bypass_db() -> None:
    """'burpcollaborator.net' must not appear in waf_bypass_db.json."""
    assert "burpcollaborator" not in _read(_WAF_BYPASS_DB)


def test_no_burpcollaborator_in_defense_simulator() -> None:
    """'burpcollaborator.net' must not appear in defense_simulator.py."""
    assert "burpcollaborator" not in _read(_DEFENSE_SIM)
