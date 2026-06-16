"""NOW-2 foundation + 2d — ambient ScanPolicy + exploitation-ceiling gate logic."""
from vxis.agent.policy.runtime_policy import (
    clear_active_policy,
    clear_injection_decision,
    get_active_policy,
    get_injection_decision,
    injection_action_blocked,
    set_active_policy,
    set_injection_decision,
    skill_blocked_by_ceiling,
    tool_blocked_by_ceiling,
)
from vxis.agent.policy.scan_policy import FAIL_CLOSED_DEFAULT, PROFILE_POLICY_TABLE


def test_active_policy_roundtrip():
    assert get_active_policy() is None
    tok = set_active_policy(FAIL_CLOSED_DEFAULT)
    try:
        assert get_active_policy() is FAIL_CLOSED_DEFAULT
    finally:
        clear_active_policy(tok)
    assert get_active_policy() is None


def test_ceiling_blocks_exploitation_below_lateral():
    # none (FAIL_CLOSED_DEFAULT) and read-only (standard/prod) both block shell/python
    assert tool_blocked_by_ceiling("shell_exec", FAIL_CLOSED_DEFAULT) is True
    assert tool_blocked_by_ceiling("python_exec", FAIL_CLOSED_DEFAULT) is True
    assert tool_blocked_by_ceiling("shell_exec", PROFILE_POLICY_TABLE["standard"]) is True


def test_ceiling_allows_exploitation_at_lateral_and_full():
    assert tool_blocked_by_ceiling("shell_exec", PROFILE_POLICY_TABLE["crown"]) is False  # lateral
    assert tool_blocked_by_ceiling("python_exec", PROFILE_POLICY_TABLE["aggressive"]) is False  # full


def test_ceiling_ignores_non_exploitation_tools():
    assert tool_blocked_by_ceiling("http_request", FAIL_CLOSED_DEFAULT) is False
    assert tool_blocked_by_ceiling("report_finding", FAIL_CLOSED_DEFAULT) is False
    assert tool_blocked_by_ceiling("browser_navigate", FAIL_CLOSED_DEFAULT) is False


def test_ceiling_legacy_when_no_policy():
    # ceiling off (policy None) → never blocked, matching P1/scope gates
    assert tool_blocked_by_ceiling("shell_exec", None) is False
    assert tool_blocked_by_ceiling("python_exec", None) is False


def test_active_policy_nesting_restores_outer():
    # F4: clearing with the reset token restores the OUTER policy, not None — so a
    # nested/SDK/MCP scan can't wipe the surrounding scan's ambient policy.
    outer = FAIL_CLOSED_DEFAULT
    inner = PROFILE_POLICY_TABLE["aggressive"]
    tok_outer = set_active_policy(outer)
    try:
        tok_inner = set_active_policy(inner)
        try:
            assert get_active_policy() is inner
        finally:
            clear_active_policy(tok_inner)
        assert get_active_policy() is outer  # restored, not wiped to None
    finally:
        clear_active_policy(tok_outer)
    assert get_active_policy() is None


# ── F2: exploitation ceiling covers run_skill attack templates ──
_ACTIVE_SKILLS = (
    "test_injection", "test_ssrf", "attempt_auth", "test_xss", "test_idor",
    "test_business_logic", "test_api_security", "test_auth_deep", "test_csrf",
    "post_auth_enum", "execute_chain",
)
_PASSIVE = ("enumerate_endpoints", "test_sensitive_files", "test_misconfig", "test_crypto", "test_infra")


def test_skill_ceiling_blocks_active_below_lateral():
    for sk in _ACTIVE_SKILLS:
        assert skill_blocked_by_ceiling(sk, PROFILE_POLICY_TABLE["standard"]) is True, sk  # read-only
        assert skill_blocked_by_ceiling(sk, FAIL_CLOSED_DEFAULT) is True, sk  # none


def test_skill_ceiling_allows_active_at_lateral_and_full():
    assert skill_blocked_by_ceiling("test_injection", PROFILE_POLICY_TABLE["crown"]) is False  # lateral
    assert skill_blocked_by_ceiling("test_injection", PROFILE_POLICY_TABLE["aggressive"]) is False  # full


def test_skill_ceiling_allows_passive_even_at_readonly():
    for sk in _PASSIVE:
        assert skill_blocked_by_ceiling(sk, PROFILE_POLICY_TABLE["standard"]) is False, sk
        assert skill_blocked_by_ceiling(sk, FAIL_CLOSED_DEFAULT) is False, sk


def test_skill_ceiling_legacy_when_no_policy():
    assert skill_blocked_by_ceiling("test_injection", None) is False


def test_skill_ceiling_unknown_skill_fail_closed():
    # unrecognized skill under read-only → treated as active → blocked
    assert skill_blocked_by_ceiling("totally_unknown_skill", PROFILE_POLICY_TABLE["standard"]) is True


# ── F3 (2e): injection-approval decision + gate ──
def test_injection_decision_roundtrip():
    assert get_injection_decision() is None
    tok = set_injection_decision("deny")
    try:
        assert get_injection_decision() == "deny"
    finally:
        clear_injection_decision(tok)
    assert get_injection_decision() is None


def test_injection_not_blocked_on_none_or_full():
    # None (legacy/ungated) and full (approved) never block — incl. mutating HTTP
    for decision in (None, "full"):
        assert injection_action_blocked("shell_exec", {}, decision) is False
        assert injection_action_blocked("run_skill", {"skill": "test_injection"}, decision) is False
        assert injection_action_blocked("http_request", {"method": "POST"}, decision) is False


def test_injection_deny_blocks_injection_class_actions():
    assert injection_action_blocked("shell_exec", {}, "deny") is True
    assert injection_action_blocked("python_exec", {}, "deny") is True
    assert injection_action_blocked("run_skill", {"skill": "test_injection"}, "deny") is True
    assert injection_action_blocked("run_skill", {"skill": "test_ssrf"}, "deny") is True


def test_injection_deny_allows_passive_and_non_injection_tools():
    # injection deny skips the attack phase, but passive recon + navigation still run
    assert injection_action_blocked("run_skill", {"skill": "enumerate_endpoints"}, "deny") is False
    assert injection_action_blocked("http_request", {"url": "http://t"}, "deny") is False
    assert injection_action_blocked("report_finding", {}, "deny") is False


# ── F3 follow-up: readonly must be genuinely read-only (was a no-op == full) ──
def test_readonly_blocks_exploitation_attack_skills_and_mutating_http():
    # readonly = "GET/HEAD only"; everything that can mutate is refused at dispatch
    assert injection_action_blocked("shell_exec", {}, "readonly") is True
    assert injection_action_blocked("python_exec", {}, "readonly") is True
    assert injection_action_blocked("run_skill", {"skill": "test_injection"}, "readonly") is True
    for method in ("POST", "post", "PUT", "PATCH", "DELETE"):
        assert injection_action_blocked("http_request", {"method": method}, "readonly") is True, method


def test_readonly_allows_get_head_and_passive():
    assert injection_action_blocked("http_request", {"method": "GET"}, "readonly") is False
    assert injection_action_blocked("http_request", {"method": "HEAD"}, "readonly") is False
    assert injection_action_blocked("http_request", {}, "readonly") is False  # defaults to GET
    assert injection_action_blocked("run_skill", {"skill": "enumerate_endpoints"}, "readonly") is False
    assert injection_action_blocked("report_finding", {}, "readonly") is False
