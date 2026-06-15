"""NOW-2 foundation + 2d — ambient ScanPolicy + exploitation-ceiling gate logic."""
from vxis.agent.policy.runtime_policy import (
    clear_active_policy,
    get_active_policy,
    set_active_policy,
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
