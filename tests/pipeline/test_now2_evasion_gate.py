"""NOW-2/2a — evasion (ghost) capability gate.

Ghost anonymization is gated by the ScanPolicy evasion ceiling, but ONLY when a
policy is active (capability-ceiling enabled). When ctx.policy is None (ceiling
off) evasion follows legacy behavior — consistent with the P1/scope gates that
only enforce when configured — so existing scans don't regress.
"""
from vxis.agent.policy.scan_policy import FAIL_CLOSED_DEFAULT, PROFILE_POLICY_TABLE
from vxis.pipeline.scan_pipeline_v2 import _evasion_blocked_by_policy


def test_evasion_not_blocked_when_no_policy():
    # ceiling off (policy None) → ghost follows legacy behavior, never blocked here
    assert _evasion_blocked_by_policy(None) is False


def test_evasion_blocked_when_policy_forbids():
    # FAIL_CLOSED_DEFAULT (unknown/no profile) has evasion_allowed=False → blocked
    assert _evasion_blocked_by_policy(FAIL_CLOSED_DEFAULT) is True


def test_evasion_allowed_when_policy_permits():
    # the aggressive (lab) profile permits evasion
    assert _evasion_blocked_by_policy(PROFILE_POLICY_TABLE["aggressive"]) is False
