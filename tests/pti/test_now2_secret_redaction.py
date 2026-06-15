"""NOW-2/2c — trajectory secret redaction driven by ScanPolicy.secret_handling.

Previously trajectory PII hashing fired only on the VXIS_TRAJECTORY_PRIVACY=strict
env var. Now an active ScanPolicy whose secret_handling is 'encrypt-redact' (the
fail-closed default, and every prod/crown profile) also triggers redaction —
policy-driven, not env-only. plaintext-lab (lab profiles) and no-active-policy
(legacy) do not redact.
"""
from vxis.agent.policy.runtime_policy import clear_active_policy, set_active_policy
from vxis.agent.policy.scan_policy import FAIL_CLOSED_DEFAULT, PROFILE_POLICY_TABLE
from vxis.pti import TrajectoryRecord, target_hash_for_url
from vxis.pti.trajectory import _policy_requires_redaction, apply_privacy


def _rec() -> TrajectoryRecord:
    return TrajectoryRecord(
        scan_id="scan-1",
        target_hash=target_hash_for_url("https://example.com"),
        iter=1,
        decision_class="strategy",
        model_used="claude-sonnet",
        input_context={
            "host": "tenant.example.com",
            "target_url": "https://tenant.example.com/app?token=secret",
        },
        input_token_count=100,
        output_action={"tool": "query_pti", "args": {}},
        output_token_count=20,
        outcome_status="pending",
        cost_usd=0.02,
        latency_ms=300,
    )


def test_policy_requires_redaction_matrix():
    assert _policy_requires_redaction(None) is False  # legacy / ceiling off
    assert _policy_requires_redaction(FAIL_CLOSED_DEFAULT) is True  # encrypt-redact
    assert _policy_requires_redaction(PROFILE_POLICY_TABLE["aggressive"]) is False  # plaintext-lab


def test_apply_privacy_redacts_under_encrypt_redact_policy_without_env(monkeypatch):
    monkeypatch.delenv("VXIS_TRAJECTORY_PRIVACY", raising=False)
    tok = set_active_policy(FAIL_CLOSED_DEFAULT)  # encrypt-redact
    try:
        out = apply_privacy(_rec())  # no privacy_mode, no env
    finally:
        clear_active_policy(tok)
    assert out.input_context["host"].startswith("sha256:")
    assert "tenant.example.com" not in out.input_context["target_url"]


def test_apply_privacy_plaintext_lab_policy_does_not_redact(monkeypatch):
    monkeypatch.delenv("VXIS_TRAJECTORY_PRIVACY", raising=False)
    tok = set_active_policy(PROFILE_POLICY_TABLE["aggressive"])  # plaintext-lab
    try:
        out = apply_privacy(_rec())
    finally:
        clear_active_policy(tok)
    assert out.input_context["host"] == "tenant.example.com"  # unchanged


def test_apply_privacy_no_policy_is_legacy_no_redact(monkeypatch):
    monkeypatch.delenv("VXIS_TRAJECTORY_PRIVACY", raising=False)
    out = apply_privacy(_rec())  # no active policy, no env
    assert out.input_context["host"] == "tenant.example.com"  # legacy: unchanged
