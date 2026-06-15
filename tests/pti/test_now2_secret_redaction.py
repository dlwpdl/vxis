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


def _rec(output_action=None, outcome_evidence=None) -> TrajectoryRecord:
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
        output_action=output_action or {"tool": "query_pti", "args": {}},
        output_token_count=20,
        outcome_status="pending",
        outcome_evidence=outcome_evidence,
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


# ── F1: redaction scope widened to output_action + outcome_evidence + secret detectors ──
def test_redacts_authorization_header_in_output_action(monkeypatch):
    monkeypatch.delenv("VXIS_TRAJECTORY_PRIVACY", raising=False)
    rec = _rec(output_action={"tool": "http_request",
                              "args": {"headers": {"Authorization": "Bearer SECRETTOKEN123"}}})
    tok = set_active_policy(FAIL_CLOSED_DEFAULT)
    try:
        out = apply_privacy(rec)
    finally:
        clear_active_policy(tok)
    assert "SECRETTOKEN123" not in out.model_dump_json()
    assert out.output_action["args"]["headers"]["Authorization"].startswith("sha256:")


def test_redacts_cookie_and_apikey_in_output_action(monkeypatch):
    monkeypatch.delenv("VXIS_TRAJECTORY_PRIVACY", raising=False)
    rec = _rec(output_action={"tool": "http_request", "args": {"headers": {
        "Cookie": "session=raw_session_val", "X-Api-Key": "raw_api_key_val"}}})
    tok = set_active_policy(FAIL_CLOSED_DEFAULT)
    try:
        out = apply_privacy(rec)
    finally:
        clear_active_policy(tok)
    blob = out.model_dump_json()
    assert "raw_session_val" not in blob
    assert "raw_api_key_val" not in blob


def test_redacts_token_query_in_outcome_evidence(monkeypatch):
    monkeypatch.delenv("VXIS_TRAJECTORY_PRIVACY", raising=False)
    rec = _rec(outcome_evidence="GET /app?token=rawsecretval -> 200 OK")
    tok = set_active_policy(FAIL_CLOSED_DEFAULT)
    try:
        out = apply_privacy(rec)
    finally:
        clear_active_policy(tok)
    assert "rawsecretval" not in out.outcome_evidence


def test_redacts_bearer_in_outcome_evidence(monkeypatch):
    monkeypatch.delenv("VXIS_TRAJECTORY_PRIVACY", raising=False)
    rec = _rec(outcome_evidence="sent Authorization: Bearer raw.jwt.value and got 200")
    tok = set_active_policy(FAIL_CLOSED_DEFAULT)
    try:
        out = apply_privacy(rec)
    finally:
        clear_active_policy(tok)
    assert "raw.jwt.value" not in out.outcome_evidence


def test_plaintext_lab_leaves_secrets_raw(monkeypatch):
    monkeypatch.delenv("VXIS_TRAJECTORY_PRIVACY", raising=False)
    rec = _rec(output_action={"tool": "http_request", "args": {"headers": {"Authorization": "Bearer KEEPRAW1"}}},
               outcome_evidence="?token=KEEPRAW2")
    tok = set_active_policy(PROFILE_POLICY_TABLE["aggressive"])  # plaintext-lab
    try:
        out = apply_privacy(rec)
    finally:
        clear_active_policy(tok)
    blob = out.model_dump_json()
    assert "KEEPRAW1" in blob and "KEEPRAW2" in blob  # lab keeps raw


def test_no_policy_leaves_output_action_raw(monkeypatch):
    monkeypatch.delenv("VXIS_TRAJECTORY_PRIVACY", raising=False)
    rec = _rec(output_action={"tool": "http_request", "args": {"headers": {"Authorization": "Bearer LEGACYRAW"}}})
    assert "LEGACYRAW" in apply_privacy(rec).model_dump_json()  # legacy: unchanged


def test_writeback_outcome_redacts_evidence_under_policy(tmp_path, monkeypatch):
    monkeypatch.delenv("VXIS_TRAJECTORY_PRIVACY", raising=False)
    from vxis.pti.trajectory import TrajectoryStore

    store = TrajectoryStore(tmp_path / "data")  # name not a target-hash → append allowed
    store.append(_rec())
    tok = set_active_policy(FAIL_CLOSED_DEFAULT)
    try:
        updated = store.writeback_outcome(
            "scan-1", iter=1, outcome_status="pending",
            outcome_evidence="Authorization: Bearer WBRAWSECRET",
        )
    finally:
        clear_active_policy(tok)
    assert "WBRAWSECRET" not in (updated.outcome_evidence or "")
    assert "WBRAWSECRET" not in (store.load("scan-1")[0].outcome_evidence or "")
