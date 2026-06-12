from __future__ import annotations

from vxis.agent.skills.test_auth_deep import _reset_response_is_poisoned


def test_benign_reset_confirmation_is_not_poisoning() -> None:
    # A normal "Password reset email sent" 200 contains the word "reset" but is
    # NOT evidence the Host header was honored. It must not be flagged.
    assert _reset_response_is_poisoned("password reset email sent") is False
    assert _reset_response_is_poisoned("if an account exists, a reset link was sent") is False


def test_reflected_attacker_host_is_poisoning() -> None:
    # The actual signal: the attacker-controlled host reflected in the body
    # (e.g. a reset link pointing at evil.com).
    assert _reset_response_is_poisoned("reset link: https://evil.com/reset?t=abc") is True
    assert _reset_response_is_poisoned("EVIL.COM") is True
