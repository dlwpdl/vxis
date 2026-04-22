"""Unit tests for _mask() in test_local_storage_secrets."""
from vxis.agent.skills.desktop.test_local_storage_secrets import _mask


def test_mask_preserves_prefix_and_suffix():
    secret = "AKIAIOSFODNN7EXAMPLE"
    result = _mask(secret)
    assert result.startswith(secret[:6]), "prefix must be preserved"
    assert result.endswith(secret[-6:]), "suffix must be preserved"


def test_mask_middle_is_starred():
    secret = "AKIAIOSFODNN7EXAMPLE"
    result = _mask(secret)
    middle = result[6:-6]
    assert all(c == "*" for c in middle), "middle must be all stars"
    assert len(middle) >= 1


def test_mask_total_length_unchanged():
    secret = "sk_live_abcdefghijklmnopqrstuvwxyz"
    result = _mask(secret)
    assert len(result) == len(secret)


def test_mask_short_secret_fully_starred():
    # shorter than 12 chars → no prefix/suffix kept
    secret = "abc"
    result = _mask(secret)
    assert result == "***"


def test_mask_exactly_12_chars_fully_starred():
    # len == keep*2 → edge case: no middle chars left → fully starred
    secret = "abcdefghijkl"  # exactly 12
    result = _mask(secret)
    assert result == "*" * 12


def test_mask_jwt_prefix_fingerprint():
    jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyMSJ9.SIG123456"
    result = _mask(jwt)
    assert result.startswith("eyJhbG")
    assert result.endswith(jwt[-6:])
    assert "*" in result
