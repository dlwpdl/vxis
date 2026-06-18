"""Preflight validates the Gemini model is actually callable (not just key present).

A preview/unavailable model previously showed Brain ✓ then silently 404'd every
call → 0-finding scans. Now preflight checks the model endpoint and fails loudly.
"""
import urllib.error

from vxis.cli import preflight


class _Resp:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_available_on_200():
    ok = preflight._gemini_model_available(
        "gemini-2.5-pro", "k", _opener=lambda req, timeout: _Resp(200)
    )
    assert ok is True


def test_unavailable_on_404():
    def opener(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)

    assert preflight._gemini_model_available("gemini-3.1-pro-preview", "k", _opener=opener) is False


def test_failopen_on_transient_network_error():
    def opener(req, timeout):
        raise OSError("connection reset")

    # transient errors must NOT block a scan
    assert preflight._gemini_model_available("gemini-2.5-pro", "k", _opener=opener) is True


def test_failopen_when_cannot_check():
    assert preflight._gemini_model_available("", "k") is True
    assert preflight._gemini_model_available("m", "") is True


def test_brain_error_surfaces_specific_reason():
    # The generic "set a key" line misled users who HAD set a key but hit a
    # non-callable model. The reason from check_brain must be surfaced.
    msg = preflight._brain_unavailable_message(
        "api:gemini/gemini-3.1-pro-preview (model not callable with this key — "
        "pick a GA model like gemini-2.5-pro)"
    )
    assert "model not callable" in msg
    assert "gemini-2.5-pro" in msg


def test_brain_error_bare_backend_has_no_reason_suffix():
    assert "→" not in preflight._brain_unavailable_message("unknown")
    assert "→" not in preflight._brain_unavailable_message("")


def test_brain_error_no_key_backend_does_not_duplicate_set_a_key():
    # check_brain's no-key return starts with "none (...)" and already says
    # "set a key" — appending it would duplicate what base already instructs.
    no_key = (
        "none (director LLM key missing — set VXIS_DIRECTOR_LLM plus provider key, "
        "or configure a reachable local legacy backend)"
    )
    assert "→" not in preflight._brain_unavailable_message(no_key)
