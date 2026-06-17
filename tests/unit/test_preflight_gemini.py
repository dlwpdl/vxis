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
