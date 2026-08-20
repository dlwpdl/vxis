"""AgentBrain.healthcheck(): one real director call → (callable?, reason).

This is the single source of truth preflight uses to refuse a dead Brain before
a scan starts (instead of 9 silently-failing calls mid-scan). It must report the
REAL provider/model/HTTP error, not a generic hint.
"""

import io
import json
import urllib.error

from vxis.agent.brain import AgentBrain


def _openai_brain(monkeypatch, model="gpt-5.4"):
    monkeypatch.setenv("UPSTREAM_LLM_PROVIDER", "openai")
    monkeypatch.setenv("UPSTREAM_LLM_MODEL", model)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0123456789abcdef")  # gitleaks:allow
    # strip anything that would auto-promote a different frontier director
    for k in (
        "VXIS_DIRECTOR_LLM",
        "VXIS_DIRECTOR_LLM_PROVIDER",
        "VXIS_DIRECTOR_LLM_MODEL",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "TOGETHER_API_KEY",
        "LLM_API_KEY",
    ):
        monkeypatch.delenv(k, raising=False)
    return AgentBrain()


def test_healthcheck_ok_when_model_callable(monkeypatch):
    b = _openai_brain(monkeypatch)

    class _Resp:
        status = 200

        def read(self):
            return b'{"choices":[{"message":{"content":"OK"}}],"usage":{}}'

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=0: _Resp())
    ok, reason = b.healthcheck()
    assert ok is True
    assert reason == ""


def test_healthcheck_reports_http_error(monkeypatch):
    b = _openai_brain(monkeypatch)

    def _boom(req, timeout=0):
        raise urllib.error.HTTPError(
            req.full_url,
            404,
            "Not Found",
            {},
            io.BytesIO(b'{"error":{"message":"This is not a chat model"}}'),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _boom)
    ok, reason = b.healthcheck()
    assert ok is False
    assert "404" in reason
    assert "openai" in reason and "gpt-5.4" in reason
    assert "not a chat model" in reason


def test_healthcheck_uses_role_scoped_local_base_url(monkeypatch):
    monkeypatch.setenv("VXIS_DIRECTOR_LLM", "llamacpp/local-35b")
    monkeypatch.setenv("VXIS_DIRECTOR_LLM_BASE_URL", "http://127.0.0.1:8090")
    monkeypatch.delenv("VXIS_LLAMACPP_BASE_URL", raising=False)
    brain = AgentBrain()
    requested_urls: list[str] = []

    class _Resp:
        status = 200

        def read(self):
            return b'{"choices":[{"message":{"content":"OK"}}],"usage":{}}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def _urlopen(req, timeout=0):
        requested_urls.append(req.full_url)
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)

    assert brain.healthcheck() == (True, "")
    assert requested_urls == ["http://127.0.0.1:8090/v1/chat/completions"]


def test_healthcheck_calls_wavespeed_openai_compatible_endpoint(monkeypatch):
    monkeypatch.setenv("VXIS_DIRECTOR_LLM", "wavespeed/google/gemini-3.7-flash")
    monkeypatch.setenv("VXIS_DIRECTOR_LLM_EXTRA_BODY_JSON", '{"reasoning_effort": "high"}')
    monkeypatch.setenv("WAVESPEED_API_KEY", "ws-test-0123456789abcdef")  # gitleaks:allow
    for key in (
        "VXIS_DIRECTOR_LLM_PROVIDER",
        "VXIS_DIRECTOR_LLM_MODEL",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "TOGETHER_API_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    brain = AgentBrain()
    requests = []

    class _Resp:
        status = 200

        def read(self):
            return b'{"choices":[{"message":{"content":"OK"}}],"usage":{}}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def _urlopen(req, timeout=0):
        requests.append(req)
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)

    assert brain.healthcheck() == (True, "")
    assert len(requests) == 1
    assert requests[0].full_url == "https://llm.wavespeed.ai/v1/chat/completions"
    assert requests[0].get_header("Authorization") == "Bearer ws-test-0123456789abcdef"
    payload = json.loads(requests[0].data)
    assert payload["model"] == "google/gemini-3.7-flash"
    assert payload["reasoning_effort"] == "high"
