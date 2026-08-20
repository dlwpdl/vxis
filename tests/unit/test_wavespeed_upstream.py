import json
import urllib.request

from tools.upstream_watch import llm


def test_upstream_chat_uses_wavespeed_endpoint(monkeypatch):
    monkeypatch.setenv("UPSTREAM_LLM_PROVIDER", "wavespeed")
    monkeypatch.setenv("UPSTREAM_LLM_MODEL", "google/gemini-3.7-flash")
    monkeypatch.setenv("WAVESPEED_API_KEY", "ws-test-0123456789abcdef")  # gitleaks:allow
    requests = []

    class _Resp:
        def read(self):
            return b'{"choices":[{"message":{"content":"OK"}}]}'

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def _urlopen(req, timeout=0):
        requests.append(req)
        return _Resp()

    monkeypatch.setattr(urllib.request, "urlopen", _urlopen)

    response = llm.chat("system", "user")

    assert response is not None and response.provider == "wavespeed"
    assert requests[0].full_url == "https://llm.wavespeed.ai/v1/chat/completions"
    assert requests[0].get_header("Authorization") == "Bearer ws-test-0123456789abcdef"
    assert json.loads(requests[0].data)["model"] == "google/gemini-3.7-flash"
