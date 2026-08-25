import json
import urllib.request

from tools.upstream_watch import llm


def test_upstream_chat_uses_openrouter_endpoint(monkeypatch):
    monkeypatch.setenv("UPSTREAM_LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("UPSTREAM_LLM_MODEL", "stealth/ox-alpha")
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test-0123456789abcdef")  # gitleaks:allow
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

    assert response is not None and response.provider == "openrouter"
    assert requests[0].full_url == "https://openrouter.ai/api/v1/chat/completions"
    assert requests[0].get_header("Authorization") == "Bearer sk-or-test-0123456789abcdef"
    payload = json.loads(requests[0].data)
    assert payload["model"] == "stealth/ox-alpha"
    assert payload["reasoning"] == {"effort": "high"}
