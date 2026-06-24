import json

from vxis.agent.brain import AgentBrain


def test_anthropic_call_marks_system_prompt_cacheable(monkeypatch) -> None:
    captured = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return b'{"content":[{"text":"ok"}],"usage":{}}'

    def fake_urlopen(req, timeout):
        captured["payload"] = json.loads(req.data.decode("utf-8"))
        return _Resp()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    brain = AgentBrain(provider="anthropic", model="claude-sonnet-4-6")
    assert brain._call_anthropic("key", "system prompt", "user prompt") == "ok"

    assert captured["payload"]["system"] == [
        {
            "type": "text",
            "text": "system prompt",
            "cache_control": {"type": "ephemeral"},
        }
    ]
