"""preflight.check_brain must validate the resolved director model for ALL cloud
providers (not just gemini): reject unknown/uncallable models BEFORE the scan,
with the real reason + valid options — so a bad model never silently dies 9x."""
from vxis.cli import preflight


def _openai_env(monkeypatch, model):
    monkeypatch.setenv("UPSTREAM_LLM_PROVIDER", "openai")
    monkeypatch.setenv("UPSTREAM_LLM_MODEL", model)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0123456789abcdef")
    for k in (
        "VXIS_DIRECTOR_LLM_PROVIDER", "VXIS_DIRECTOR_LLM_MODEL",
        "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY",
        "TOGETHER_API_KEY", "LLM_API_KEY",
    ):
        monkeypatch.delenv(k, raising=False)


def test_unknown_model_blocked_with_valid_list(monkeypatch):
    # gpt-5.3-codex is not in the registry → reject fast (no network) + show valid
    _openai_env(monkeypatch, "gpt-5.3-codex")
    label, ready = preflight.check_brain(interactive=False)
    assert ready is False
    assert "gpt-5.3-codex" in label
    assert "gpt-5.4" in label  # valid options surfaced for re-pick


def test_registry_valid_but_uncallable_blocked(monkeypatch):
    _openai_env(monkeypatch, "gpt-5.4")
    monkeypatch.setattr(
        "vxis.agent.brain.AgentBrain.healthcheck",
        lambda self: (False, "openai/gpt-5.4: HTTP 401 invalid_api_key"),
    )
    label, ready = preflight.check_brain(interactive=False)
    assert ready is False
    assert "401" in label


def test_valid_callable_model_ready(monkeypatch):
    _openai_env(monkeypatch, "gpt-5.4")
    monkeypatch.setattr(
        "vxis.agent.brain.AgentBrain.healthcheck", lambda self: (True, "")
    )
    label, ready = preflight.check_brain(interactive=False)
    assert ready is True
    assert "gpt-5.4" in label
