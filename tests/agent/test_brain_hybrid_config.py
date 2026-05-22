from __future__ import annotations

from vxis.agent.brain import AgentBrain


def test_agent_brain_uses_director_role_env_as_primary_model(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_DIRECTOR_LLM_PROVIDER", "openai")
    monkeypatch.setenv("VXIS_DIRECTOR_LLM_MODEL", "gpt-5.4")
    monkeypatch.setenv("VXIS_WORKER_LLM_PROVIDER", "llamacpp")
    monkeypatch.setenv("VXIS_WORKER_LLM_MODEL", "local-35b")
    monkeypatch.delenv("UPSTREAM_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("UPSTREAM_LLM_MODEL", raising=False)

    brain = AgentBrain()

    assert brain._provider == "openai"
    assert brain._model == "gpt-5.4"
    assert brain._hybrid_model_config.director.ref == "openai/gpt-5.4"
    assert brain._hybrid_model_config.worker.ref == "llamacpp/local-35b"


def test_agent_brain_keeps_explicit_constructor_model_over_role_env(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_DIRECTOR_LLM_PROVIDER", "openai")
    monkeypatch.setenv("VXIS_DIRECTOR_LLM_MODEL", "gpt-5.4")

    brain = AgentBrain(provider="llamacpp", model="local-test")

    assert brain._provider == "llamacpp"
    assert brain._model == "local-test"
    assert brain._hybrid_model_config.director.ref == "openai/gpt-5.4"


def test_call_llm_for_role_uses_worker_endpoint_before_director_fallback(monkeypatch) -> None:
    monkeypatch.setenv("VXIS_DIRECTOR_LLM_PROVIDER", "openai")
    monkeypatch.setenv("VXIS_DIRECTOR_LLM_MODEL", "gpt-5.4")
    monkeypatch.setenv("VXIS_WORKER_LLM_PROVIDER", "llamacpp")
    monkeypatch.setenv("VXIS_WORKER_LLM_MODEL", "local-35b")

    brain = AgentBrain()
    calls: list[tuple[str, str]] = []

    def fake_direct(
        system_prompt: str,
        user_prompt: str,
        provider: str = "",
        model: str = "",
        image_path: str = "",
    ) -> str | None:
        calls.append((provider, model))
        return "worker response"

    monkeypatch.setattr(brain, "_call_llm_direct", fake_direct)

    response = brain._call_llm_for_role("worker", "sys", "user")

    assert response == "worker response"
    assert calls == [("llamacpp", "local-35b")]
