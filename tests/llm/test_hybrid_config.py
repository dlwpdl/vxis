from __future__ import annotations

from vxis.llm.hybrid_config import (
    ModelRole,
    parse_model_ref,
    resolve_hybrid_model_config,
)


def test_hybrid_defaults_use_frontier_director_and_local_worker() -> None:
    config = resolve_hybrid_model_config(env={})

    assert config.director.provider == "anthropic"
    assert config.director.model == "claude-sonnet-4-6"
    assert config.director.is_frontier is True
    assert config.worker.provider == "llamacpp"
    assert config.worker.is_local is True
    assert config.verifier.ref == config.director.ref
    assert config.summarizer.ref == config.worker.ref
    assert config.uses_hybrid_split is True


def test_env_overrides_roles_independently() -> None:
    config = resolve_hybrid_model_config(env={
        "VXIS_DIRECTOR_LLM": "openai/gpt-5.4",
        "VXIS_WORKER_LLM": "ollama/qwen2.5-coder:14b",
        "VXIS_VERIFIER_LLM_PROVIDER": "anthropic",
        "VXIS_VERIFIER_LLM_MODEL": "claude-opus-4-6",
        "VXIS_SUMMARIZER_LLM": "together/deepseek-ai/DeepSeek-V3.1",
    })

    assert config.director.ref == "openai/gpt-5.4"
    assert config.worker.ref == "ollama/qwen2.5-coder:14b"
    assert config.verifier.ref == "anthropic/claude-opus-4-6"
    assert config.summarizer.ref == "together/deepseek-ai/DeepSeek-V3.1"


def test_existing_upstream_cloud_becomes_director_not_worker_when_worker_unset() -> None:
    config = resolve_hybrid_model_config(
        base_provider="openai",
        base_model="gpt-4o-mini",
        env={},
    )

    assert config.director.ref == "openai/gpt-4o-mini"
    assert config.director.source == "legacy_upstream_cloud"
    assert config.worker.provider == "llamacpp"
    assert config.worker.source == "default_local_worker"


def test_existing_upstream_local_becomes_worker_and_degraded_director_without_cloud() -> None:
    config = resolve_hybrid_model_config(
        base_provider="llamacpp",
        base_model="local-35b",
        env={},
    )

    assert config.director.ref == "llamacpp/local-35b"
    assert config.director.source == "legacy_upstream_local_degraded_director"
    assert config.worker.ref == "llamacpp/local-35b"
    assert config.worker.source == "legacy_upstream_local"


def test_existing_upstream_local_uses_frontier_director_when_key_available() -> None:
    config = resolve_hybrid_model_config(
        base_provider="llamacpp",
        base_model="local-35b",
        env={"OPENAI_API_KEY": "test-key"},
    )

    assert config.director.ref == "openai/gpt-5.4"
    assert config.director.source == "available_frontier_key"
    assert config.worker.ref == "llamacpp/local-35b"


def test_for_role_accepts_enum_and_string() -> None:
    config = resolve_hybrid_model_config(env={})

    assert config.for_role(ModelRole.DIRECTOR) == config.director
    assert config.for_role("worker") == config.worker


def test_parse_model_ref_preserves_provider_owned_model_ids() -> None:
    assert parse_model_ref("openai/gpt-5.4") == ("openai", "gpt-5.4")
    assert parse_model_ref("together/moonshotai/Kimi-K2.5") == (
        "together",
        "moonshotai/Kimi-K2.5",
    )
    assert parse_model_ref("moonshotai/Kimi-K2.5") == ("", "moonshotai/Kimi-K2.5")
