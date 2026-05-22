"""Role-based LLM configuration for the hybrid VXIS runtime.

The design target is:
    director  -> frontier/cloud reasoning model
    worker    -> local-first bounded task model
    verifier  -> director-strength or stronger model
    summarizer-> worker/cheap model

This module is intentionally configuration-only. Call sites decide when a role
is invoked, but they should resolve provider/model choices here instead of
spreading environment parsing across the runtime.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Mapping


class ModelRole(str, Enum):
    """Logical model roles used by the hybrid agent runtime."""

    DIRECTOR = "director"
    WORKER = "worker"
    VERIFIER = "verifier"
    SUMMARIZER = "summarizer"


_LOCAL_PROVIDERS = {"ollama", "llamacpp"}
_FRONTIER_PROVIDERS = {"anthropic", "openai", "gemini"}
_CLOUD_PROVIDERS = {"anthropic", "openai", "gemini", "together", "deepseek"}
_KNOWN_PROVIDERS = _LOCAL_PROVIDERS | _CLOUD_PROVIDERS | {"google", "vertex", "vertex_ai"}

_DEFAULT_DIRECTOR = ("anthropic", "claude-sonnet-4-6")
_DEFAULT_VERIFIER = ("anthropic", "claude-sonnet-4-6")
_DEFAULT_LLAMACPP_MODEL = "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m"
_DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:14b"


@dataclass(frozen=True)
class ModelEndpoint:
    """Resolved provider/model endpoint for one logical role."""

    role: ModelRole
    provider: str
    model: str
    source: str
    base_url: str = ""

    @property
    def is_local(self) -> bool:
        return self.provider in _LOCAL_PROVIDERS

    @property
    def is_frontier(self) -> bool:
        return self.provider in _FRONTIER_PROVIDERS and bool(self.model)

    @property
    def is_cloud(self) -> bool:
        return self.provider in _CLOUD_PROVIDERS

    @property
    def ref(self) -> str:
        if not self.provider:
            return self.model
        if not self.model:
            return self.provider
        return f"{self.provider}/{self.model}"


@dataclass(frozen=True)
class HybridModelConfig:
    """Resolved LLM endpoints for every VXIS runtime role."""

    director: ModelEndpoint
    worker: ModelEndpoint
    verifier: ModelEndpoint
    summarizer: ModelEndpoint

    def for_role(self, role: ModelRole | str) -> ModelEndpoint:
        resolved = role if isinstance(role, ModelRole) else ModelRole(str(role).lower())
        return {
            ModelRole.DIRECTOR: self.director,
            ModelRole.WORKER: self.worker,
            ModelRole.VERIFIER: self.verifier,
            ModelRole.SUMMARIZER: self.summarizer,
        }[resolved]

    @property
    def uses_hybrid_split(self) -> bool:
        return self.director.ref != self.worker.ref

    @property
    def local_worker_first(self) -> bool:
        return self.worker.is_local


def normalize_provider(provider: str) -> str:
    """Normalize provider aliases used across CLI/docs/env vars."""
    value = str(provider or "").strip().lower()
    if value in {"google", "vertex", "vertex_ai"}:
        return "gemini"
    return value


def parse_model_ref(value: str) -> tuple[str, str]:
    """Parse Strix/LiteLLM-style provider/model references.

    Only splits when the first segment is a known provider, so model IDs such
    as ``moonshotai/Kimi-K2.5`` remain intact unless written as
    ``together/moonshotai/Kimi-K2.5``.
    """
    ref = str(value or "").strip()
    if "/" not in ref:
        return "", ref
    provider, model = ref.split("/", 1)
    if normalize_provider(provider) in _KNOWN_PROVIDERS:
        return normalize_provider(provider), model.strip()
    return "", ref


def resolve_hybrid_model_config(
    *,
    base_provider: str = "",
    base_model: str = "",
    env: Mapping[str, str] | None = None,
) -> HybridModelConfig:
    """Resolve role-based model endpoints from env and legacy settings.

    New role env vars:
        VXIS_DIRECTOR_LLM=openai/gpt-5.4
        VXIS_WORKER_LLM=llamacpp/local-model
        VXIS_VERIFIER_LLM=anthropic/claude-opus-4-6
        VXIS_SUMMARIZER_LLM=ollama/qwen2.5-coder:14b

    The split provider/model form is also supported for each role via
    ``VXIS_<ROLE>_LLM_PROVIDER`` and ``VXIS_<ROLE>_LLM_MODEL``.
    """
    raw_env = env or {}
    director = _resolve_director(base_provider=base_provider, base_model=base_model, env=raw_env)
    worker = _resolve_worker(base_provider=base_provider, base_model=base_model, env=raw_env)
    verifier = _resolve_verifier(director=director, env=raw_env)
    summarizer = _resolve_summarizer(worker=worker, env=raw_env)
    return HybridModelConfig(
        director=director,
        worker=worker,
        verifier=verifier,
        summarizer=summarizer,
    )


def _resolve_director(
    *,
    base_provider: str,
    base_model: str,
    env: Mapping[str, str],
) -> ModelEndpoint:
    explicit = _endpoint_from_role_env(ModelRole.DIRECTOR, env)
    if explicit is not None:
        return explicit

    base = _legacy_endpoint(ModelRole.DIRECTOR, base_provider, base_model, env)
    if base is not None and not base.is_local:
        return replace(base, source="legacy_upstream_cloud")

    available = _first_available_frontier(env)
    if available is not None:
        return available

    cloud = _first_available_cloud(env)
    if cloud is not None:
        return cloud

    if base is not None and base.is_local:
        return replace(base, source="legacy_upstream_local_degraded_director")

    provider, model = _DEFAULT_DIRECTOR
    return ModelEndpoint(
        role=ModelRole.DIRECTOR,
        provider=provider,
        model=model,
        source="default_frontier",
    )


def _resolve_worker(
    *,
    base_provider: str,
    base_model: str,
    env: Mapping[str, str],
) -> ModelEndpoint:
    explicit = _endpoint_from_role_env(ModelRole.WORKER, env)
    if explicit is not None:
        return explicit

    base = _legacy_endpoint(ModelRole.WORKER, base_provider, base_model, env)
    if base is not None and base.is_local:
        return replace(base, source="legacy_upstream_local")

    if _env_get(env, "VXIS_LLAMACPP_MODEL") or _env_get(env, "VXIS_LLAMACPP_BASE_URL"):
        return _local_endpoint(ModelRole.WORKER, "llamacpp", env, source="local_env")

    if (
        _env_get(env, "VXIS_OLLAMA_UNCENSORED_MODEL")
        or _env_get(env, "VXIS_OLLAMA_MODEL")
        or _env_get(env, "VXIS_OLLAMA_BASE_URL")
    ):
        return _local_endpoint(ModelRole.WORKER, "ollama", env, source="local_env")

    return _local_endpoint(ModelRole.WORKER, "llamacpp", env, source="default_local_worker")


def _resolve_verifier(
    *,
    director: ModelEndpoint,
    env: Mapping[str, str],
) -> ModelEndpoint:
    explicit = _endpoint_from_role_env(ModelRole.VERIFIER, env)
    if explicit is not None:
        return explicit

    if director.is_frontier:
        return replace(director, role=ModelRole.VERIFIER, source="default_to_director")

    available = _first_available_frontier(env, role=ModelRole.VERIFIER)
    if available is not None:
        return available

    provider, model = _DEFAULT_VERIFIER
    return ModelEndpoint(
        role=ModelRole.VERIFIER,
        provider=provider,
        model=model,
        source="default_frontier",
    )


def _resolve_summarizer(
    *,
    worker: ModelEndpoint,
    env: Mapping[str, str],
) -> ModelEndpoint:
    explicit = _endpoint_from_role_env(ModelRole.SUMMARIZER, env)
    if explicit is not None:
        return explicit
    return replace(worker, role=ModelRole.SUMMARIZER, source="default_to_worker")


def _endpoint_from_role_env(role: ModelRole, env: Mapping[str, str]) -> ModelEndpoint | None:
    prefix = f"VXIS_{role.value.upper()}_LLM"
    combined = _env_get(env, prefix)
    provider = ""
    model = ""
    if combined:
        provider, model = parse_model_ref(combined)

    provider = _env_get(env, f"{prefix}_PROVIDER") or provider
    model = _env_get(env, f"{prefix}_MODEL") or model
    provider = normalize_provider(provider)
    if not provider and not model:
        return None
    if not provider:
        provider = _infer_provider_from_model(model)
    if not model:
        model = _default_model_for_provider(provider, env)

    return ModelEndpoint(
        role=role,
        provider=provider,
        model=model,
        source="role_env",
        base_url=_role_base_url(role, provider, env),
    )


def _legacy_endpoint(
    role: ModelRole,
    provider: str,
    model: str,
    env: Mapping[str, str],
) -> ModelEndpoint | None:
    normalized = normalize_provider(provider)
    if not normalized:
        return None
    resolved_model = str(model or "").strip() or _default_model_for_provider(normalized, env)
    return ModelEndpoint(
        role=role,
        provider=normalized,
        model=resolved_model,
        source="legacy_upstream",
        base_url=_role_base_url(role, normalized, env),
    )


def _first_available_frontier(
    env: Mapping[str, str],
    *,
    role: ModelRole = ModelRole.DIRECTOR,
) -> ModelEndpoint | None:
    for provider, model, key_names in (
        ("anthropic", "claude-sonnet-4-6", ("ANTHROPIC_API_KEY",)),
        ("openai", "gpt-5.4", ("OPENAI_API_KEY", "LLM_API_KEY")),
        ("gemini", "gemini-3.1-pro-preview", ("GOOGLE_API_KEY", "GEMINI_API_KEY")),
    ):
        if any(_env_get(env, key) for key in key_names):
            return ModelEndpoint(
                role=role,
                provider=provider,
                model=model,
                source="available_frontier_key",
            )
    return None


def _first_available_cloud(env: Mapping[str, str]) -> ModelEndpoint | None:
    for provider, model, key_names in (
        ("together", "moonshotai/Kimi-K2.5", ("TOGETHER_API_KEY",)),
        ("deepseek", "deepseek-chat", ("DEEPSEEK_API_KEY",)),
    ):
        if any(_env_get(env, key) for key in key_names):
            return ModelEndpoint(
                role=ModelRole.DIRECTOR,
                provider=provider,
                model=model,
                source="available_cloud_key_degraded_director",
            )
    return None


def _local_endpoint(
    role: ModelRole,
    provider: str,
    env: Mapping[str, str],
    *,
    source: str,
) -> ModelEndpoint:
    provider = normalize_provider(provider)
    return ModelEndpoint(
        role=role,
        provider=provider,
        model=_default_model_for_provider(provider, env),
        source=source,
        base_url=_role_base_url(role, provider, env),
    )


def _default_model_for_provider(provider: str, env: Mapping[str, str]) -> str:
    provider = normalize_provider(provider)
    if provider == "llamacpp":
        return _env_get(env, "VXIS_LLAMACPP_MODEL") or _DEFAULT_LLAMACPP_MODEL
    if provider == "ollama":
        return (
            _env_get(env, "VXIS_OLLAMA_UNCENSORED_MODEL")
            or _env_get(env, "VXIS_OLLAMA_MODEL")
            or _DEFAULT_OLLAMA_MODEL
        )
    return {
        "anthropic": "claude-sonnet-4-6",
        "openai": "gpt-5.4",
        "gemini": "gemini-2.5-pro",
        "together": "deepseek-ai/DeepSeek-V3.1",
        "deepseek": "deepseek-chat",
    }.get(provider, "")


def _role_base_url(role: ModelRole, provider: str, env: Mapping[str, str]) -> str:
    role_value = _env_get(env, f"VXIS_{role.value.upper()}_LLM_BASE_URL")
    if role_value:
        return role_value.rstrip("/")
    provider = normalize_provider(provider)
    if provider == "llamacpp":
        return (_env_get(env, "VXIS_LLAMACPP_BASE_URL") or "http://localhost:8080").rstrip("/")
    if provider == "ollama":
        return (_env_get(env, "VXIS_OLLAMA_BASE_URL") or "http://localhost:11434").rstrip("/")
    return ""


def _infer_provider_from_model(model: str) -> str:
    value = str(model or "").lower()
    if value.startswith("claude-"):
        return "anthropic"
    if value.startswith(("gpt-", "o1", "o3", "o4")):
        return "openai"
    if value.startswith("gemini-"):
        return "gemini"
    if ":" in value:
        return "ollama"
    return ""


def _env_get(env: Mapping[str, str], key: str) -> str:
    return str(env.get(key, "") or "").strip()


__all__ = [
    "HybridModelConfig",
    "ModelEndpoint",
    "ModelRole",
    "normalize_provider",
    "parse_model_ref",
    "resolve_hybrid_model_config",
]
