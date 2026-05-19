from __future__ import annotations

import importlib.util
from pathlib import Path


_SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "tools"
    / "benchmark"
    / "scripted_juiceshop_richer_smoke.py"
)
_SPEC = importlib.util.spec_from_file_location("bench_runtime_module", _SCRIPT_PATH)
assert _SPEC and _SPEC.loader
bench = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(bench)


def test_require_llm_runtime_accepts_remote_provider_with_key(monkeypatch):
    monkeypatch.setenv("UPSTREAM_LLM_PROVIDER", "openai")
    monkeypatch.setenv("UPSTREAM_LLM_MODEL", "gpt-5.5")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    provider, model, base_url = bench._require_llm_runtime()

    assert provider == "openai"
    assert model == "gpt-5.5"
    assert base_url == ""


def test_require_llm_runtime_rejects_remote_provider_without_key(monkeypatch):
    monkeypatch.setenv("UPSTREAM_LLM_PROVIDER", "openai")
    monkeypatch.setenv("UPSTREAM_LLM_MODEL", "gpt-5.5")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    try:
        bench._require_llm_runtime()
    except SystemExit as exc:
        assert "OPENAI_API_KEY" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected SystemExit for missing OPENAI_API_KEY")
