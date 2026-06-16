"""Hybrid model catalog — curated defaults guaranteed + models.dev live breadth.

Keeps cloud model lists current without manual edits: a live models.dev fetch is
merged onto the curated registry (curated wins on conflicts so the models we
control are always correct), with graceful fallback to disk cache then the
bundled defaults when offline / no network.
"""
from vxis.llm.model_catalog import (
    CatalogResult,
    _normalize_models_dev,
    available_models,
    merge_catalog,
)
from vxis.llm.model_registry import ModelInfo

# Minimal models.dev-shaped fixture (provider keys: anthropic/google/togetherai/...)
RAW = {
    "anthropic": {
        "models": {
            "claude-opus-4-8": {
                "id": "claude-opus-4-8",
                "name": "Claude Opus 4.8",
                "family": "claude-opus",
                "attachment": True,
                "reasoning": True,
                "tool_call": True,
                "modalities": {"input": ["text", "image", "pdf"], "output": ["text"]},
                "limit": {"context": 1_000_000, "output": 64_000},
            },
            "claude-zztest-9": {
                "id": "claude-zztest-9",
                "name": "Future Claude",
                "reasoning": False,
                "tool_call": True,
                "modalities": {"input": ["text"], "output": ["text"]},
                "limit": {"context": 200_000, "output": 8_000},
            },
        }
    },
    "google": {
        "models": {
            "gemini-9-pro": {
                "id": "gemini-9-pro",
                "reasoning": False,
                "tool_call": True,
                "modalities": {"input": ["text", "image"], "output": ["text"]},
                "limit": {"context": 2_000_000, "output": 64_000},
            }
        }
    },
}


def test_normalize_extracts_model_fields():
    models = _normalize_models_dev(RAW, "anthropic")
    by_id = {m.model_id: m for m in models}
    assert "claude-opus-4-8" in by_id
    m = by_id["claude-opus-4-8"]
    assert m.provider == "anthropic"
    assert m.context_window == 1_000_000
    assert m.max_output_tokens == 64_000
    assert m.supports_vision is True  # "image" in input modalities
    assert m.reasoning_model is True


def test_normalize_maps_gemini_to_google_key():
    # vxis calls it "gemini"; models.dev stores it under "google"
    models = _normalize_models_dev(RAW, "gemini")
    ids = {m.model_id for m in models}
    assert "gemini-9-pro" in ids
    assert all(m.provider == "gemini" for m in models)


def test_normalize_unknown_provider_is_empty():
    assert _normalize_models_dev(RAW, "openai") == []
    assert _normalize_models_dev({}, "anthropic") == []


def test_merge_curated_wins_on_conflict():
    curated = [ModelInfo(model_id="claude-opus-4-8", provider="anthropic",
                         context_window=1_000_000, max_output_tokens=64_000, notes="CURATED")]
    live = [ModelInfo(model_id="claude-opus-4-8", provider="anthropic",
                      context_window=200_000, max_output_tokens=8_000, notes="LIVE")]
    merged = merge_catalog(curated, live)
    same = [m for m in merged if m.model_id == "claude-opus-4-8"]
    assert len(same) == 1
    assert same[0].notes == "CURATED"  # curated authoritative


def test_merge_adds_live_only_models():
    curated = [ModelInfo(model_id="claude-opus-4-8", provider="anthropic",
                         context_window=1_000_000, max_output_tokens=64_000)]
    live = _normalize_models_dev(RAW, "anthropic")
    merged = merge_catalog(curated, live)
    ids = {m.model_id for m in merged}
    assert "claude-opus-4-8" in ids  # curated kept
    assert "claude-zztest-9" in ids  # live extra surfaced automatically


def test_available_offline_falls_back_to_curated(monkeypatch):
    # network down + no cache → bundled curated defaults, never crash
    monkeypatch.setattr("vxis.llm.model_catalog._load_cache", lambda: (None, float("inf")))
    res = available_models("anthropic", fetcher=lambda: None)
    assert isinstance(res, CatalogResult)
    assert res.source == "default"
    ids = {m.model_id for m in res.models}
    assert "claude-opus-4-8" in ids  # registry guarantees the flagship offline


def test_available_live_merges_and_labels_source(monkeypatch):
    monkeypatch.setattr("vxis.llm.model_catalog._save_cache", lambda data: None)
    res = available_models("anthropic", fetcher=lambda: RAW)
    assert res.source == "live"
    ids = {m.model_id for m in res.models}
    assert "claude-opus-4-8" in ids
    assert "claude-zztest-9" in ids  # live-only model present
