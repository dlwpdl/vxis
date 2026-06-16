"""Hybrid model catalog — keeps cloud model lists current without manual edits.

The curated :data:`vxis.llm.model_registry._MODELS` list is the authoritative,
always-available base (the models we control — Claude, etc. — are guaranteed
correct and offline). On top of it we merge a LIVE catalog from models.dev
(``GET https://models.dev/api.json``, an open-source community catalog from the
SST/OpenCode team — no API key needed to list), so newly-released models for
every provider appear automatically.

Resolution is fail-soft, three tiers:
    1. live   — fresh models.dev fetch (short timeout), cached to disk.
    2. cache  — last good fetch from ~/.vxis/cache/models_dev.json (<= 24h).
    3. default — bundled curated registry only (offline / first run / no creds).

Curated entries always win on an id conflict so our metadata is canonical. This
is infra fetching (model metadata), NOT target traffic, so urllib is used — the
same pattern as cli.interactive._fetch_llamacpp_models. No data is sent: it is a
read-only public GET.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from vxis.llm.model_registry import ModelInfo, list_models

MODELS_DEV_URL = "https://models.dev/api.json"
_CACHE_TTL_SECONDS = 24 * 3600

# vxis provider name -> models.dev provider key (only where they differ).
_PROVIDER_KEY = {"gemini": "google", "together": "togetherai"}


@dataclass(frozen=True)
class CatalogResult:
    """Resolved model list for a provider plus where it came from."""

    models: list[ModelInfo]
    source: str  # "live" | "cache" | "default"


def _cache_path() -> Path:
    override = os.environ.get("VXIS_MODELS_CACHE", "").strip()
    if override:
        return Path(override)
    return Path(os.path.expanduser("~/.vxis/cache/models_dev.json"))


def _fetch_models_dev(timeout: float = 2.5) -> dict | None:
    """Fetch the models.dev catalog. Returns the parsed dict, or None on any
    failure (offline, timeout, non-200, bad JSON) — never raises."""
    try:
        req = urllib.request.Request(
            MODELS_DEV_URL, method="GET", headers={"User-Agent": "vxis-model-catalog"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (trusted infra URL)
            if not 200 <= getattr(resp, "status", 200) < 300:
                return None
            body = resp.read().decode("utf-8", errors="replace")
        payload = json.loads(body)
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _load_cache() -> tuple[dict | None, float]:
    """Return (cached_catalog, age_seconds). (None, inf) when absent/unreadable."""
    path = _cache_path()
    try:
        if path.exists():
            age = time.time() - path.stat().st_mtime
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data, age
    except Exception:
        pass
    return None, float("inf")


def _save_cache(data: dict) -> None:
    """Best-effort write of the last good fetch. Silent on failure."""
    try:
        path = _cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass


def _normalize_models_dev(raw: dict | None, vxis_provider: str) -> list[ModelInfo]:
    """Map a models.dev catalog into ModelInfo for one vxis provider.

    Unknown provider or malformed data → empty list (never raises)."""
    key = _PROVIDER_KEY.get(vxis_provider, vxis_provider)
    block = (raw or {}).get(key) or {}
    models = block.get("models") if isinstance(block, dict) else None
    if not isinstance(models, dict):
        return []
    out: list[ModelInfo] = []
    for mid, entry in models.items():
        if not isinstance(entry, dict):
            continue
        limit = entry.get("limit") if isinstance(entry.get("limit"), dict) else {}
        modalities = entry.get("modalities") if isinstance(entry.get("modalities"), dict) else {}
        modal_in = modalities.get("input") or []
        out.append(
            ModelInfo(
                model_id=str(entry.get("id") or mid),
                provider=vxis_provider,
                context_window=int(limit.get("context") or 0) or 128_000,
                max_output_tokens=int(limit.get("output") or 0) or 8_000,
                supports_vision=("image" in modal_in) or bool(entry.get("attachment")),
                supports_json_mode=bool(entry.get("tool_call")),
                reasoning_model=bool(entry.get("reasoning")),
                family=str(entry.get("family") or ""),
                notes=str(entry.get("name") or ""),
            )
        )
    return out


def merge_catalog(curated: list[ModelInfo], live: list[ModelInfo]) -> list[ModelInfo]:
    """Curated first (authoritative), then any live models not already present."""
    seen = {m.model_id.lower() for m in curated}
    merged = list(curated)
    for m in live:
        if m.model_id.lower() not in seen:
            merged.append(m)
            seen.add(m.model_id.lower())
    return merged


def available_models(
    provider: str,
    *,
    allow_network: bool = True,
    fetcher=None,
) -> CatalogResult:
    """Resolve the model list for *provider*: curated base + live models.dev
    breadth, with cache/offline fallback. ``fetcher`` is injectable for tests."""
    curated = list_models(provider)
    fetch = fetcher or _fetch_models_dev

    raw: dict | None = None
    source = "default"
    if allow_network:
        raw = fetch()
        if raw is not None:
            source = "live"
            _save_cache(raw)
    if raw is None:
        cached, age = _load_cache()
        if cached is not None and age <= _CACHE_TTL_SECONDS:
            raw = cached
            source = "cache"

    live_models = _normalize_models_dev(raw, provider) if raw else []
    if not live_models:
        source = "default"
    return CatalogResult(models=merge_catalog(curated, live_models), source=source)


__all__ = [
    "CatalogResult",
    "available_models",
    "merge_catalog",
    "MODELS_DEV_URL",
]
