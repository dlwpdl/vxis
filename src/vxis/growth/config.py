"""Bootstrap config loader|||Bootstrap 설정 로더."""

from __future__ import annotations

import tomllib
from pathlib import Path

DEFAULT_BOOTSTRAP_CONFIG: dict = {
    "budget": {
        "max_monthly_llm_usd": 15.0,
        "max_daily_llm_calls": 100,
    },
    "polling": {
        "cve_watch_interval_hours": 6,
        "threat_news_interval_hours": 4,
        "signal_analyze_interval_hours": 12,
        "signal_ingest_interval_hours": 6,
    },
    "filtering": {
        "regex_prefilter_enabled": True,
        "trust_threshold_for_llm": 0.8,
        "batch_size": 20,
    },
    "apply": {
        "dry_run": True,
        "auto_apply_threshold": 0.9,
        "require_benchmark_validation": True,
    },
    "tiers": {
        "primary": "claude_code",
        "fallback": "ollama",
        "cheap_api": "together",
        "critical_only": "sonnet",
        "synthesis_only": "opus",
    },
    "cache": {
        "extraction_ttl_days": 30,
        "cache_dir": ".vxis/cache/extractions",
    },
}


def load_bootstrap_config(path: Path | None = None) -> dict:
    """Load growth_bootstrap.toml or return defaults|||설정 파일 또는 기본값 로드."""
    if path is None:
        path = Path("configs/growth_bootstrap.toml")
    if not path.exists():
        return DEFAULT_BOOTSTRAP_CONFIG
    with path.open("rb") as f:
        return tomllib.load(f)


def is_dry_run() -> bool:
    """Check if dry-run mode is active|||Dry-run 모드 여부."""
    return bool(load_bootstrap_config()["apply"]["dry_run"])


def get_tier_routing() -> dict[str, str]:
    """Return LLM tier routing|||LLM 티어 라우팅 반환."""
    return dict(load_bootstrap_config()["tiers"])
