"""
VXIS configuration schema using Pydantic Settings v2.

Defines all configuration models for the security automation platform,
including scan profiles, client configs, tool settings, and the root
VXISConfig settings class that reads from env vars and .env file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ToolSettings(BaseModel):
    """Per-tool configuration overlay applied on top of scan-profile defaults."""

    enabled: bool = True
    extra_args: str = ""
    timeout_override: int | None = None


class ScanProfile(BaseModel):
    """
    Named scan profile that governs pacing and concurrency for a run.

    rate_limit=0 means unrestricted (used by passive profile which relies on
    third-party APIs that already enforce their own limits).
    """

    name: str
    description: str = ""
    rate_limit: int = Field(ge=0, description="Requests per second; 0 = unlimited")
    max_concurrency: int = Field(ge=1)
    nmap_timing: int = Field(ge=0, le=5, description="Nmap -T timing template (0-5)")
    nuclei_rate: int = Field(ge=0, description="Nuclei requests per second")
    skip_plugins: list[str] = Field(default_factory=list)
    tool_overrides: dict[str, ToolSettings] = Field(default_factory=dict)


class ClientConfig(BaseModel):
    """Engagement-specific metadata attached to a scan run or report."""

    client_name: str
    targets: list[str] = Field(default_factory=list)
    exclude_targets: list[str] = Field(default_factory=list)
    exclude_ports: list[int] = Field(default_factory=list)
    scope_notes: str = ""
    report_template: str = "default"
    custom_logo_path: str | None = None


def _default_profiles() -> dict[str, ScanProfile]:
    """Build the four built-in scan profiles shipped with VXIS."""
    return {
        "passive": ScanProfile(
            name="passive",
            description=(
                "No direct contact with target systems. "
                "Uses third-party intelligence sources only (Shodan, Censys, etc.)."
            ),
            rate_limit=0,
            max_concurrency=4,
            nmap_timing=0,
            nuclei_rate=0,
            skip_plugins=["active-scan", "brute-force"],
        ),
        "stealth": ScanProfile(
            name="stealth",
            description=(
                "Minimal network footprint. "
                "Slow, low-volume probes designed to evade IDS/IPS detection."
            ),
            rate_limit=5,
            max_concurrency=2,
            nmap_timing=1,
            nuclei_rate=2,
            skip_plugins=["brute-force"],
        ),
        "standard": ScanProfile(
            name="standard",
            description=(
                "Balanced profile suitable for most engagements. "
                "Moderate pacing with full plugin coverage."
            ),
            rate_limit=50,
            max_concurrency=5,
            nmap_timing=3,
            nuclei_rate=25,
        ),
        "aggressive": ScanProfile(
            name="aggressive",
            description=(
                "Maximum speed. Use only in isolated lab environments or "
                "with explicit client approval for high-impact scanning."
            ),
            rate_limit=200,
            max_concurrency=8,
            nmap_timing=4,
            nuclei_rate=100,
        ),
    }


class VXISConfig(BaseSettings):
    """
    Root settings object for the VXIS platform.

    Values are resolved in this priority order (highest first):
      1. Environment variables prefixed with ``VXIS_``
      2. ``.env`` file in the working directory
      3. ``config.toml`` (loaded externally via CLI before instantiation)
      4. Field defaults defined below
    """

    model_config = SettingsConfigDict(
        env_prefix="VXIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        # Allow nested model population from env vars (e.g. VXIS_TOOLS__NMAP__ENABLED)
        env_nested_delimiter="__",
        # Unknown keys in .env are silently ignored to allow forward-compat
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Core infrastructure
    # ------------------------------------------------------------------
    data_dir: Path = Field(
        default=Path("~/.vxis").expanduser(),
        description="Root directory for VXIS runtime data (databases, reports, cache).",
    )
    db_url: str = Field(
        default="sqlite+aiosqlite:///~/.vxis/vxis.db",
        description="SQLAlchemy database URL. Defaults to a local SQLite file.",
    )
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # ------------------------------------------------------------------
    # External API credentials (SecretStr prevents accidental logging)
    # ------------------------------------------------------------------
    shodan_api_key: SecretStr | None = None
    censys_api_id: SecretStr | None = None
    censys_api_secret: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    github_token: SecretStr | None = None

    # ------------------------------------------------------------------
    # Hybrid LLM roles
    # ------------------------------------------------------------------
    director_llm: str = Field(
        default="",
        description="Frontier director model in provider/model format. Env: VXIS_DIRECTOR_LLM.",
    )
    worker_llm: str = Field(
        default="",
        description="Local-first worker model in provider/model format. Env: VXIS_WORKER_LLM.",
    )
    verifier_llm: str = Field(
        default="",
        description="Strong verifier model in provider/model format. Env: VXIS_VERIFIER_LLM.",
    )
    summarizer_llm: str = Field(
        default="",
        description="Cheap/local summarizer model in provider/model format. Env: VXIS_SUMMARIZER_LLM.",
    )

    # ------------------------------------------------------------------
    # Ghost Mode — 익명화 프록시 풀
    # ------------------------------------------------------------------
    proxy_pool: list[str] = Field(
        default_factory=list,
        description=(
            "Ghost 모드 프록시 목록. 콤마 구분 env var: VXIS_PROXY_POOL. "
            "예: socks5://127.0.0.1:9050,http://user:pass@proxy:8080. "
            "Tor(socks5://127.0.0.1:9050) 사용 시 출구 노드 오염 경고 발생. "
            "VXIS_GHOST_ALLOW_TOR=true 로 경고 무시 가능."
        ),
    )
    ghost_allow_tor: bool = Field(
        default=False,
        description="Tor 출구 노드 오염 경고를 무시하고 강제 사용. VXIS_GHOST_ALLOW_TOR=true.",
    )

    # ------------------------------------------------------------------
    # Ollama (local uncensored LLM)
    # ------------------------------------------------------------------
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama API base URL. Default: http://localhost:11434",
    )
    ollama_uncensored_model: str = Field(
        default="qwen2.5-coder:14b",
        description="Ollama model for uncensored brain mode. Override with VXIS_OLLAMA_UNCENSORED_MODEL.",
    )
    llamacpp_base_url: str = Field(
        default="http://localhost:8080",
        description="llama.cpp server OpenAI-compatible base URL. Default: http://localhost:8080",
    )
    llamacpp_model: str = Field(
        default="huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m",
        description="Default llama.cpp model id exposed by the local server.",
    )
    llamacpp_hf_repo: str = Field(
        default="shennguyen/Huihui-Qwen3.6-35B-A3B-Claude-4.7-Opus-abliterated-GGUF",
        description="Optional Hugging Face repo used to launch llama.cpp locally.",
    )
    llamacpp_hf_file: str = Field(
        default="huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m.gguf",
        description="Optional GGUF file name used to launch llama.cpp locally.",
    )
    llamacpp_context: int = Field(
        default=2048,
        ge=512,
        description="Recommended startup context window for llama.cpp local runs on memory-constrained Macs.",
    )

    # ------------------------------------------------------------------
    # Scan profiles
    # ------------------------------------------------------------------
    profiles: dict[str, ScanProfile] = Field(
        default_factory=_default_profiles,
        description="Named scan profiles. The four built-in profiles are always present.",
    )

    # ------------------------------------------------------------------
    # Tool-level defaults (can be overridden per-profile via tool_overrides)
    # ------------------------------------------------------------------
    tools: dict[str, ToolSettings] = Field(default_factory=dict)

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------
    report_output_dir: Path = Field(
        default=Path("~/.vxis/reports").expanduser(),
        description="Directory where generated reports are written.",
    )
    report_company_name: str = "VXIS Security"
    report_author: str = ""

    # ------------------------------------------------------------------
    # Dashboard
    # ------------------------------------------------------------------
    dashboard_token: SecretStr | None = Field(
        default=None,
        description=(
            "Shared secret token for dashboard authentication. "
            "When set, all dashboard requests must include a Bearer token "
            "or ?token= query parameter. Leave unset to disable auth."
        ),
    )
