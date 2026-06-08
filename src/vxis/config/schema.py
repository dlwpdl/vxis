"""
VXIS configuration schema using Pydantic Settings v2.

Defines all configuration models for the security automation platform,
including scan profiles, client configs, tool settings, and the root
VXISConfig settings class that reads from env vars and .env file.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Mapping

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
    family: Literal["core", "business"] = "core"
    intent: str = "crown_jewel"
    status: Literal["active", "scaffold"] = "active"
    public_name: str = ""
    public_tool_disclosure: bool = False
    standards: list[str] = Field(default_factory=list)
    assessment_modules: list[str] = Field(default_factory=list)
    report_sections: list[str] = Field(default_factory=list)
    requires_engagement: bool = False
    allowed_techniques: list[str] = Field(default_factory=list)
    rate_limit: int = Field(ge=0, description="Requests per second; 0 = unlimited")
    max_concurrency: int = Field(ge=1)
    nmap_timing: int = Field(ge=0, le=5, description="Nmap -T timing template (0-5)")
    nuclei_rate: int = Field(ge=0, description="Nuclei requests per second")
    skip_plugins: list[str] = Field(default_factory=list)
    tool_overrides: dict[str, ToolSettings] = Field(default_factory=dict)

    @property
    def is_business_profile(self) -> bool:
        return self.family == "business"

    @property
    def is_scaffold(self) -> bool:
        return self.status == "scaffold"


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
    """Build the built-in scan profiles shipped with VXIS."""
    return {
        "crown": ScanProfile(
            name="crown",
            public_name="VXIS Crown Assessment",
            description=(
                "Default VXIS mode. Agentic, evidence-backed pentest focused "
                "on crown-jewel impact and attack-chain closure."
            ),
            family="core",
            intent="crown_jewel",
            status="active",
            assessment_modules=[
                "agentic_discovery",
                "attack_chain_validation",
                "business_logic_review",
                "evidence_backed_findings",
            ],
            report_sections=[
                "validated_findings",
                "attack_chains",
                "crown_jewel_impact",
                "discovered_not_tested",
                "remediation_plan",
            ],
            rate_limit=50,
            max_concurrency=5,
            nmap_timing=3,
            nuclei_rate=25,
        ),
        "passive": ScanProfile(
            name="passive",
            description=(
                "No direct contact with target systems. "
                "Uses third-party intelligence sources only (Shodan, Censys, etc.)."
            ),
            family="core",
            intent="passive_discovery",
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
            family="core",
            intent="low_footprint_crown",
            rate_limit=5,
            max_concurrency=2,
            nmap_timing=1,
            nuclei_rate=2,
            skip_plugins=["brute-force"],
        ),
        "standard": ScanProfile(
            name="standard",
            description=(
                "Legacy balanced core profile. Kept for compatibility; use "
                "'crown' for the default VXIS agentic pentest posture."
            ),
            family="core",
            intent="balanced_agentic",
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
            family="core",
            intent="high_intensity_crown",
            rate_limit=200,
            max_concurrency=8,
            nmap_timing=4,
            nuclei_rate=100,
        ),
        "continuous-devsec": ScanProfile(
            name="continuous-devsec",
            public_name="VXIS Continuous DevSec",
            description=(
                "Scaffold for recurring SaaS AppSec assessments. It wraps "
                "the crown engine with scope, cadence, delta, and customer "
                "reporting controls."
            ),
            family="business",
            intent="continuous_devsec",
            status="scaffold",
            standards=[
                "OWASP Top 10",
                "OWASP ASVS",
                "OWASP API Security Top 10",
                "CIS Continuous Vulnerability Management",
            ],
            assessment_modules=[
                "web_application_baseline",
                "api_authorization_review",
                "infrastructure_exposure_review",
                "cloud_configuration_review",
                "agentic_validation",
            ],
            report_sections=[
                "coverage_matrix",
                "tested_assets",
                "discovered_not_tested",
                "delta_summary",
                "third_party_dependencies",
                "validated_findings",
                "remediation_plan",
            ],
            rate_limit=25,
            max_concurrency=4,
            nmap_timing=2,
            nuclei_rate=10,
            skip_plugins=["brute-force"],
        ),
        "vc-portfolio-monitor": ScanProfile(
            name="vc-portfolio-monitor",
            public_name="VXIS Portfolio Cyber Risk Monitor",
            description=(
                "Scaffold for recurring VC portfolio monitoring and investor-"
                "facing cyber risk summaries across many companies."
            ),
            family="business",
            intent="portfolio_risk_monitoring",
            status="scaffold",
            standards=[
                "OWASP Top 10",
                "OWASP API Security Top 10",
                "CIS Continuous Vulnerability Management",
                "NIST Cybersecurity Supply Chain Risk Management",
            ],
            assessment_modules=[
                "external_attack_surface",
                "portfolio_risk_index",
                "infrastructure_exposure_review",
                "cloud_configuration_review",
                "discovered_asset_inventory",
            ],
            report_sections=[
                "portfolio_heatmap",
                "company_scorecards",
                "critical_risk_summary",
                "discovered_not_tested",
                "remediation_tracking",
                "board_ready_summary",
            ],
            rate_limit=15,
            max_concurrency=3,
            nmap_timing=2,
            nuclei_rate=5,
            skip_plugins=["brute-force", "destructive"],
        ),
        "pre-investment-dd": ScanProfile(
            name="pre-investment-dd",
            public_name="VXIS Pre-Investment Cyber Due Diligence",
            description=(
                "Scaffold for short-window investment diligence focused on "
                "critical exposure, ownership uncertainty, and business impact."
            ),
            family="business",
            intent="investment_due_diligence",
            status="scaffold",
            standards=[
                "OWASP Top 10",
                "OWASP API Security Top 10",
                "CIS Continuous Vulnerability Management",
            ],
            assessment_modules=[
                "rapid_external_exposure",
                "critical_vulnerability_review",
                "identity_and_access_review",
                "cloud_configuration_review",
                "investment_risk_summary",
            ],
            report_sections=[
                "go_no_go_summary",
                "critical_risks",
                "unknown_or_unverified_assets",
                "deal_condition_recommendations",
            ],
            rate_limit=20,
            max_concurrency=4,
            nmap_timing=2,
            nuclei_rate=8,
            skip_plugins=["brute-force", "destructive"],
        ),
        "remediation-verification": ScanProfile(
            name="remediation-verification",
            public_name="VXIS Remediation Verification",
            description=(
                "Scaffold for retesting known findings and producing fixed / "
                "not-fixed / regressed evidence."
            ),
            family="business",
            intent="remediation_verification",
            status="scaffold",
            assessment_modules=[
                "finding_retest",
                "control_regression_check",
                "evidence_delta",
                "attestation_ready_summary",
            ],
            report_sections=[
                "retest_summary",
                "fixed_findings",
                "not_fixed_findings",
                "regressions",
                "verification_evidence",
            ],
            rate_limit=20,
            max_concurrency=3,
            nmap_timing=2,
            nuclei_rate=5,
            skip_plugins=["brute-force", "broad-discovery"],
        ),
        "compliance-mapping": ScanProfile(
            name="compliance-mapping",
            public_name="VXIS Compliance Mapping",
            description=(
                "Scaffold add-on profile for mapping validated VXIS findings "
                "to SOC-2, ISO 27001, and ISMS-P controls. It is an output "
                "mapping layer, not a compliance consulting mode."
            ),
            family="business",
            intent="compliance_mapping",
            status="scaffold",
            standards=[
                "SOC-2 Common Criteria",
                "ISO 27001 Annex A",
                "ISMS-P",
                "MITRE ATT&CK",
            ],
            assessment_modules=[
                "control_mapping",
                "evidence_to_control_traceability",
                "portfolio_control_rollup",
            ],
            report_sections=[
                "mapped_controls",
                "control_coverage_matrix",
                "evidence_traceability",
                "unmapped_risks",
            ],
            rate_limit=25,
            max_concurrency=3,
            nmap_timing=2,
            nuclei_rate=5,
            skip_plugins=["brute-force", "destructive", "broad-discovery"],
        ),
        "p1-adversary-emulation": ScanProfile(
            name="p1-adversary-emulation",
            public_name="VXIS Adversary Emulation",
            description=(
                "Authorized adversary-emulation profile. All target-facing "
                "actions require an active P1 engagement, scope enforcement, "
                "and hash-chained audit."
            ),
            family="business",
            intent="adversary_emulation",
            status="active",
            requires_engagement=True,
            allowed_techniques=["recon", "emulate", "c2", "lateral", "persist"],
            assessment_modules=[
                "engagement_scope_enforcement",
                "adversary_emulation_orchestration",
                "immutable_audit_trail",
                "killswitch_lifecycle",
            ],
            report_sections=[
                "engagement_summary",
                "scope_decisions",
                "emulation_timeline",
                "audit_verification",
                "remediation_plan",
            ],
            rate_limit=10,
            max_concurrency=2,
            nmap_timing=1,
            nuclei_rate=2,
            skip_plugins=["destructive"],
        ),
    }


_PROFILE_ALIASES: dict[str, str] = {
    "": "crown",
    "default": "crown",
    "agentic": "crown",
    "crown-jewel": "crown",
    "crown_jewel": "crown",
    "devsec": "continuous-devsec",
    "continuous": "continuous-devsec",
    "b2b": "continuous-devsec",
    "b2b-standard": "continuous-devsec",
    "vc": "vc-portfolio-monitor",
    "portfolio": "vc-portfolio-monitor",
    "vc-baseline": "vc-portfolio-monitor",
    "vc-monitor": "vc-portfolio-monitor",
    "dd": "pre-investment-dd",
    "due-diligence": "pre-investment-dd",
    "retest": "remediation-verification",
    "compliance": "compliance-mapping",
    "p1": "p1-adversary-emulation",
    "ae": "p1-adversary-emulation",
    "adversary": "p1-adversary-emulation",
    "adversary-emulation": "p1-adversary-emulation",
}


def normalize_scan_profile_name(profile: str | None) -> str:
    value = str(profile or "").strip().lower()
    return _PROFILE_ALIASES.get(value, value or "crown")


def resolve_scan_profile(
    profile: str | None,
    profiles: Mapping[str, ScanProfile] | None = None,
) -> ScanProfile:
    profile_map = dict(profiles or _default_profiles())
    resolved = normalize_scan_profile_name(profile)
    if resolved not in profile_map:
        raise KeyError(f"unknown scan profile: {profile}")
    return profile_map[resolved]


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
        description="Named scan profiles. Built-in core and business profiles are always present.",
    )
    active_profile: str = Field(
        default="crown",
        description="Active scan profile name. Default is the core agentic crown profile.",
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
