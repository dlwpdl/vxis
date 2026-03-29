"""
Upstream Watch — Target repository configuration.

Defines which repos to monitor, what to look for, and VXIS context
for AI-powered relevance filtering.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class WatchTarget:
    """A GitHub repository to monitor for changes relevant to VXIS."""

    owner: str
    repo: str
    reason: str  # Why we watch this repo
    watch_releases: bool = True
    watch_commits: bool = True
    branches: tuple[str, ...] = ("main", "master")
    # Paths to focus on (empty = all). Reduces noise from docs/CI changes.
    include_paths: tuple[str, ...] = ()
    # Paths to ignore
    exclude_paths: tuple[str, ...] = (
        "docs/",
        ".github/",
        "README.md",
        "CHANGELOG.md",
        "LICENSE",
        ".gitignore",
    )
    # Relevance tags — AI uses these to judge importance
    relevance_tags: tuple[str, ...] = ()


# ── Target Repositories ──────────────────────────────────────────

TARGETS: list[WatchTarget] = [
    # ── AI Pentest Agents ──
    WatchTarget(
        owner="usestrix",
        repo="strix",
        reason="AI agent pentest framework — architecture, agent patterns, vuln dedup, scan modes",
        include_paths=("src/", "strix/", "agents/", "lib/"),
        relevance_tags=(
            "agent-architecture",
            "vuln-dedup",
            "scan-mode",
            "browser-automation",
            "ci-integration",
            "report-generation",
        ),
    ),
    WatchTarget(
        owner="vxcontrol",
        repo="pentagi",
        reason="Multi-agent pentest system — knowledge graph, memory system, sandboxed execution",
        include_paths=("backend/", "internal/", "pkg/", "cmd/"),
        relevance_tags=(
            "knowledge-graph",
            "multi-agent",
            "memory-system",
            "sandboxed-execution",
            "tool-orchestration",
        ),
    ),
    WatchTarget(
        owner="0x4m4",
        repo="hexstrike-ai",
        reason="MCP server for security tools — tool integration patterns, MCP protocol usage",
        include_paths=("src/", "tools/", "agents/"),
        relevance_tags=(
            "mcp-server",
            "tool-integration",
            "web-automation",
            "agent-framework",
        ),
    ),
    # ── Core Security Tools (used by VXIS plugins) ──
    WatchTarget(
        owner="projectdiscovery",
        repo="nuclei",
        reason="Primary vuln scanner — new template features, output format changes, performance improvements",
        include_paths=("pkg/", "cmd/", "internal/"),
        exclude_paths=("docs/", ".github/", "integration_tests/"),
        relevance_tags=(
            "template-engine",
            "output-format",
            "scan-performance",
            "new-protocols",
        ),
    ),
    WatchTarget(
        owner="projectdiscovery",
        repo="nuclei-templates",
        reason="Vuln template updates — new CVEs, detection techniques",
        watch_commits=False,  # Too noisy, releases only
        relevance_tags=("new-cve-templates", "detection-techniques"),
    ),
    WatchTarget(
        owner="projectdiscovery",
        repo="subfinder",
        reason="Subdomain enumeration — new sources, API changes",
        include_paths=("v2/pkg/", "v2/cmd/"),
        relevance_tags=("recon-sources", "api-changes", "output-format"),
    ),
    WatchTarget(
        owner="projectdiscovery",
        repo="httpx",
        reason="HTTP probing — new detection features, output fields",
        include_paths=("cmd/", "runner/", "common/"),
        relevance_tags=("tech-detect", "output-fields", "cdn-detection"),
    ),
    WatchTarget(
        owner="aquasecurity",
        repo="trivy",
        reason="Container/supply-chain scanner — new analyzers, output changes",
        include_paths=("pkg/", "cmd/"),
        relevance_tags=(
            "new-analyzers",
            "output-format",
            "sbom",
            "license-scanning",
        ),
    ),
    WatchTarget(
        owner="trufflesecurity",
        repo="trufflehog",
        reason="Secrets detection — new detectors, output format",
        include_paths=("pkg/"),
        relevance_tags=("new-detectors", "output-format", "verification"),
    ),
    WatchTarget(
        owner="prowler-cloud",
        repo="prowler",
        reason="Cloud security — new checks, AWS/Azure/GCP coverage",
        include_paths=("prowler/providers/", "prowler/lib/"),
        relevance_tags=("new-checks", "cloud-providers", "compliance-frameworks"),
    ),
    # ── Emerging Tools to Watch ──
    WatchTarget(
        owner="GH05TCREW",
        repo="pentestagent",
        reason="AI agent framework for black-box testing — workflow patterns",
        relevance_tags=("agent-workflow", "black-box-testing"),
    ),
    # ── AI-Powered Security Assistants ──
    WatchTarget(
        owner="GreyDGL",
        repo="PentestGPT",
        reason="GPT-based interactive pentest assistant — AI workflow and prompt engineering patterns",
        include_paths=("pentestgpt/", "src/"),
        relevance_tags=("ai-agent", "llm", "interactive-pentest", "gpt"),
    ),
    WatchTarget(
        owner="browser-use",
        repo="browser-use",
        reason="AI browser automation — Playwright + LLM agent patterns, CPR Eyes 개선 참고",
        include_paths=("browser_use/", "examples/"),
        relevance_tags=("ai-agent", "browser", "playwright", "automation", "cpr"),
    ),
    # ── Recon & OSINT Frameworks ──
    WatchTarget(
        owner="blacklanternsecurity",
        repo="bbot",
        reason="Modular recon framework — module system, dependency resolution, event pipeline",
        include_paths=("bbot/modules/", "bbot/core/", "bbot/scanner/"),
        relevance_tags=("recon", "osint", "modular", "pipeline", "subdomain"),
    ),
    WatchTarget(
        owner="six2dez",
        repo="reconftw",
        reason="All-in-one recon pipeline — tool chain orchestration patterns",
        include_paths=("reconftw.sh",),
        watch_commits=True,
        watch_releases=True,
        relevance_tags=("recon", "pipeline", "automation", "all-in-one"),
    ),
    # ── Scan Orchestration & Workflow Engines ──
    WatchTarget(
        owner="j3ssie",
        repo="osmedeus",
        reason="Workflow-based scan orchestration — distributed scanning, workflow engine",
        include_paths=("core/", "libs/", "workflow/"),
        relevance_tags=("workflow", "automation", "distributed", "scan-engine"),
    ),
    # ── Adversary Emulation & TTP Libraries ──
    WatchTarget(
        owner="mitre",
        repo="caldera",
        reason="Adversary emulation — plugin architecture, ATT&CK mapping, agent patterns",
        include_paths=("app/", "plugins/"),
        relevance_tags=("adversary-emulation", "mitre-attack", "agent", "plugin-system"),
    ),
    WatchTarget(
        owner="redcanaryco",
        repo="atomic-red-team",
        reason="ATT&CK TTP test cases — new techniques and detection coverage",
        watch_commits=False,
        watch_releases=True,
        relevance_tags=("mitre-attack", "ttp", "detection", "testing"),
    ),
    # ── Modern Web Security Tooling ──
    WatchTarget(
        owner="caido",
        repo="caido",
        reason="Modern web security proxy — UX patterns, plugin system, automation API",
        include_paths=("packages/",),
        relevance_tags=("web-security", "proxy", "automation", "modern-ui"),
    ),
]


# ── VXIS Context (fed to AI for relevance judgment) ──────────────

VXIS_CONTEXT = """\
VXIS is an AI-powered security automation platform that orchestrates 35+ \
open-source security tools via CLI subprocess, analyzes results with multi-model \
AI, and generates NCC Group-grade consulting reports.

Current architecture:
- Plugin system: BasePlugin ABC with DAG-based execution (asyncio)
- 35 plugins across 15 categories (recon, scan, vuln, crypto, secrets, cert, \
  osint, brand, code, container, cloud, supply_chain, cicd, ad, privesc, email)
- Finding pipeline: normalize → deduplicate (SHA-256 hash) → FP filter (5-stage) → enrich (CVSS/MITRE/compliance)
- Report engine: Jinja2 HTML + DOCX export + attestation letters + SVG charts
- Dashboard: FastAPI + HTMX
- CLI: Typer + Rich
- DB: SQLAlchemy async (SQLite/PostgreSQL)

Areas of active interest:
1. AI-based vulnerability deduplication (LLM semantic matching)
2. Scan checkpoint/resume for long-running scans
3. Knowledge graph / smart memory across scan sessions
4. Browser automation for evidence screenshots (Playwright)
5. MCP server mode for AI agent ecosystem integration
6. Historical delta / trend analysis across repeat scans
7. NVD cache with live API lookup
8. CI/CD integration (GitHub Actions templates)
9. PDF generation alternative (WeasyPrint blocked by GHSA)

IMPORTANT LICENSE CONSTRAINT:
- AGPL/GPL code must NOT be copied. Architecture concepts and approaches only.
- All VXIS code must be 100% original.
- When suggesting changes, describe the CONCEPT to implement, not code to copy.
"""


# ── Wrapped Tool → VXIS Plugin Mapping ──────────────────────────
# When these repos release a new version, VXIS should validate
# that the corresponding plugin's CLI flags are still compatible.

TOOL_PLUGIN_MAP: dict[str, str] = {
    "projectdiscovery/nuclei": "nuclei",
    "projectdiscovery/httpx": "httpx",
    "projectdiscovery/subfinder": "subfinder",
    "aquasecurity/trivy": "trivy",
    "trufflesecurity/trufflehog": "trufflehog",
    "prowler-cloud/prowler": "prowler",
}


# ── Notification Config ──────────────────────────────────────────

@dataclass
class NotifyConfig:
    """Notification channel configuration. Values from env vars."""

    slack_webhook_url: str = ""  # VXIS_SLACK_WEBHOOK
    # Future: notion_token, notion_database_id, discord_webhook, email
    digest_output_dir: str = "tools/upstream_watch/digests"
    min_relevance_score: float = 0.6  # 0.0-1.0, below this = skip notification


# ── State Tracking ───────────────────────────────────────────────

STATE_FILE = "tools/upstream_watch/.state.json"
DIGEST_DIR = "tools/upstream_watch/digests"
