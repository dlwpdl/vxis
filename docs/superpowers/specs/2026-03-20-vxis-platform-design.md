# VXIS Security Automation Platform — Design Specification

## 1. Overview

VXIS is an AI-powered security automation platform that orchestrates 40+ open-source security tools via CLI subprocess, analyzes results with multi-model AI, and generates NCC Group-grade consulting reports.

**Product type**: Consulting tool (operator runs on their machine, delivers reports to clients)
**Domain**: vxis.io
**License**: Proprietary (private repo, 100% original code)
**Language**: Python (Go CLI binaries called via subprocess)

### 1.1 Service Tiers

| Tier | Name | Mode | Description |
|------|------|------|-------------|
| 1 | Recon | Zero-Touch | No client cooperation required. External scanning only. |
| 2 | Breach | Cooperative | Client provides access (VPN, credentials, AWS role, source code). |

### 1.2 Business Model

1. ProtoPie internal dogfooding (first client)
2. Freelance consulting (Korean SMBs, startups)
3. PE/VC portfolio batch scanning
4. Korean company incorporation

---

## 2. Architecture

### 2.1 System Architecture

```
CLI Input ("vxis scan --target example.com --tier recon --profile standard")
    │
    ▼
┌─────────────────────────────────────────────────────────┐
│ Core Engine                                             │
│                                                         │
│  ┌──────────┐   ┌───────────┐   ┌──────────────────┐   │
│  │ Scope    │──▶│ DNS       │──▶│ DAG Executor      │   │
│  │ Validator│   │ Resolver  │   │ (asyncio)         │   │
│  └──────────┘   │ (pinning) │   │                   │   │
│                 └───────────┘   │ ┌───────────────┐ │   │
│                                 │ │ DAGContext     │ │   │
│  ┌──────────────┐               │ │ (typed data   │ │   │
│  │ Global Rate  │◀─────────────▶│ │  flow)        │ │   │
│  │ Limiter      │               │ └───────────────┘ │   │
│  │ (token bucket│               │                   │   │
│  │  per target) │               │ Semaphore L1/L2   │   │
│  └──────────────┘               └─────────┬─────────┘   │
│                                           │              │
│  ┌────────────────────────────────────────▼──────────┐   │
│  │ Plugin Layer (async subprocess)                   │   │
│  │ subfinder → httpx → nmap → nuclei → testssl →... │   │
│  └────────────────────────────────────────┬──────────┘   │
│                                           │              │
│  ┌────────────────────────────────────────▼──────────┐   │
│  │ Post-Processing Pipeline                          │   │
│  │ FindingFactory → Deduplicator → FP Pipeline →     │   │
│  │ Enricher (CVSS/MITRE/Compliance) → DB             │   │
│  └────────────────────────────────────────┬──────────┘   │
│                                           │              │
│  ┌────────────────────────────────────────▼──────────┐   │
│  │ Report Engine                                     │   │
│  │ Jinja2 (80%) + Claude AI (20%) → PDF/DOCX        │   │
│  └──────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 2.2 Directory Structure

```
vxis/
├── cli/
│   └── main.py                 # Typer + Rich Live
├── core/
│   ├── engine.py               # asyncio DAG executor
│   ├── context.py              # DAGContext (typed data flow between plugins)
│   ├── scanner.py              # async subprocess wrapper (run_tool)
│   ├── normalizer.py           # FindingFactory per tool + FindingDeduplicator
│   ├── enricher.py             # CVSS + MITRE ATT&CK + compliance + remediation
│   ├── fp_pipeline.py          # 5-stage FP elimination
│   ├── rate_limiter.py         # global token bucket per target
│   ├── dns_resolver.py         # DNS pinning per scan session
│   ├── scope.py                # scope validation + authorization check
│   ├── logger.py               # audit logging (tamper-evident, timestamped)
│   ├── resilience.py           # retry + graduated failure (4 levels)
│   └── db.py                   # SQLite WAL + write-behind buffer
├── plugins/
│   ├── base.py                 # BasePlugin ABC (required/optional depends)
│   ├── registry.py             # auto-discovery via pkgutil + DAG builder
│   ├── recon/
│   │   ├── subfinder.py
│   │   └── httpx_plugin.py
│   ├── scan/
│   │   ├── nmap_plugin.py
│   │   └── wafw00f_plugin.py
│   ├── vuln/
│   │   └── nuclei_plugin.py
│   ├── crypto/
│   │   ├── testssl_plugin.py
│   │   └── checkdmarc_plugin.py
│   └── secrets/
│       └── trufflehog_plugin.py
├── models/
│   ├── finding.py              # Pydantic Finding + 2-layer dedup
│   ├── evidence.py             # EvidenceItem + chain of custody
│   └── db_models.py            # SQLAlchemy ORM (ScanRecord, FindingRecord, ToolRunRecord)
├── report/
│   ├── generator.py            # Jinja2 + WeasyPrint
│   ├── ai_summary.py           # Claude API executive summary
│   ├── charts.py               # SVG donut/bar charts
│   └── templates/
│       ├── base.html
│       ├── styles/
│       │   └── main.css        # @page print CSS
│       ├── partials/
│       │   ├── _cover.html
│       │   ├── _toc.html
│       │   ├── _executive_summary.html
│       │   ├── _methodology.html
│       │   ├── _finding_card.html
│       │   ├── _severity_chart.html
│       │   └── _attestation.html
│       └── profiles/
│           ├── default.html
│           ├── executive.html
│           └── technical.html
├── knowledge/
│   ├── fp_registry.py          # FP pattern storage/lookup
│   ├── nvd_cache.py            # NVD CVSS local cache (24h TTL)
│   ├── compliance_mappings.json
│   ├── mitre_attack.json
│   └── remediation_templates.toml
├── Dockerfile
├── config.toml
├── pyproject.toml
└── tests/
    ├── unit/
    ├── integration/
    └── fixtures/               # Real tool output samples
```

---

## 3. Core Components

### 3.1 DAG Executor (core/engine.py)

**Pattern**: asyncio event loop + topological sort + semaphore concurrency control

**Key behaviors**:
- Plugins declare `depends_on` (required) and `optional_depends`
- Required dependency failure → skip dependent node
- Optional dependency failure → run dependent with defaults
- DAGContext carries typed results between nodes (not just completion signals)
- WAF detection result dynamically adjusts nuclei rate-limit via DAGContext
- Global timeout budget across entire scan session
- Cycle detection at DAG construction time (before execution)

**Concurrency**:
- L1 Semaphore: limits concurrent DAG nodes (tools)
- L2 monitoring: psutil-based system resource check (CPU/memory)
- Fan-out strategy: batch subdomains in groups of 50, respect OS fd limits

**Graduated failure model**:

| Level | Condition | Action |
|-------|-----------|--------|
| SUCCESS | exit 0, valid output | Continue normally |
| PARTIAL | exit != 0, but stdout has valid data | Continue with warning, use partial data |
| DEGRADED | some targets completed, others failed | Continue with available results |
| FAILED | no recoverable output | Skip dependents (required) or use defaults (optional) |

### 3.2 Plugin System (plugins/base.py)

**Granularity**: One plugin per tool (not per category)

```python
@dataclass(frozen=True)
class PluginMeta:
    name: str                          # "subfinder", "nmap", etc.
    version: str
    tool_binary: str                   # binary name for shutil.which()
    category: str                      # "recon", "scan", "vuln", "crypto", "secrets"
    depends_on: tuple[str, ...]        # required dependencies
    optional_depends: tuple[str, ...]  # optional dependencies (defaults if missing)
    timeout_seconds: int
    produces: tuple[str, ...]          # output data keys in DAGContext

class BasePlugin(ABC):
    meta: PluginMeta
    build_command(target, scan_profile, ctx: DAGContext, tool_config) -> str
    parse_output(raw_stdout, raw_stderr) -> PluginOutput
    validate_environment() -> bool
    get_timeout(scan_profile) -> int
```

**Auto-discovery**: pkgutil walks `vxis.plugins.*`, finds all BasePlugin subclasses, registers them, and builds DAG from their metadata.

### 3.3 Scan DAG (Phase 0 — 8 tools)

```
TARGET
  │
  ├── subfinder ──── httpx ──┬── nmap ──┬── nuclei
  │                          │          │
  ├── checkdmarc             ├── wafw00f┘  (wafw00f gates nuclei rate)
  │                          │
  └── trufflehog             └── testssl.sh
```

**Tool specifications**:

| Tool | Input | Key Flags | Output | Timeout |
|------|-------|-----------|--------|---------|
| subfinder | target domain | `-all -recursive -oJ -silent` | JSON Lines (subdomains) | 5min |
| httpx | subfinder subdomains | `-json -tech-detect -tls-grab -cdn -cname -asn` | JSON Lines (live hosts) | 10min |
| nmap | httpx live IPs (non-CDN) | `-sV -sC -O --open --reason -oX` | XML | 30min |
| nuclei | httpx live URLs | `-severity crit,high,med -irr -json-export -etags dos,fuzz` | JSON Lines | 90min |
| testssl.sh | nmap 443 hosts | `--fast --sneaky --severity LOW --jsonfile` | JSON | 8min/host |
| checkdmarc | target domain | `--output-format json` + BIMI/MTA-STS/DKIM selector checks | JSON | 30sec |
| wafw00f | httpx live URLs | `-a -f json` | JSON | 2min |
| trufflehog | GitHub org | `github --org --json --no-verification --exclude-globs` | JSON Lines | 60min |

### 3.4 Finding Model (models/finding.py)

**Pydantic model with**:
- Severity enum (critical/high/medium/low/informational)
- CVSSVector (v3.1 with auto-calculated severity)
- MitreAttack mapping
- Evidence list (typed: http_transaction, screenshot, cli_output, dns_record, certificate)
- analyst_severity override + analyst_notes
- effective_severity computed field

**2-Layer Deduplication**:

```
Layer 1 (Exact): SHA-256(canonical_target + port + protocol + finding_type + CVE/CWE + affected_component)
  → Auto-merge: combine evidence, keep highest severity, merge source_plugins list

Layer 2 (Fuzzy): SHA-256(canonical_target + finding_type + CVE/CWE)
  → No auto-merge: group as "related findings" for analyst review
```

`canonical_target` uses DNS pinning results to unify IP ↔ domain references.

### 3.5 FP Elimination Pipeline (core/fp_pipeline.py)

5 stages, sequential:

| Stage | Name | Action |
|-------|------|--------|
| 0 | Context Pre-filter | Drop findings impossible for detected tech stack (e.g., IIS vuln on Apache) |
| 1 | Tool-level Validation | Wildcard DNS check, nmap reason verification, nuclei matcher re-check |
| 2 | Cross-tool Correlation | nuclei TLS finding + testssl.sh confirmation → confidence +0.20 |
| 3 | Re-validation | Re-send nuclei HTTP request for HIGH/CRITICAL findings, compare response |
| 4 | Confidence Scoring | Base per tool + modifiers → score 0.0-1.0, threshold 0.5 for report inclusion |

**Base confidence scores**: testssl 0.90, checkdmarc 0.95, nuclei 0.60, nmap 0.75, trufflehog 0.55, wafw00f 0.70

**Cross-validation rules** stored declaratively in TOML (not hardcoded).

### 3.6 Finding Enrichment (core/enricher.py)

All stages run in parallel per finding:

1. **CVSS**: NVD API lookup (with local cache, 24h TTL) → tool-embedded score → deterministic derivation from finding characteristics
2. **MITRE ATT&CK**: Static mapping (finding tags → technique IDs) using enterprise-attack.json
3. **Compliance**: Static JSON mapping (finding_type → ISO 27001/SOC 2/ISMS-P/PCI DSS/NIST CSF controls)
4. **Business Impact**: Context-based estimation (industry + finding type → financial/reputational/regulatory impact)
5. **Remediation**: 3-tier (static template → AI-generated → reference-only)

### 3.7 Evidence Collection (models/evidence.py)

Each EvidenceItem contains:
- evidence_type, captured_at (UTC), captured_by (tool+version)
- SHA-256 content hash
- chain_of_custody (append-only audit trail)
- PII redacted non-reversibly at capture time
- Secrets masked at DB storage (original in encrypted storage only)

**Sources**:
- nuclei `-irr` flag captures HTTP request/response pairs
- Playwright headless screenshots for specific finding types (default-login, exposure, takeover, panel)
- Raw tool stdout preserved per ToolRunRecord
- Tool version captured at execution time for reproducibility

### 3.8 Rate Limiting (core/rate_limiter.py)

**Two layers**:
1. Per-tool rate limits (configured in scan profile)
2. Per-target global token bucket (all tools combined, prevents aggregate DoS)

**4 Scan Profiles**:

| Profile | Rate/host | Concurrency | nmap Timing | nuclei Rate | Ports |
|---------|-----------|-------------|-------------|-------------|-------|
| PASSIVE_ONLY | 0 (no active probes) | N/A | N/A | N/A | N/A |
| STEALTH | 1-5 req/s | 2 tools | -T2 | 5-10 | 80,443,8080,8443 |
| STANDARD | 50 req/s | 5 tools | -T3 | 50-100 | curated 40 ports |
| AGGRESSIVE | 200 req/s | 8 tools | -T4 | 150-500 | all 65535 |

### 3.9 DNS Pinning (core/dns_resolver.py)

At scan session start, resolve all discovered subdomains and pin results. All subsequent tools receive resolved IPs, ensuring:
- Finding target consistency (no IP ↔ domain mismatch in dedup)
- CDN detection accuracy (same IP throughout scan)
- Reproducible results across scan phases

### 3.10 Resilience (core/resilience.py)

- RetryConfig: max 2 retries, exponential backoff (5s base, 2x multiplier)
- Retryable exit codes: 1, 137 (OOM killed)
- Non-zero exit with stdout → treated as PARTIAL, data extracted
- Per-plugin timeout with profile multiplier (stealth 2x, aggressive 0.5x)
- Checkpoint/resume: DAG node state persisted to SQLite, resume skips completed nodes

---

## 4. Report Engine

### 4.1 Architecture

Jinja2 template inheritance:
- `base.html` → layout, headers, footers, page breaks
- `profiles/*.html` → extends base (default, executive, technical)
- `partials/*.html` → included blocks (cover, finding_card, charts)

**AI scope (20%)**: Executive summary paragraph, attack narrative per finding, business impact paragraph, risk rating justification. All via Claude Sonnet with structured prompts.

**Template scope (80%)**: Cover page, ToC, methodology, finding cards (title/severity/CVSS/evidence/remediation/references), severity charts, compliance mapping tables, attestation letter.

### 4.2 Output Formats

1. **PDF** (WeasyPrint) — primary deliverable, NCC Group style
2. **DOCX** (python-docx) — editable version for clients
3. **Attestation Letter** (1-page PDF) — severity summary for compliance submission
4. **Web Dashboard** (Phase 2+) — real-time scan results with export

### 4.3 Report Structure (NCC Group Reference)

1. Cover Page (client name, date, VXIS branding, classification)
2. Executive Summary (AI-generated, 3-4 paragraphs)
3. Table of Contents
4. Document Control (version history, confidentiality notice)
5. Technical Summary (scope, caveats, methodology)
6. Table of Findings (severity matrix with status)
7. Risk Ratings (CVSS explanation, exploitability scale)
8. Finding Details (per finding):
   - Overall Risk / Impact / Exploitability
   - Finding ID, Component, Category, Status
   - Description (AI-assisted attack narrative)
   - Evidence (HTTP transaction, screenshots, CLI output)
   - Recommendation (3-tier: immediate/short-term/long-term)
   - References
   - MITRE ATT&CK mapping
   - Compliance mapping
9. Appendix (tool versions, scan configuration, methodology details)

---

## 5. Data Model

### 5.1 Database

SQLite with WAL mode. SQLAlchemy ORM for PostgreSQL upgrade path.

**Tables**:
- `scans` — scan sessions (id, target, profile, status, timestamps, config snapshot)
- `findings` — normalized findings (all Finding fields, indexed on scan_id+severity, target+dedup_hash)
- `tool_runs` — execution audit trail (command, exit code, stdout path, timestamps, elapsed)
- `evidence` — evidence items (finding_id FK, type, sha256, content/file_path, chain_of_custody JSON)

**Per-scan isolation**: Each scan session uses a separate SQLite file for concurrent scan support.

### 5.2 Config

TOML + Pydantic Settings. Loading priority: env vars (VXIS_ prefix) → .env → config.toml → defaults.

Secrets (API keys) via environment variables only, never in config files. Pydantic SecretStr type.

Per-client config in `clients/*.toml` (targets, exclusions, scope notes, custom logo).

---

## 6. Scan Scope (Tier 1 + Tier 2)

### 6.1 Tier 1 Recon Scope (Zero-Touch)

| Category | Checks | Tools | Automation |
|----------|--------|-------|-----------|
| DNS/Email | SPF/DKIM/DMARC/DNSSEC/MTA-STS, subdomain enum, takeover | checkdmarc, subfinder, amass, dnsx, nuclei | 95% |
| Network | Port scan, service fingerprint, SSL/TLS, 30+ service vulns | nmap, masscan, testssl.sh, ssh-audit | 95% |
| WebApp | OWASP Top 10 external, headers, WAF, content discovery | nuclei, ffuf, httpx, wafw00f, sqlmap | 85% |
| Cloud | AWS 300+ checks (read-only IAM), public S3/ECR, Azure/GCP | Prowler, ScoutSuite, S3Scanner | 90% |
| OSINT | Credential leaks, code repo secrets, employee enum, Shodan | trufflehog, gitleaks, theHarvester, shodan | 70% |
| Supply Chain | Dependency CVEs, typosquatting, CI/CD workflow | snyk, trivy, confused, poutine | 85% |
| Cert/PKI | CT monitoring, wildcard, unexpected CA, expiry | crt.sh, certspotter, sslyze | 95% |
| Brand | Lookalike domains, phishing kits | dnstwist, URLCrazy | 60% |

### 6.2 Tier 2 Breach Scope (Cooperative)

| Category | Tools | Automation |
|----------|-------|-----------|
| AD/LDAP | bloodhound, certipy, impacket, NetExec | 85% (enum FA, exploitation SA) |
| Privilege Escalation | linpeas, winpeas, WESng, LES | 90% (find FA, validate SA) |
| SAST | semgrep, codeql, bandit, checkov | 60% (high FP, needs triage) |
| Container/K8s | trivy, kube-bench, polaris, deepce | 90% |
| CI/CD | poutine, actionlint | 60% |
| Cloud Deep | PMapper, ScoutSuite, Steampipe, cloudmapper | 85% |
| Social Engineering | GoPhish | 50% (template manual) |
| Compliance | Prowler profiles, ScoutSuite | 70% |

---

## 7. Knowledge System

### 7.1 FP Registry

Analyst verdicts (TP/FP) recorded per finding. Context-aware: target technology, WAF, CDN. Auto-disable templates exceeding 50% FP rate with 10+ samples. Rules stored declaratively in TOML.

### 7.2 NVD Cache

Local SQLite cache of NVD CVSS data. 24h TTL. Bulk download sync daily. Eliminates API rate limit bottleneck.

### 7.3 Historical Delta

Repeat scans compute diff: new findings, resolved findings, persistent findings, regressions. Delta included in report.

### 7.4 Nuclei Template Management

- Fork community templates to internal repo
- Exclude: fuzzing/, dos/, helpers/
- Include: cves/ (CVSS >= 7.0), exposures/, misconfigurations/, default-logins/, takeovers/, ssl/
- 30-day delay on new releases
- Template validation harness against known-vulnerable + known-clean targets
- Version pinned per release tag

---

## 8. Legal & Security Safeguards

1. **Scope Validator**: IP/domain whitelist check before ANY scan tool executes. Hard block on out-of-scope targets.
2. **Authorization Check**: Y/N prompt with scope document reference before scan start.
3. **Audit Logging**: Every tool invocation logged (timestamp, tool, target, command, operator). Tamper-evident.
4. **PII Redaction**: Non-reversible masking of PII patterns in evidence at capture time.
5. **Secret Handling**: trufflehog findings masked in DB/reports. Originals in encrypted-at-rest storage only.
6. **Rate Limiting**: Global per-target token bucket prevents accidental DoS.
7. **DNS Pinning**: Prevents scanning unintended IPs due to DNS changes mid-scan.

---

## 9. Testing Strategy

### 3-Tier Pyramid

| Tier | What | How | Speed |
|------|------|-----|-------|
| Unit | DAG logic, dedup hash, FP rules, config parsing, models | pytest + mock subprocess | Fast (<10s) |
| Integration | Tool output parsers against fixture files, report rendering | pytest + real tool output samples in tests/fixtures/ | Medium (<60s) |
| E2E | Full scan pipeline with real tools against test targets | CI only, Docker environment | Slow (<30min) |

---

## 10. Deployment

### Docker Image

```dockerfile
FROM python:3.12-slim
# Install Go tools (subfinder, httpx, nuclei, etc.)
# Install system tools (nmap, testssl.sh, etc.)
# Install Python dependencies
# Copy VXIS source
ENTRYPOINT ["python", "-m", "vxis"]
```

All 8+ security tools pre-installed. Single `docker run` to execute scans.

---

## 11. Phase Plan

| Phase | Scope | Key Deliverables |
|-------|-------|-----------------|
| 0 | Core engine + 8 plugins + PDF report | MVP: `vxis scan` produces consulting-grade PDF |
| 1 | +10 plugins (cloud, osint, supply chain, cert, brand) | Full Tier 1 Recon coverage |
| 2 | Tier 2 plugins (AD, privesc, SAST, container, CI/CD) | Full Tier 2 Breach coverage |
| 3 | Web dashboard + DOCX export + batch mode | PE portfolio scanning capability |
| 4 | White-label + multi-client management | Consulting business scalability |
| 5+ | SaaS transition, Korean company incorporation | Business model evolution |

---

## 12. Constraints & Non-Goals

### Constraints
- AGPL code (Strix, PentAGI) must NOT be forked/copied. Architecture concepts only.
- NCC Group reports are confidential reference — format/structure only, no content.
- All VXIS code is 100% original.
- Open-source tools called via CLI subprocess only (no license contamination).

### Non-Goals (explicitly excluded)
- SaaS multi-tenant platform (future consideration)
- Real-time monitoring/SIEM integration
- Automated exploitation without human review
- Mobile app
