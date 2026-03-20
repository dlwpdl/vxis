# VXIS Phase 0-A: Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the foundational layer — project scaffolding, data models, config system, and core infrastructure (subprocess runner, resilience, rate limiter, DNS resolver, scope validator, audit logger, database).

**Architecture:** Bottom-up construction of all core components that plugins and the engine will depend on. Every component is independently testable with unit tests. No external tool dependencies — this layer is pure Python.

**Tech Stack:** Python 3.12, Pydantic 2.x, SQLAlchemy 2.x (async, aiosqlite), TOML (tomli), pytest, pytest-asyncio

**Spec:** `docs/superpowers/specs/2026-03-20-vxis-platform-design.md`

---

## File Structure

```
vxis/
├── pyproject.toml
├── config.toml
├── src/
│   └── vxis/
│       ├── __init__.py
│       ├── models/
│       │   ├── __init__.py
│       │   ├── finding.py          # Pydantic Finding + 2-layer dedup
│       │   ├── evidence.py         # EvidenceItem + chain of custody
│       │   └── db_models.py        # SQLAlchemy ORM
│       ├── config/
│       │   ├── __init__.py
│       │   └── schema.py           # Pydantic Settings + TOML
│       └── core/
│           ├── __init__.py
│           ├── scanner.py          # async subprocess wrapper
│           ├── resilience.py       # retry + graduated failure
│           ├── rate_limiter.py     # token bucket per target
│           ├── dns_resolver.py     # DNS pinning
│           ├── scope.py            # scope validation
│           ├── logger.py           # audit logging
│           └── db.py               # SQLite WAL + session factory
└── tests/
    ├── __init__.py
    ├── conftest.py
    ├── unit/
    │   ├── __init__.py
    │   ├── test_finding.py
    │   ├── test_evidence.py
    │   ├── test_config.py
    │   ├── test_scanner.py
    │   ├── test_resilience.py
    │   ├── test_rate_limiter.py
    │   ├── test_dns_resolver.py
    │   ├── test_scope.py
    │   ├── test_logger.py
    │   └── test_db.py
    └── fixtures/
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/vxis/__init__.py`
- Create: `.gitignore`
- Create: `.python-version`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "vxis"
version = "0.1.0"
description = "AI-powered security automation platform"
requires-python = ">=3.12"
dependencies = [
    "pydantic>=2.9,<3",
    "pydantic-settings>=2.7,<3",
    "sqlalchemy>=2.0,<3",
    "aiosqlite>=0.20,<1",
    "typer>=0.15,<1",
    "rich>=13.0,<14",
    "weasyprint>=63,<64",
    "jinja2>=3.1,<4",
    "anthropic>=0.40,<1",
    "dnspython>=2.7,<3",
    "tomli>=2.0,<3; python_version < '3.11'",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0,<9",
    "pytest-asyncio>=0.24,<1",
    "pytest-cov>=6.0,<7",
    "ruff>=0.8,<1",
]

[project.scripts]
vxis = "vxis.cli.main:app"

[tool.hatch.build.targets.wheel]
packages = ["src/vxis"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"

[tool.ruff]
target-version = "py312"
line-length = 100
```

- [ ] **Step 2: Create .gitignore**

```
__pycache__/
*.pyc
.venv/
*.egg-info/
dist/
build/
.ruff_cache/
.pytest_cache/
*.db
*.sqlite
.env
data/
reports/
```

- [ ] **Step 3: Create .python-version**

```
3.12
```

- [ ] **Step 4: Create src/vxis/__init__.py**

```python
"""VXIS — AI-powered security automation platform."""

__version__ = "0.1.0"
```

- [ ] **Step 5: Create empty __init__.py files for all packages**

Create empty `__init__.py` in: `src/vxis/models/`, `src/vxis/config/`, `src/vxis/core/`, `tests/`, `tests/unit/`

- [ ] **Step 6: Install project in dev mode and verify**

Run: `python -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"`
Expected: Successful installation, `python -c "import vxis; print(vxis.__version__)"` outputs `0.1.0`

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml .gitignore .python-version src/ tests/
git commit -m "chore: initialize VXIS project scaffolding"
```

---

### Task 2: Finding Data Model

**Files:**
- Create: `src/vxis/models/finding.py`
- Create: `tests/unit/test_finding.py`

- [ ] **Step 1: Write failing tests for Finding model**

```python
# tests/unit/test_finding.py
import pytest
from vxis.models.finding import (
    Finding, Severity, FindingStatus, CVSSVector, MitreAttack,
    Evidence, Reference,
)


class TestSeverityEnum:
    def test_severity_ordering(self):
        assert Severity.CRITICAL.weight > Severity.HIGH.weight
        assert Severity.HIGH.weight > Severity.MEDIUM.weight

    def test_severity_from_string(self):
        assert Severity("critical") == Severity.CRITICAL


class TestCVSSVector:
    def test_cvss_severity_critical(self):
        cvss = CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            base_score=10.0,
        )
        assert cvss.severity_from_score == Severity.CRITICAL

    def test_cvss_severity_medium(self):
        cvss = CVSSVector(vector_string="CVSS:3.1/AV:N/AC:H/PR:L/UI:R/S:U/C:L/I:L/A:N", base_score=4.6)
        assert cvss.severity_from_score == Severity.MEDIUM


class TestFinding:
    def _make_finding(self, **overrides):
        defaults = dict(
            scan_id="scan-001",
            title="SQL Injection",
            description="SQL injection in login form",
            severity=Severity.CRITICAL,
            target="example.com",
            finding_type="vulnerability",
            source_plugin="nuclei",
        )
        defaults.update(overrides)
        return Finding(**defaults)

    def test_effective_severity_uses_analyst_override(self):
        f = self._make_finding(analyst_severity=Severity.LOW)
        assert f.effective_severity == Severity.LOW

    def test_effective_severity_defaults_to_severity(self):
        f = self._make_finding()
        assert f.effective_severity == Severity.CRITICAL

    def test_dedup_hash_same_for_identical_findings(self):
        f1 = self._make_finding(target="example.com", port=443, cve_ids=["CVE-2021-44228"])
        f2 = self._make_finding(target="example.com", port=443, cve_ids=["CVE-2021-44228"])
        assert f1.dedup_hash == f2.dedup_hash

    def test_dedup_hash_different_for_different_port(self):
        f1 = self._make_finding(port=80)
        f2 = self._make_finding(port=443)
        assert f1.dedup_hash != f2.dedup_hash

    def test_dedup_hash_different_for_different_component(self):
        f1 = self._make_finding(affected_component="/api/login")
        f2 = self._make_finding(affected_component="/api/search")
        assert f1.dedup_hash != f2.dedup_hash

    def test_fuzzy_hash_same_ignoring_component(self):
        f1 = self._make_finding(affected_component="/api/login", cve_ids=["CVE-2021-44228"])
        f2 = self._make_finding(affected_component="/api/search", cve_ids=["CVE-2021-44228"])
        assert f1.fuzzy_hash == f2.fuzzy_hash

    def test_merge_with_combines_evidence(self):
        f1 = self._make_finding(
            evidence=[Evidence(evidence_type="cli_output", title="nmap output", content="port 443 open")]
        )
        f2 = self._make_finding(
            source_plugin="nmap",
            evidence=[Evidence(evidence_type="cli_output", title="nuclei output", content="vuln found")]
        )
        f1.merge_with(f2)
        assert len(f1.evidence) == 2
        assert "nmap" in f1.source_plugins

    def test_merge_keeps_highest_severity(self):
        f1 = self._make_finding(severity=Severity.LOW)
        f2 = self._make_finding(severity=Severity.CRITICAL)
        f1.merge_with(f2)
        assert f1.severity == Severity.CRITICAL
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_finding.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'vxis.models.finding'`

- [ ] **Step 3: Implement Finding model**

```python
# src/vxis/models/finding.py
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFORMATIONAL: 0,
        }[self]


class FindingStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"


class CVSSVector(BaseModel):
    version: str = "3.1"
    vector_string: str
    base_score: float = Field(ge=0.0, le=10.0)

    @computed_field
    @property
    def severity_from_score(self) -> Severity:
        if self.base_score >= 9.0:
            return Severity.CRITICAL
        if self.base_score >= 7.0:
            return Severity.HIGH
        if self.base_score >= 4.0:
            return Severity.MEDIUM
        if self.base_score >= 0.1:
            return Severity.LOW
        return Severity.INFORMATIONAL


class MitreAttack(BaseModel):
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    subtechnique_id: str | None = None


class Evidence(BaseModel):
    evidence_type: str
    title: str
    content: str | None = None
    file_path: str | None = None
    content_type: str | None = None


class Reference(BaseModel):
    title: str
    url: str


class Finding(BaseModel):
    id: str | None = None
    scan_id: str

    title: str
    description: str
    severity: Severity
    status: FindingStatus = FindingStatus.OPEN

    target: str
    affected_component: str | None = None
    port: int | None = None
    protocol: str | None = None

    finding_type: str
    cvss: CVSSVector | None = None
    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    mitre_attack: list[MitreAttack] = Field(default_factory=list)

    source_plugin: str
    source_plugins: list[str] = Field(default_factory=list)
    source_tool_ref: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    evidence: list[Evidence] = Field(default_factory=list)
    remediation: str | None = None
    references: list[Reference] = Field(default_factory=list)

    analyst_severity: Severity | None = None
    analyst_notes: str | None = None

    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_data: dict[str, Any] = Field(default_factory=dict, exclude=True)

    @computed_field
    @property
    def effective_severity(self) -> Severity:
        return self.analyst_severity if self.analyst_severity else self.severity

    @computed_field
    @property
    def dedup_hash(self) -> str:
        components = [
            self.target.lower().strip(),
            str(self.port or ""),
            self.protocol or "",
            self.finding_type,
            "|".join(sorted(self.cve_ids)) if self.cve_ids else self.title.lower().strip(),
            (self.affected_component or "").lower().strip(),
        ]
        raw = "::".join(components)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @computed_field
    @property
    def fuzzy_hash(self) -> str:
        components = [
            self.target.lower().strip(),
            self.finding_type,
            "|".join(sorted(self.cve_ids)) if self.cve_ids else self.title.lower().strip(),
        ]
        raw = "::".join(components)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def merge_with(self, other: Finding) -> None:
        if other.source_plugin not in self.source_plugins:
            self.source_plugins.append(other.source_plugin)
        self.evidence.extend(other.evidence)
        if other.severity.weight > self.severity.weight:
            self.severity = other.severity
        for cve in other.cve_ids:
            if cve not in self.cve_ids:
                self.cve_ids.append(cve)
        for cwe in other.cwe_ids:
            if cwe not in self.cwe_ids:
                self.cwe_ids.append(cwe)
        if other.confidence > self.confidence:
            self.confidence = other.confidence
        self.updated_at = datetime.now(timezone.utc)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/unit/test_finding.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/vxis/models/finding.py tests/unit/test_finding.py
git commit -m "feat: add Finding data model with 2-layer dedup and merge"
```

---

### Task 3: Evidence Model

**Files:**
- Create: `src/vxis/models/evidence.py`
- Create: `tests/unit/test_evidence.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_evidence.py
from vxis.models.evidence import EvidenceItem, create_evidence, transfer_custody, mask_secret


class TestEvidenceItem:
    def test_create_evidence_sets_hash(self):
        ev = create_evidence(b"test content", "cli_output", "nmap", "finding-001")
        assert len(ev.sha256_hash) == 64
        assert ev.evidence_type == "cli_output"
        assert ev.captured_by == "nmap"

    def test_chain_of_custody_initial(self):
        ev = create_evidence(b"data", "http_transaction", "nuclei", "f-001")
        assert len(ev.chain_of_custody) == 1
        assert ev.chain_of_custody[0]["action"] == "captured"

    def test_transfer_custody_appends(self):
        ev = create_evidence(b"data", "cli_output", "nmap", "f-001")
        ev = transfer_custody(ev, "analyzed", "vxis-enricher")
        assert len(ev.chain_of_custody) == 2
        assert ev.chain_of_custody[1]["action"] == "analyzed"


class TestMaskSecret:
    def test_mask_short_secret(self):
        assert mask_secret("abc") == "***"

    def test_mask_long_secret(self):
        result = mask_secret("AKIAIOSFODNN7EXAMPLE")
        assert result.startswith("AKIA")
        assert result.endswith("MPLE")
        assert "*" in result

    def test_mask_preserves_length(self):
        secret = "my_secret_key_123"
        assert len(mask_secret(secret)) == len(secret)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_evidence.py -v`
Expected: FAIL

- [ ] **Step 3: Implement Evidence model**

```python
# src/vxis/models/evidence.py
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


@dataclass
class EvidenceItem:
    evidence_id: str
    finding_id: str
    evidence_type: str
    captured_at: datetime
    captured_by: str
    sha256_hash: str
    content: bytes
    metadata: dict = field(default_factory=dict)
    chain_of_custody: list[dict] = field(default_factory=list)


def create_evidence(
    content: bytes, evidence_type: str, tool: str, finding_id: str
) -> EvidenceItem:
    now = datetime.now(timezone.utc)
    return EvidenceItem(
        evidence_id=str(uuid4()),
        finding_id=finding_id,
        evidence_type=evidence_type,
        captured_at=now,
        captured_by=tool,
        sha256_hash=hashlib.sha256(content).hexdigest(),
        content=content,
        chain_of_custody=[
            {
                "action": "captured",
                "timestamp": now.isoformat(),
                "actor": f"vxis-scanner/{tool}",
            }
        ],
    )


def transfer_custody(
    evidence: EvidenceItem, action: str, actor: str
) -> EvidenceItem:
    evidence.chain_of_custody.append(
        {
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "actor": actor,
            "evidence_hash_at_transfer": evidence.sha256_hash,
        }
    )
    return evidence


def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    visible = 4
    return secret[:visible] + "*" * (len(secret) - visible * 2) + secret[-visible:]
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_evidence.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vxis/models/evidence.py tests/unit/test_evidence.py
git commit -m "feat: add Evidence model with chain of custody and secret masking"
```

---

### Task 4: Config System

**Files:**
- Create: `src/vxis/config/schema.py`
- Create: `config.toml`
- Create: `tests/unit/test_config.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_config.py
import os
import pytest
from pathlib import Path
from vxis.config.schema import VXISConfig, ScanProfile, ToolSettings


class TestScanProfile:
    def test_default_profiles_exist(self):
        config = VXISConfig()
        assert "stealth" in config.profiles
        assert "standard" in config.profiles
        assert "aggressive" in config.profiles
        assert "passive" in config.profiles

    def test_stealth_is_slower(self):
        config = VXISConfig()
        assert config.profiles["stealth"].rate_limit < config.profiles["standard"].rate_limit

    def test_aggressive_max_concurrency(self):
        config = VXISConfig()
        assert config.profiles["aggressive"].max_concurrency >= 8


class TestToolSettings:
    def test_tool_defaults(self):
        ts = ToolSettings()
        assert ts.enabled is True
        assert ts.extra_args == ""

    def test_tool_timeout_override(self):
        ts = ToolSettings(timeout_override=1800)
        assert ts.timeout_override == 1800


class TestVXISConfig:
    def test_default_db_url(self):
        config = VXISConfig()
        assert "sqlite" in config.db_url

    def test_env_var_override(self, monkeypatch):
        monkeypatch.setenv("VXIS_LOG_LEVEL", "DEBUG")
        config = VXISConfig()
        assert config.log_level == "DEBUG"

    def test_secret_fields_are_secret(self):
        config = VXISConfig()
        # SecretStr should not leak in repr
        assert config.shodan_api_key is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_config.py -v`
Expected: FAIL

- [ ] **Step 3: Implement config schema**

```python
# src/vxis/config/schema.py
from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class ToolSettings(BaseModel):
    enabled: bool = True
    extra_args: str = ""
    timeout_override: int | None = None


class ScanProfile(BaseModel):
    name: str
    description: str = ""
    rate_limit: int = 50
    max_concurrency: int = 5
    nmap_timing: int = 3
    nuclei_rate: int = 100
    skip_plugins: list[str] = Field(default_factory=list)
    tool_overrides: dict[str, ToolSettings] = Field(default_factory=dict)


class ClientConfig(BaseModel):
    client_name: str
    targets: list[str]
    exclude_targets: list[str] = Field(default_factory=list)
    exclude_ports: list[int] = Field(default_factory=list)
    scope_notes: str = ""
    report_template: str = "default"
    custom_logo_path: str | None = None


def _default_profiles() -> dict[str, ScanProfile]:
    return {
        "passive": ScanProfile(
            name="passive",
            description="Zero active probing — OSINT and passive DNS only",
            rate_limit=0,
            max_concurrency=4,
            nmap_timing=0,
            nuclei_rate=0,
        ),
        "stealth": ScanProfile(
            name="stealth",
            description="Low and slow — IDS/IPS evasion",
            rate_limit=5,
            max_concurrency=2,
            nmap_timing=1,
            nuclei_rate=10,
        ),
        "standard": ScanProfile(
            name="standard",
            description="Balanced speed and stealth",
            rate_limit=50,
            max_concurrency=5,
            nmap_timing=3,
            nuclei_rate=100,
        ),
        "aggressive": ScanProfile(
            name="aggressive",
            description="Maximum speed, full coverage",
            rate_limit=200,
            max_concurrency=8,
            nmap_timing=4,
            nuclei_rate=500,
        ),
    }


class VXISConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VXIS_",
        env_file=".env",
        env_nested_delimiter="__",
    )

    data_dir: Path = Path("./data")
    db_url: str = "sqlite:///./data/vxis.db"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    shodan_api_key: SecretStr | None = None
    censys_api_id: SecretStr | None = None
    censys_api_secret: SecretStr | None = None
    anthropic_api_key: SecretStr | None = None
    github_token: SecretStr | None = None

    profiles: dict[str, ScanProfile] = Field(default_factory=_default_profiles)
    tools: dict[str, ToolSettings] = Field(default_factory=dict)

    report_output_dir: Path = Path("./reports")
    report_company_name: str = "VXIS Security"
    report_author: str = ""
```

- [ ] **Step 4: Create default config.toml**

```toml
# config.toml — VXIS default configuration
data_dir = "./data"
db_url = "sqlite:///./data/vxis.db"
log_level = "INFO"
report_output_dir = "./reports"
report_company_name = "VXIS Security"
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/unit/test_config.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/vxis/config/ tests/unit/test_config.py config.toml
git commit -m "feat: add config system with TOML + Pydantic Settings + scan profiles"
```

---

### Task 5: Async Subprocess Runner

**Files:**
- Create: `src/vxis/core/scanner.py`
- Create: `tests/unit/test_scanner.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_scanner.py
import pytest
from vxis.core.scanner import run_tool, ToolResult


class TestRunTool:
    @pytest.mark.asyncio
    async def test_successful_command(self):
        result = await run_tool("echo hello")
        assert result.return_code == 0
        assert "hello" in result.stdout

    @pytest.mark.asyncio
    async def test_failed_command(self):
        result = await run_tool("false")
        assert result.return_code != 0

    @pytest.mark.asyncio
    async def test_timeout_kills_process(self):
        with pytest.raises(TimeoutError):
            await run_tool("sleep 10", timeout=1)

    @pytest.mark.asyncio
    async def test_captures_stderr(self):
        result = await run_tool("echo error >&2", shell=True)
        assert "error" in result.stderr

    @pytest.mark.asyncio
    async def test_result_has_elapsed_time(self):
        result = await run_tool("echo fast")
        assert result.elapsed_seconds >= 0
        assert result.elapsed_seconds < 5

    @pytest.mark.asyncio
    async def test_result_has_command(self):
        result = await run_tool("echo test")
        assert "echo" in result.command
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_scanner.py -v`
Expected: FAIL

- [ ] **Step 3: Implement scanner**

```python
# src/vxis/core/scanner.py
from __future__ import annotations

import asyncio
import shlex
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ToolResult:
    stdout: str
    stderr: str
    return_code: int
    command: str
    elapsed_seconds: float


async def run_tool(
    command: str,
    timeout: int = 600,
    shell: bool = False,
    output_file: Path | None = None,
) -> ToolResult:
    start = time.monotonic()

    if shell:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=10 * 1024 * 1024,
        )
    else:
        proc = await asyncio.create_subprocess_exec(
            *shlex.split(command),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=10 * 1024 * 1024,
        )

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"Command timed out after {timeout}s: {command[:100]}")

    elapsed = time.monotonic() - start

    stdout_str = stdout_bytes.decode("utf-8", errors="replace")
    stderr_str = stderr_bytes.decode("utf-8", errors="replace")

    if output_file and stdout_str:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(stdout_str)

    return ToolResult(
        stdout=stdout_str,
        stderr=stderr_str,
        return_code=proc.returncode or -1,
        command=command,
        elapsed_seconds=elapsed,
    )
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_scanner.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vxis/core/scanner.py tests/unit/test_scanner.py
git commit -m "feat: add async subprocess runner with timeout and output capture"
```

---

### Task 6: Resilience (Retry + Graduated Failure)

**Files:**
- Create: `src/vxis/core/resilience.py`
- Create: `tests/unit/test_resilience.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_resilience.py
import pytest
from unittest.mock import AsyncMock
from vxis.core.resilience import (
    RetryConfig, ResilientRunner, ToolResult as TResult,
    ToolExecutionError, ToolTimeoutError, ToolResultLevel,
)


class TestToolResultLevel:
    def test_success(self):
        assert ToolResultLevel.SUCCESS.should_continue is True

    def test_partial(self):
        assert ToolResultLevel.PARTIAL.should_continue is True

    def test_failed(self):
        assert ToolResultLevel.FAILED.should_continue is False


class TestRetryConfig:
    def test_defaults(self):
        rc = RetryConfig()
        assert rc.max_retries == 2
        assert rc.backoff_base == 5.0

    def test_is_retryable(self):
        rc = RetryConfig()
        assert rc.is_retryable(137) is True
        assert rc.is_retryable(0) is False


class TestResilientRunner:
    @pytest.mark.asyncio
    async def test_success_on_first_try(self):
        runner = ResilientRunner()
        mock_func = AsyncMock(return_value="result")
        result = await runner.run_with_retry(mock_func, max_retries=2)
        assert result == "result"
        assert mock_func.call_count == 1

    @pytest.mark.asyncio
    async def test_retries_on_failure(self):
        runner = ResilientRunner(RetryConfig(max_retries=2, backoff_base=0.01))
        mock_func = AsyncMock(side_effect=[RuntimeError("fail"), RuntimeError("fail"), "success"])
        result = await runner.run_with_retry(mock_func, max_retries=2)
        assert result == "success"
        assert mock_func.call_count == 3

    @pytest.mark.asyncio
    async def test_raises_after_max_retries(self):
        runner = ResilientRunner(RetryConfig(max_retries=1, backoff_base=0.01))
        mock_func = AsyncMock(side_effect=RuntimeError("always fails"))
        with pytest.raises(ToolExecutionError):
            await runner.run_with_retry(mock_func, max_retries=1)


class TestClassifyResult:
    def test_success(self):
        from vxis.core.resilience import classify_result
        assert classify_result(0, "output") == ToolResultLevel.SUCCESS

    def test_partial_with_output(self):
        from vxis.core.resilience import classify_result
        assert classify_result(1, "some output") == ToolResultLevel.PARTIAL

    def test_failed_no_output(self):
        from vxis.core.resilience import classify_result
        assert classify_result(1, "") == ToolResultLevel.FAILED
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_resilience.py -v`
Expected: FAIL

- [ ] **Step 3: Implement resilience**

```python
# src/vxis/core/resilience.py
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ToolResultLevel(Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    DEGRADED = "degraded"
    FAILED = "failed"

    @property
    def should_continue(self) -> bool:
        return self in (ToolResultLevel.SUCCESS, ToolResultLevel.PARTIAL, ToolResultLevel.DEGRADED)


@dataclass
class RetryConfig:
    max_retries: int = 2
    backoff_base: float = 5.0
    backoff_multiplier: float = 2.0
    retryable_exit_codes: tuple[int, ...] = (1, 137)

    def is_retryable(self, exit_code: int) -> bool:
        return exit_code in self.retryable_exit_codes


def classify_result(return_code: int, stdout: str) -> ToolResultLevel:
    if return_code == 0:
        return ToolResultLevel.SUCCESS
    if stdout.strip():
        return ToolResultLevel.PARTIAL
    return ToolResultLevel.FAILED


class ToolExecutionError(Exception):
    def __init__(self, message: str, exit_code: int = -1, stderr: str = ""):
        self.exit_code = exit_code
        self.stderr = stderr
        super().__init__(message)


class ToolTimeoutError(Exception):
    def __init__(self, tool_name: str, timeout: int):
        self.tool_name = tool_name
        self.timeout = timeout
        super().__init__(f"{tool_name} timed out after {timeout}s")


class ResilientRunner:
    def __init__(self, config: RetryConfig | None = None):
        self.config = config or RetryConfig()

    async def run_with_retry(self, func, max_retries: int | None = None):
        retries = max_retries if max_retries is not None else self.config.max_retries
        last_error: Exception | None = None

        for attempt in range(retries + 1):
            try:
                return await func()
            except Exception as e:
                last_error = e
                if attempt < retries:
                    wait = self.config.backoff_base * (self.config.backoff_multiplier ** attempt)
                    logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {wait:.1f}s")
                    await asyncio.sleep(wait)

        raise ToolExecutionError(
            f"Failed after {retries + 1} attempts: {last_error}",
            exit_code=-1,
            stderr=str(last_error),
        )
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_resilience.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vxis/core/resilience.py tests/unit/test_resilience.py
git commit -m "feat: add resilience layer with retry, backoff, and graduated failure"
```

---

### Task 7: Rate Limiter

**Files:**
- Create: `src/vxis/core/rate_limiter.py`
- Create: `tests/unit/test_rate_limiter.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_rate_limiter.py
import pytest
import asyncio
import time
from vxis.core.rate_limiter import TokenBucketRateLimiter


class TestTokenBucketRateLimiter:
    @pytest.mark.asyncio
    async def test_allows_within_rate(self):
        limiter = TokenBucketRateLimiter(rate=100, capacity=100)
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 1.0

    @pytest.mark.asyncio
    async def test_throttles_over_rate(self):
        limiter = TokenBucketRateLimiter(rate=10, capacity=1)
        start = time.monotonic()
        for _ in range(3):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed >= 0.15  # At least 2 waits of ~0.1s

    @pytest.mark.asyncio
    async def test_zero_rate_never_blocks(self):
        limiter = TokenBucketRateLimiter(rate=0, capacity=0)
        await limiter.acquire()  # Should not block

    @pytest.mark.asyncio
    async def test_per_target_isolation(self):
        from vxis.core.rate_limiter import GlobalRateLimiter
        global_limiter = GlobalRateLimiter(default_rate=10)
        l1 = global_limiter.get_limiter("target1.com")
        l2 = global_limiter.get_limiter("target2.com")
        assert l1 is not l2
        # Same target returns same limiter
        assert global_limiter.get_limiter("target1.com") is l1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_rate_limiter.py -v`
Expected: FAIL

- [ ] **Step 3: Implement rate limiter**

```python
# src/vxis/core/rate_limiter.py
from __future__ import annotations

import asyncio
import time


class TokenBucketRateLimiter:
    def __init__(self, rate: float, capacity: float | None = None):
        self.rate = rate
        self.capacity = capacity if capacity is not None else max(rate, 1)
        self.tokens = self.capacity
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0) -> None:
        if self.rate <= 0:
            return

        async with self._lock:
            self._refill()
            while self.tokens < tokens:
                wait_time = (tokens - self.tokens) / self.rate
                await asyncio.sleep(wait_time)
                self._refill()
            self.tokens -= tokens

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.last_refill = now


class GlobalRateLimiter:
    def __init__(self, default_rate: float = 50):
        self.default_rate = default_rate
        self._limiters: dict[str, TokenBucketRateLimiter] = {}

    def get_limiter(self, target: str) -> TokenBucketRateLimiter:
        if target not in self._limiters:
            self._limiters[target] = TokenBucketRateLimiter(
                rate=self.default_rate, capacity=self.default_rate
            )
        return self._limiters[target]

    def set_rate(self, target: str, rate: float) -> None:
        limiter = self.get_limiter(target)
        limiter.rate = rate
        limiter.capacity = max(rate, 1)
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_rate_limiter.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vxis/core/rate_limiter.py tests/unit/test_rate_limiter.py
git commit -m "feat: add token bucket rate limiter with per-target isolation"
```

---

### Task 8: DNS Resolver (Pinning)

**Files:**
- Create: `src/vxis/core/dns_resolver.py`
- Create: `tests/unit/test_dns_resolver.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_dns_resolver.py
import pytest
from vxis.core.dns_resolver import DNSPinningResolver


class TestDNSPinningResolver:
    @pytest.mark.asyncio
    async def test_resolve_returns_ips(self):
        resolver = DNSPinningResolver()
        ips = await resolver.resolve("google.com")
        assert len(ips) > 0
        assert all(isinstance(ip, str) for ip in ips)

    @pytest.mark.asyncio
    async def test_pinning_returns_same_result(self):
        resolver = DNSPinningResolver()
        ips1 = await resolver.resolve("google.com")
        ips2 = await resolver.resolve("google.com")
        assert ips1 == ips2  # Pinned — same session, same result

    def test_canonical_target_for_domain(self):
        resolver = DNSPinningResolver()
        resolver._cache["example.com"] = ["93.184.216.34"]
        assert resolver.get_canonical_target("example.com") == "93.184.216.34"

    def test_canonical_target_for_ip(self):
        resolver = DNSPinningResolver()
        assert resolver.get_canonical_target("93.184.216.34") == "93.184.216.34"

    @pytest.mark.asyncio
    async def test_resolve_invalid_domain(self):
        resolver = DNSPinningResolver()
        ips = await resolver.resolve("this-domain-does-not-exist-xyz123.com")
        assert ips == []

    def test_is_ip_address(self):
        resolver = DNSPinningResolver()
        assert resolver._is_ip("192.168.1.1") is True
        assert resolver._is_ip("example.com") is False
        assert resolver._is_ip("2001:db8::1") is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_dns_resolver.py -v`
Expected: FAIL

- [ ] **Step 3: Implement DNS resolver**

```python
# src/vxis/core/dns_resolver.py
from __future__ import annotations

import ipaddress
import logging
from dns import resolver as dns_resolver
from dns.exception import DNSException

logger = logging.getLogger(__name__)


class DNSPinningResolver:
    def __init__(self, nameservers: list[str] | None = None):
        self._cache: dict[str, list[str]] = {}
        self._resolver = dns_resolver.Resolver()
        if nameservers:
            self._resolver.nameservers = nameservers
        self._resolver.timeout = 10
        self._resolver.lifetime = 30

    async def resolve(self, hostname: str) -> list[str]:
        if self._is_ip(hostname):
            return [hostname]

        if hostname in self._cache:
            return self._cache[hostname]

        ips: list[str] = []
        try:
            answers = self._resolver.resolve(hostname, "A")
            ips = [str(rdata) for rdata in answers]
        except DNSException:
            logger.warning(f"DNS resolution failed for {hostname}")
        except Exception as e:
            logger.error(f"Unexpected DNS error for {hostname}: {e}")

        self._cache[hostname] = ips
        return ips

    async def resolve_many(self, hostnames: list[str]) -> dict[str, list[str]]:
        results = {}
        for hostname in hostnames:
            results[hostname] = await self.resolve(hostname)
        return results

    def get_canonical_target(self, target: str) -> str:
        if self._is_ip(target):
            return target
        ips = self._cache.get(target, [])
        return ips[0] if ips else target

    def get_pinned_results(self) -> dict[str, list[str]]:
        return dict(self._cache)

    @staticmethod
    def _is_ip(value: str) -> bool:
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_dns_resolver.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vxis/core/dns_resolver.py tests/unit/test_dns_resolver.py
git commit -m "feat: add DNS pinning resolver for session-consistent target resolution"
```

---

### Task 9: Scope Validator

**Files:**
- Create: `src/vxis/core/scope.py`
- Create: `tests/unit/test_scope.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_scope.py
import pytest
from vxis.core.scope import ScopeValidator, ScopeViolationError


class TestScopeValidator:
    def test_domain_in_scope(self):
        sv = ScopeValidator(targets=["example.com"], exclude_targets=[])
        assert sv.is_in_scope("example.com") is True

    def test_subdomain_in_scope(self):
        sv = ScopeValidator(targets=["example.com"], exclude_targets=[])
        assert sv.is_in_scope("api.example.com") is True

    def test_unrelated_domain_out_of_scope(self):
        sv = ScopeValidator(targets=["example.com"], exclude_targets=[])
        assert sv.is_in_scope("evil.com") is False

    def test_excluded_domain(self):
        sv = ScopeValidator(targets=["example.com"], exclude_targets=["mail.example.com"])
        assert sv.is_in_scope("mail.example.com") is False
        assert sv.is_in_scope("api.example.com") is True

    def test_ip_in_cidr_scope(self):
        sv = ScopeValidator(targets=["192.168.1.0/24"], exclude_targets=[])
        assert sv.is_in_scope("192.168.1.50") is True
        assert sv.is_in_scope("10.0.0.1") is False

    def test_validate_raises_on_violation(self):
        sv = ScopeValidator(targets=["example.com"], exclude_targets=[])
        with pytest.raises(ScopeViolationError):
            sv.validate("evil.com")

    def test_validate_passes_for_in_scope(self):
        sv = ScopeValidator(targets=["example.com"], exclude_targets=[])
        sv.validate("api.example.com")  # Should not raise

    def test_wildcard_target(self):
        sv = ScopeValidator(targets=["*.example.com"], exclude_targets=[])
        assert sv.is_in_scope("api.example.com") is True
        assert sv.is_in_scope("example.com") is True

    def test_excluded_port(self):
        sv = ScopeValidator(targets=["example.com"], exclude_targets=[], exclude_ports=[22])
        assert sv.is_port_allowed(80) is True
        assert sv.is_port_allowed(22) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_scope.py -v`
Expected: FAIL

- [ ] **Step 3: Implement scope validator**

```python
# src/vxis/core/scope.py
from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger(__name__)


class ScopeViolationError(Exception):
    def __init__(self, target: str, scope_targets: list[str]):
        self.target = target
        super().__init__(
            f"SCOPE VIOLATION: '{target}' is not in authorized scope {scope_targets}"
        )


class ScopeValidator:
    def __init__(
        self,
        targets: list[str],
        exclude_targets: list[str],
        exclude_ports: list[int] | None = None,
    ):
        self.targets = targets
        self.exclude_targets = exclude_targets
        self.exclude_ports = set(exclude_ports or [])
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._domains: list[str] = []

        for t in targets:
            try:
                self._networks.append(ipaddress.ip_network(t, strict=False))
            except ValueError:
                self._domains.append(t.lstrip("*.").lower())

    def is_in_scope(self, target: str) -> bool:
        target_lower = target.lower().strip()

        # Check exclusions first
        for excl in self.exclude_targets:
            if target_lower == excl.lower() or target_lower.endswith("." + excl.lower()):
                return False

        # Check IP ranges
        try:
            ip = ipaddress.ip_address(target)
            return any(ip in net for net in self._networks)
        except ValueError:
            pass

        # Check domains
        for domain in self._domains:
            if target_lower == domain or target_lower.endswith("." + domain):
                return True

        return False

    def validate(self, target: str) -> None:
        if not self.is_in_scope(target):
            raise ScopeViolationError(target, self.targets)

    def is_port_allowed(self, port: int) -> bool:
        return port not in self.exclude_ports
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_scope.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vxis/core/scope.py tests/unit/test_scope.py
git commit -m "feat: add scope validator with domain/CIDR/exclusion support"
```

---

### Task 10: Audit Logger

**Files:**
- Create: `src/vxis/core/logger.py`
- Create: `tests/unit/test_logger.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_logger.py
import json
import pytest
from pathlib import Path
from vxis.core.logger import AuditLogger


class TestAuditLogger:
    def test_log_tool_run(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file)
        logger.log_tool_run(
            scan_id="scan-001",
            plugin_name="nmap",
            target="example.com",
            command="nmap -sV example.com",
        )
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["event"] == "tool_run"
        assert record["plugin_name"] == "nmap"
        assert "timestamp" in record

    def test_log_scope_check(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file)
        logger.log_scope_check("scan-001", "example.com", True)
        record = json.loads(log_file.read_text().strip())
        assert record["event"] == "scope_check"
        assert record["in_scope"] is True

    def test_append_mode(self, tmp_path):
        log_file = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_file)
        logger.log_tool_run("s1", "nmap", "t1", "cmd1")
        logger.log_tool_run("s1", "nuclei", "t1", "cmd2")
        lines = log_file.read_text().strip().splitlines()
        assert len(lines) == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_logger.py -v`
Expected: FAIL

- [ ] **Step 3: Implement audit logger**

```python
# src/vxis/core/logger.py
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    def __init__(self, log_path: Path):
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _write(self, record: dict) -> None:
        record["timestamp"] = datetime.now(timezone.utc).isoformat()
        with open(self.log_path, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")

    def log_tool_run(
        self,
        scan_id: str,
        plugin_name: str,
        target: str,
        command: str,
        exit_code: int | None = None,
        elapsed_seconds: float | None = None,
    ) -> None:
        self._write({
            "event": "tool_run",
            "scan_id": scan_id,
            "plugin_name": plugin_name,
            "target": target,
            "command": command,
            "exit_code": exit_code,
            "elapsed_seconds": elapsed_seconds,
        })

    def log_scope_check(self, scan_id: str, target: str, in_scope: bool) -> None:
        self._write({
            "event": "scope_check",
            "scan_id": scan_id,
            "target": target,
            "in_scope": in_scope,
        })

    def log_scan_start(self, scan_id: str, target: str, profile: str, config_snapshot: dict) -> None:
        self._write({
            "event": "scan_start",
            "scan_id": scan_id,
            "target": target,
            "profile": profile,
            "config_snapshot": config_snapshot,
        })

    def log_scan_end(self, scan_id: str, finding_count: int, status: str) -> None:
        self._write({
            "event": "scan_end",
            "scan_id": scan_id,
            "finding_count": finding_count,
            "status": status,
        })
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_logger.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/vxis/core/logger.py tests/unit/test_logger.py
git commit -m "feat: add tamper-evident JSONL audit logger"
```

---

### Task 11: Database Layer

**Files:**
- Create: `src/vxis/models/db_models.py`
- Create: `src/vxis/core/db.py`
- Create: `tests/unit/test_db.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_db.py
import pytest
from vxis.core.db import create_engine, get_session, init_db
from vxis.models.db_models import Base, ScanRecord, FindingRecord, ToolRunRecord


class TestDatabase:
    @pytest.mark.asyncio
    async def test_create_tables(self, tmp_path):
        db_url = f"sqlite+aiosqlite:///{tmp_path}/test.db"
        engine = create_engine(db_url)
        await init_db(engine)
        # Tables should exist without error

    @pytest.mark.asyncio
    async def test_insert_scan(self, tmp_path):
        db_url = f"sqlite+aiosqlite:///{tmp_path}/test.db"
        engine = create_engine(db_url)
        await init_db(engine)

        async with get_session(engine) as session:
            scan = ScanRecord(
                id="scan-001",
                target="example.com",
                profile="standard",
                status="running",
            )
            session.add(scan)
            await session.commit()

            result = await session.get(ScanRecord, "scan-001")
            assert result is not None
            assert result.target == "example.com"

    @pytest.mark.asyncio
    async def test_insert_finding(self, tmp_path):
        db_url = f"sqlite+aiosqlite:///{tmp_path}/test.db"
        engine = create_engine(db_url)
        await init_db(engine)

        async with get_session(engine) as session:
            scan = ScanRecord(id="s1", target="t", profile="standard", status="done")
            session.add(scan)
            finding = FindingRecord(
                id="f1",
                scan_id="s1",
                dedup_hash="abc123",
                title="SQL Injection",
                severity="critical",
                effective_severity="critical",
                finding_type="vulnerability",
                target="example.com",
                source_plugin="nuclei",
            )
            session.add(finding)
            await session.commit()

            result = await session.get(FindingRecord, "f1")
            assert result is not None
            assert result.title == "SQL Injection"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/unit/test_db.py -v`
Expected: FAIL

- [ ] **Step 3: Implement DB models**

```python
# src/vxis/models/db_models.py
from sqlalchemy import (
    Column, String, Integer, Float, Text, DateTime, JSON,
    ForeignKey, Index, func,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"
    id = Column(String(36), primary_key=True)
    target = Column(String(512), nullable=False, index=True)
    profile = Column(String(50), nullable=False, default="standard")
    status = Column(String(20), nullable=False, default="pending")
    started_at = Column(DateTime, server_default=func.now())
    finished_at = Column(DateTime, nullable=True)
    config_snapshot = Column(JSON, nullable=True)
    findings = relationship("FindingRecord", back_populates="scan")
    tool_runs = relationship("ToolRunRecord", back_populates="scan")


class FindingRecord(Base):
    __tablename__ = "findings"
    id = Column(String(36), primary_key=True)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    dedup_hash = Column(String(16), nullable=False, index=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, index=True)
    effective_severity = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False, default="open")
    finding_type = Column(String(50), nullable=False)
    target = Column(String(512), nullable=False)
    port = Column(Integer, nullable=True)
    protocol = Column(String(10), nullable=True)
    affected_component = Column(String(512), nullable=True)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(256), nullable=True)
    cve_ids = Column(JSON, default=list)
    cwe_ids = Column(JSON, default=list)
    source_plugin = Column(String(100), nullable=False)
    source_plugins = Column(JSON, default=list)
    confidence = Column(Float, default=0.5)
    remediation = Column(Text, nullable=True)
    evidence = Column(JSON, default=list)
    references = Column(JSON, default=list)
    mitre_attack = Column(JSON, default=list)
    analyst_severity = Column(String(20), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    raw_data = Column(JSON, default=dict)
    discovered_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())
    scan = relationship("ScanRecord", back_populates="findings")
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_target_dedup", "target", "dedup_hash"),
    )


class ToolRunRecord(Base):
    __tablename__ = "tool_runs"
    id = Column(String(36), primary_key=True)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    plugin_name = Column(String(100), nullable=False)
    command = Column(Text, nullable=False)
    return_code = Column(Integer, nullable=True)
    stdout_path = Column(String(512), nullable=True)
    stderr_snippet = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    elapsed_seconds = Column(Float, nullable=True)
    state = Column(String(20), nullable=False)
    scan = relationship("ScanRecord", back_populates="tool_runs")
```

- [ ] **Step 4: Implement DB engine and session**

```python
# src/vxis/core/db.py
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine,
)
from sqlalchemy import event

from vxis.models.db_models import Base


def create_engine(db_url: str) -> AsyncEngine:
    engine = create_async_engine(db_url, pool_size=1, max_overflow=0)

    @event.listens_for(engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_conn, connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA cache_size=-64000")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()

    return engine


async def init_db(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@asynccontextmanager
async def get_session(engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
```

- [ ] **Step 5: Run tests**

Run: `pytest tests/unit/test_db.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/vxis/models/db_models.py src/vxis/core/db.py tests/unit/test_db.py
git commit -m "feat: add SQLAlchemy async DB layer with SQLite WAL mode"
```

---

### Task 12: Run Full Test Suite and Verify Foundation

- [ ] **Step 1: Run all tests**

Run: `pytest tests/ -v --tb=short`
Expected: All tests PASS (should be ~30+ tests across 8 test files)

- [ ] **Step 2: Run ruff linter**

Run: `ruff check src/ tests/`
Expected: No errors

- [ ] **Step 3: Commit and push**

```bash
git add -A
git commit -m "chore: foundation layer complete — models, config, core infrastructure"
git push -u origin main
```

---

## Summary

| Task | Component | Test Count (approx) |
|------|-----------|-------------------|
| 1 | Project scaffolding | 0 |
| 2 | Finding model | 9 |
| 3 | Evidence model | 5 |
| 4 | Config system | 6 |
| 5 | Subprocess runner | 6 |
| 6 | Resilience | 6 |
| 7 | Rate limiter | 4 |
| 8 | DNS resolver | 6 |
| 9 | Scope validator | 8 |
| 10 | Audit logger | 3 |
| 11 | Database layer | 3 |
| 12 | Full verification | 0 |
| **Total** | **12 tasks** | **~56 tests** |

**Next plan:** `2026-03-20-vxis-phase0-engine-plugins.md` (DAG executor + 8 plugins + normalizer + FP pipeline + enricher)
