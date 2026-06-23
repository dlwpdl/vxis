"""Shared helpers for the VXIS Typer entrypoint."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

console = Console()

_BANNER = r"""
__     __ __  __ ___  ____
\ \   / / \ \/ /|_ _|/ ___|
 \ \ / /   \  /  | | \___ \
  \ V /    /  \ _| |_ ___) |
   \_/    /_/\_\_____|____/
"""


def _print_banner() -> None:
    """Render the VXIS ASCII banner using Rich."""
    console.print(
        Panel(
            Text(_BANNER.strip(), style="bold cyan", justify="center"),
            subtitle="[dim]AI-powered security automation platform[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


def _load_scan_instructions(
    instruction: str | None,
    instruction_file: Path | None,
) -> str:
    """Load operator scan instructions from inline text and/or a file."""
    parts: list[str] = []
    if instruction and instruction.strip():
        parts.append(instruction.strip())
    if instruction_file is not None:
        path = instruction_file.expanduser()
        if not path.exists():
            raise FileNotFoundError(str(path))
        if not path.is_file():
            raise IsADirectoryError(str(path))
        content = path.read_text(encoding="utf-8").strip()
        if content:
            parts.append(content)
    return "\n\n".join(parts)


def _get_config():
    """Load and return the default VXISConfig."""
    from vxis.config.schema import VXISConfig

    return VXISConfig()


def _convert_finding_records(records) -> list:
    """Convert FindingRecord ORM rows to Pydantic Finding models."""
    from vxis.models.finding import (
        CVSSVector,
        Evidence,
        Finding,
        FindingStatus,
        MitreAttack,
        Reference,
        Severity,
    )

    findings: list[Finding] = []
    for rec in records:
        cvss = None
        if rec.cvss_score is not None and rec.cvss_vector:
            cvss = CVSSVector(vector_string=rec.cvss_vector, base_score=rec.cvss_score)

        mitre = None
        if rec.mitre_attack:
            mitre = MitreAttack(**rec.mitre_attack)

        evidence = [Evidence(**e) for e in (rec.evidence or [])]
        references = [Reference(**r) for r in (rec.references or [])]
        raw_data = rec.raw_data if isinstance(rec.raw_data, dict) else {}
        primary_evidence = evidence[0].content if evidence else None

        findings.append(
            Finding(
                id=str(rec.id),
                scan_id=str(rec.scan_id),
                title=rec.title,
                description=rec.description,
                impact=raw_data.get("impact"),
                technical_analysis=raw_data.get("technical_analysis"),
                poc_description=raw_data.get("poc_description"),
                poc_script_code=raw_data.get("poc_script_code") or primary_evidence,
                replay_command=raw_data.get("replay_command"),
                severity=Severity(rec.severity),
                status=FindingStatus(rec.status),
                target=rec.target,
                affected_component=rec.affected_component or "",
                port=rec.port,
                protocol=rec.protocol,
                finding_type=rec.finding_type,
                cvss=cvss,
                cve_ids=rec.cve_ids or [],
                cwe_ids=rec.cwe_ids or [],
                mitre_attack=mitre,
                source_plugin=rec.source_plugin,
                source_plugins=rec.source_plugins or [],
                confidence=rec.confidence,
                evidence=evidence,
                remediation=rec.remediation,
                references=references,
                analyst_severity=Severity(rec.analyst_severity)
                if rec.analyst_severity
                else None,
                analyst_notes=rec.analyst_notes,
                discovered_at=rec.discovered_at,
                updated_at=rec.updated_at,
                raw_data=raw_data or None,
            )
        )
    return findings
