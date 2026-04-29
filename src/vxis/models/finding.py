"""Finding data model for VXIS security automation platform.

This module defines the core data structures for representing security findings,
including severity classification, CVSS scoring, MITRE ATT&CK mappings,
evidence attachments, and deduplication logic.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, computed_field, field_validator, model_serializer

from vxis.interaction.surface import TargetKind


class Severity(str, Enum):
    """Security finding severity levels with numeric weights for comparison."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    informational = "informational"

    @property
    def weight(self) -> int:
        """Numeric weight for severity comparison. Higher = more severe."""
        _weights: dict[str, int] = {
            "critical": 4,
            "high": 3,
            "medium": 2,
            "low": 1,
            "informational": 0,
        }
        return _weights[self.value]

    def __lt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight < other.weight

    def __le__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight <= other.weight

    def __gt__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight > other.weight

    def __ge__(self, other: "Severity") -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.weight >= other.weight


class FindingStatus(str, Enum):
    """Lifecycle status of a security finding."""

    open = "open"
    confirmed = "confirmed"
    false_positive = "false_positive"
    accepted_risk = "accepted_risk"
    remediated = "remediated"


class CVSSVector(BaseModel):
    """CVSS (Common Vulnerability Scoring System) vector and score."""

    vector_string: str = Field(
        description="CVSS vector string, e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    base_score: float = Field(ge=0.0, le=10.0, description="CVSS base score between 0.0 and 10.0")

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_from_score(self) -> Severity:
        """Derive severity from CVSS base score using standard CVSS v3 thresholds."""
        score = self.base_score
        if score == 0.0:
            return Severity.informational
        elif score < 4.0:
            return Severity.low
        elif score < 7.0:
            return Severity.medium
        elif score < 9.0:
            return Severity.high
        else:
            return Severity.critical


class MitreAttack(BaseModel):
    """MITRE ATT&CK framework classification for a finding."""

    tactic_id: str = Field(description="Tactic ID, e.g. TA0001")
    tactic_name: str = Field(description="Tactic name, e.g. Initial Access")
    technique_id: str = Field(description="Technique ID, e.g. T1190")
    technique_name: str = Field(description="Technique name, e.g. Exploit Public-Facing Application")
    subtechnique_id: str | None = Field(
        default=None, description="Sub-technique ID, e.g. T1190.001"
    )


class Evidence(BaseModel):
    """Evidence artifact attached to a finding."""

    evidence_type: str = Field(description="Type of evidence, e.g. screenshot, log, packet_capture")
    title: str = Field(description="Human-readable title for the evidence artifact")
    content: str = Field(description="Evidence content or description")
    file_path: str | None = Field(default=None, description="Path to the evidence file if stored on disk")
    content_type: str = Field(default="text/plain", description="MIME type of the evidence content")
    # phase-G: which Surface produced this evidence (web/desktop/mobile/game).
    # Default WEB for back-compat — pre-existing evidence/reports validate unchanged;
    # cross-surface synthesis decorates chains that span >1 distinct surface.
    surface: TargetKind = Field(
        default=TargetKind.WEB,
        description="Surface kind that produced this evidence (web/desktop/mobile/game)",
    )


class Reference(BaseModel):
    """External reference or advisory linked to a finding."""

    title: str = Field(description="Reference title or advisory name")
    url: str = Field(description="URL to the reference resource")


class Finding(BaseModel):
    """Core security finding model for VXIS.

    Represents a single security issue discovered during a scan. Includes
    full metadata for deduplication, analyst workflow, and reporting.
    """

    # --- Identity ---
    id: str = Field(description="Unique finding identifier")
    scan_id: str = Field(description="Identifier of the scan that produced this finding")

    # --- Description ---
    title: str = Field(description="Short, human-readable title of the finding")
    description: str = Field(description="Detailed description of the finding")

    # --- Classification ---
    severity: Severity = Field(description="Scanner-assessed severity level")
    status: FindingStatus = Field(default=FindingStatus.open, description="Current lifecycle status")

    # --- Target ---
    target: str = Field(description="Target host, URL, or asset identifier")
    affected_component: str = Field(
        default="", description="Specific component or service affected within the target"
    )
    port: int | None = Field(default=None, ge=1, le=65535, description="TCP/UDP port number if applicable")
    protocol: str | None = Field(default=None, description="Network protocol, e.g. tcp, udp, http")

    # --- Finding Classification ---
    finding_type: str = Field(description="Category or type of finding, e.g. sqli, xss, misconfig")
    cvss: CVSSVector | None = Field(default=None, description="CVSS vector and score")
    cve_ids: list[str] = Field(default_factory=list, description="Associated CVE identifiers")
    cwe_ids: list[str] = Field(default_factory=list, description="Associated CWE identifiers")
    mitre_attack: MitreAttack | None = Field(default=None, description="MITRE ATT&CK classification")

    # --- Source ---
    source_plugin: str = Field(description="Primary plugin that discovered this finding")
    source_plugins: list[str] = Field(
        default_factory=list,
        description="All plugins that have contributed to this finding (populated on merge)",
    )
    source_tool_ref: str | None = Field(
        default=None, description="Reference ID from the source tool's native output"
    )
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Scanner confidence score between 0.0 (low) and 1.0 (high)",
    )

    # --- Evidence & Remediation ---
    evidence: list[Evidence] = Field(default_factory=list, description="Attached evidence artifacts")
    remediation: str | None = Field(default=None, description="Recommended remediation steps")
    references: list[Reference] = Field(default_factory=list, description="External references")

    # --- Analyst Workflow ---
    analyst_severity: Severity | None = Field(
        default=None, description="Analyst-overridden severity (takes precedence over scanner severity)"
    )
    analyst_notes: str | None = Field(default=None, description="Analyst comments or notes")

    # --- Timestamps ---
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the finding was first discovered",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the last update to this finding",
    )

    # --- Raw Data ---
    raw_data: dict[str, Any] | None = Field(
        default=None,
        exclude=True,  # excluded from serialization to avoid leaking verbose tool output
        description="Raw output from the source tool; excluded from model serialization",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_severity(self) -> Severity:
        """Return analyst-overridden severity if set, otherwise scanner severity."""
        return self.analyst_severity if self.analyst_severity is not None else self.severity

    @computed_field  # type: ignore[prop-decorator]
    @property
    def dedup_hash(self) -> str:
        """16-character SHA-256 prefix for exact deduplication.

        Hash inputs: target + port + protocol + finding_type + first CVE + affected_component.
        Two findings with identical values on all these fields represent the same issue.
        """
        primary_cve = self.cve_ids[0] if self.cve_ids else ""
        port_str = str(self.port) if self.port is not None else ""
        protocol_str = self.protocol or ""

        raw = "|".join([
            self.target,
            port_str,
            protocol_str,
            self.finding_type,
            primary_cve,
            self.affected_component,
        ])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fuzzy_hash(self) -> str:
        """16-character SHA-256 prefix for fuzzy/near-duplicate deduplication.

        Hash inputs: target + finding_type + first CVE.
        Intentionally omits affected_component and port so that the same
        vulnerability on different components of the same host clusters together.
        """
        primary_cve = self.cve_ids[0] if self.cve_ids else ""
        raw = "|".join([self.target, self.finding_type, primary_cve])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def merge_with(self, other: "Finding") -> None:
        """Merge another finding into this one in-place.

        Merging rules:
        - Evidence: combine both lists (no deduplication on content).
        - Severity: keep the higher of the two scanner severities.
        - source_plugins: union of both plugin sets, preserving order.
        - cve_ids: union of both CVE sets, preserving order.
        - updated_at: set to now.
        """
        # Combine evidence lists
        self.evidence = self.evidence + other.evidence

        # Keep the higher severity
        if other.severity.weight > self.severity.weight:
            self.severity = other.severity

        # Union of source plugins (preserve insertion order)
        existing_plugins = set(self.source_plugins)
        if self.source_plugin not in existing_plugins:
            self.source_plugins = [self.source_plugin] + self.source_plugins
            existing_plugins.add(self.source_plugin)

        for plugin in [other.source_plugin] + other.source_plugins:
            if plugin not in existing_plugins:
                self.source_plugins.append(plugin)
                existing_plugins.add(plugin)

        # Union of CVE IDs
        existing_cves = set(self.cve_ids)
        for cve in other.cve_ids:
            if cve not in existing_cves:
                self.cve_ids.append(cve)
                existing_cves.add(cve)

        # Update timestamp
        self.updated_at = datetime.now(timezone.utc)
