"""SQLAlchemy ORM models for VXIS security automation platform.

Defines the persistent data model used by the async SQLite (or PostgreSQL)
backend.  All tables are managed through SQLAlchemy's DeclarativeBase so
that schema migrations and introspection work uniformly.

Table overview:
    scan_records    — one row per scan session
    finding_records — one row per deduplicated security finding
    tool_run_records — one row per external tool invocation
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import JSON


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    """Shared declarative base for all VXIS ORM models."""


class ScanRecord(Base):
    """Persistent representation of a single scan session.

    Attributes:
        id: Auto-incrementing primary key.
        target: Primary scan target (IP, CIDR range, or hostname).
        profile: Scan profile name used for this session.
        status: Lifecycle status ('pending', 'running', 'completed', 'failed').
        started_at: UTC timestamp when the scan started.
        finished_at: UTC timestamp when the scan ended (nullable).
        config_snapshot: JSON snapshot of the effective configuration.
        findings: Related FindingRecord rows (lazy-loaded).
        tool_runs: Related ToolRunRecord rows (lazy-loaded).
    """

    __tablename__ = "scan_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    profile: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="pending")
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    config_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Relationships
    findings: Mapped[list["FindingRecord"]] = relationship(
        "FindingRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )
    tool_runs: Mapped[list["ToolRunRecord"]] = relationship(
        "ToolRunRecord",
        back_populates="scan",
        cascade="all, delete-orphan",
        lazy="select",
    )


class FindingRecord(Base):
    """Persistent representation of a deduplicated security finding.

    Columns are a superset of the in-memory Finding Pydantic model so that
    analyst workflow fields (analyst_severity, analyst_notes) and raw tool
    output are retained without round-tripping through the domain model.

    Composite indexes:
        ix_finding_scan_severity  — optimises severity-filtered queries per scan.
        ix_finding_target_hash    — optimises deduplication lookups by target.
    """

    __tablename__ = "finding_records"

    __table_args__ = (
        Index("ix_finding_scan_severity", "scan_id", "severity"),
        Index("ix_finding_target_hash", "target", "dedup_hash"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_records.id", ondelete="CASCADE"), nullable=False
    )

    # Deduplication
    dedup_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    # Description
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Classification
    severity: Mapped[str] = mapped_column(String(32), nullable=False)
    effective_severity: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="open")
    finding_type: Mapped[str] = mapped_column(String(128), nullable=False)

    # Target
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(16), nullable=True)
    affected_component: Mapped[str] = mapped_column(String(256), nullable=False, default="")

    # CVSS
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Identifiers (stored as JSON arrays)
    cve_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    cwe_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)

    # Source
    source_plugin: Mapped[str] = mapped_column(String(128), nullable=False)
    source_plugins: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    # Evidence & remediation (stored as JSON)
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)
    evidence: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)
    references: Mapped[list[dict[str, Any]] | None] = mapped_column(JSON, nullable=True)

    # MITRE ATT&CK (stored as JSON object)
    mitre_attack: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Analyst workflow
    analyst_severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Raw tool output
    raw_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Timestamps
    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )

    # Relationship
    scan: Mapped["ScanRecord"] = relationship("ScanRecord", back_populates="findings")


class ToolRunRecord(Base):
    """Persistent record of a single external tool invocation.

    Attributes:
        id: Auto-incrementing primary key.
        scan_id: FK to the parent scan.
        plugin_name: Name of the plugin that launched the tool.
        command: Full command string that was executed.
        return_code: Process exit code (nullable until the process exits).
        stdout_path: Path to the file storing captured stdout.
        stderr_snippet: First ~4 KB of stderr for quick triage.
        started_at: UTC timestamp when the tool process started.
        finished_at: UTC timestamp when the tool process ended (nullable).
        elapsed_seconds: Wall-clock execution time.
        state: Execution state ('pending', 'running', 'done', 'failed', 'timeout').
    """

    __tablename__ = "tool_run_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("scan_records.id", ondelete="CASCADE"), nullable=False
    )

    plugin_name: Mapped[str] = mapped_column(String(128), nullable=False)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    return_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    stderr_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    elapsed_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")

    # Relationship
    scan: Mapped["ScanRecord"] = relationship("ScanRecord", back_populates="tool_runs")


# ---------------------------------------------------------------------------
# Multi-user collaboration models
# ---------------------------------------------------------------------------


class UserRecord(Base):
    """Dashboard user account.

    Roles:
        viewer    — read-only access to scans/findings.
        reviewer  — can comment and set review status on findings.
        admin     — full access including user management.
    """

    __tablename__ = "user_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    email: Mapped[str | None] = mapped_column(String(256), nullable=True)
    role: Mapped[str] = mapped_column(String(32), nullable=False, default="viewer")
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class FindingCommentRecord(Base):
    """Comment posted by a user on a finding."""

    __tablename__ = "finding_comment_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("finding_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("user_records.id", ondelete="CASCADE"), nullable=False
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow
    )


class FindingReviewRecord(Base):
    """Latest review status for a finding by a reviewer."""

    __tablename__ = "finding_review_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("finding_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("user_records.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    reviewed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow
    )
