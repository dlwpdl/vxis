"""Initial schema — scan_records, finding_records, tool_run_records.

Revision ID: 001
Revises: None
Create Date: 2026-03-23
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # -- scan_records ----------------------------------------------------------
    op.create_table(
        "scan_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("profile", sa.String(128), nullable=False),
        sa.Column("status", sa.String(64), nullable=False, server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("config_snapshot", sa.JSON(), nullable=True),
    )

    # -- finding_records -------------------------------------------------------
    op.create_table(
        "finding_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scan_records.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Deduplication
        sa.Column("dedup_hash", sa.String(64), nullable=False),
        # Description
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        # Classification
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("effective_severity", sa.String(32), nullable=False),
        sa.Column("status", sa.String(64), nullable=False, server_default="open"),
        sa.Column("finding_type", sa.String(128), nullable=False),
        # Target
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(16), nullable=True),
        sa.Column("affected_component", sa.String(256), nullable=False, server_default=""),
        # CVSS
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(256), nullable=True),
        # Identifiers (JSON arrays)
        sa.Column("cve_ids", sa.JSON(), nullable=True),
        sa.Column("cwe_ids", sa.JSON(), nullable=True),
        # Source
        sa.Column("source_plugin", sa.String(128), nullable=False),
        sa.Column("source_plugins", sa.JSON(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        # Evidence & remediation
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("references", sa.JSON(), nullable=True),
        # MITRE ATT&CK
        sa.Column("mitre_attack", sa.JSON(), nullable=True),
        # Analyst workflow
        sa.Column("analyst_severity", sa.String(32), nullable=True),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        # Raw tool output
        sa.Column("raw_data", sa.JSON(), nullable=True),
        # Timestamps
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_index(
        "ix_finding_scan_severity",
        "finding_records",
        ["scan_id", "severity"],
    )
    op.create_index(
        "ix_finding_target_hash",
        "finding_records",
        ["target", "dedup_hash"],
    )

    # -- tool_run_records ------------------------------------------------------
    op.create_table(
        "tool_run_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "scan_id",
            sa.Integer(),
            sa.ForeignKey("scan_records.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("plugin_name", sa.String(128), nullable=False),
        sa.Column("command", sa.Text(), nullable=False),
        sa.Column("return_code", sa.Integer(), nullable=True),
        sa.Column("stdout_path", sa.String(1024), nullable=True),
        sa.Column("stderr_snippet", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("elapsed_seconds", sa.Float(), nullable=True),
        sa.Column("state", sa.String(32), nullable=False, server_default="pending"),
    )


def downgrade() -> None:
    op.drop_table("tool_run_records")
    op.drop_index("ix_finding_target_hash", table_name="finding_records")
    op.drop_index("ix_finding_scan_severity", table_name="finding_records")
    op.drop_table("finding_records")
    op.drop_table("scan_records")
