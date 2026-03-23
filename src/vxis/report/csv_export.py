"""CSV export for VXIS security findings.

Produces a flat CSV file with one row per finding, suitable for import into
spreadsheets, SIEM platforms, or other tabular-data consumers.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from vxis.models.finding import Finding

_logger = logging.getLogger(__name__)

# Column definitions: (header, accessor) pairs.
# Accessors are attribute names on Finding; list-typed fields are joined with
# semicolons so they stay within a single CSV cell.
_COLUMNS: list[tuple[str, str]] = [
    ("severity", "severity"),
    ("title", "title"),
    ("target", "target"),
    ("port", "port"),
    ("finding_type", "finding_type"),
    ("source_plugin", "source_plugin"),
    ("confidence", "confidence"),
    ("cvss_score", "cvss_score"),
    ("cve_ids", "cve_ids"),
    ("cwe_ids", "cwe_ids"),
    ("status", "status"),
    ("remediation", "remediation"),
    ("discovered_at", "discovered_at"),
]


def _get_field(finding: Finding, field: str) -> str:
    """Extract a single field from a Finding, formatting as a CSV-safe string."""
    if field == "cvss_score":
        return str(finding.cvss.base_score) if finding.cvss else ""

    value = getattr(finding, field)

    if value is None:
        return ""

    # List fields → semicolon-separated
    if isinstance(value, list):
        return ";".join(str(v) for v in value)

    # Enum fields → use .value
    if hasattr(value, "value"):
        return str(value.value)

    return str(value)


class CSVExporter:
    """Export VXIS findings as a flat CSV file."""

    def export_findings(
        self,
        findings: list[Finding],
        output_path: Path,
    ) -> Path:
        """Export a list of findings to CSV.

        Parameters
        ----------
        findings:
            List of :class:`Finding` instances to serialize.
        output_path:
            Destination file path for the CSV output.

        Returns
        -------
        Path
            The resolved output path.
        """
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        headers = [col[0] for col in _COLUMNS]

        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)

            for finding in findings:
                row = [_get_field(finding, col[1]) for col in _COLUMNS]
                writer.writerow(row)

        _logger.info("Exported %d finding(s) to CSV: %s", len(findings), output_path)
        return output_path
