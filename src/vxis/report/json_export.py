"""JSON export for VXIS security findings and reports.

Provides structured JSON output with pretty-printing and proper datetime
serialization via Pydantic's native ``model_dump(mode="json")`` support.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from vxis.models.finding import Finding
from vxis.report.generator import ReportData

_logger = logging.getLogger(__name__)


class JSONExporter:
    """Export VXIS findings and reports as pretty-printed JSON files."""

    def export_findings(
        self,
        findings: list[Finding],
        output_path: Path,
    ) -> Path:
        """Export a list of findings as a JSON array.

        Parameters
        ----------
        findings:
            List of :class:`Finding` instances to serialize.
        output_path:
            Destination file path for the JSON output.

        Returns
        -------
        Path
            The resolved output path.
        """
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = [f.model_dump(mode="json") for f in findings]
        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        _logger.info("Exported %d finding(s) to JSON: %s", len(findings), output_path)
        return output_path

    def export_report(
        self,
        report_data: ReportData,
        output_path: Path,
    ) -> Path:
        """Export a full report with metadata and findings as JSON.

        The output includes top-level report metadata (scan_id, client_name,
        target, scan_date, etc.) alongside the serialized findings array and
        computed summary statistics.

        Parameters
        ----------
        report_data:
            Populated :class:`ReportData` instance.
        output_path:
            Destination file path for the JSON output.

        Returns
        -------
        Path
            The resolved output path.
        """
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "scan_id": report_data.scan_id,
            "client_name": report_data.client_name,
            "target": report_data.target,
            "scan_date": report_data.scan_date,
            "company_name": report_data.company_name,
            "author": report_data.author,
            "executive_summary": report_data.executive_summary,
            "total_findings": report_data.total_findings,
            "severity_counts": report_data.severity_counts,
            "risk_score": report_data.risk_score,
            "findings": [f.model_dump(mode="json") for f in report_data.findings],
        }

        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        _logger.info("Exported report to JSON: %s", output_path)
        return output_path
