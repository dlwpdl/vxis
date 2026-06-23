"""JSON export for VXIS security findings and reports.

Provides structured JSON output with pretty-printing and proper datetime
serialization via Pydantic's native ``model_dump(mode="json")`` support.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from vxis.agent.tools._poc_signals import POC_REPLAY_MARKERS
from vxis.models.finding import Finding, FindingStatus, Severity
from vxis.report.generator import ReportData

_logger = logging.getLogger(__name__)

_HTTP_REQUEST_LINE_RE = re.compile(
    r"\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\S+\s+HTTP/\d(?:\.\d)?",
    re.IGNORECASE,
)
_HIGH_VALUE_SEVERITIES = {Severity.critical, Severity.high}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _raw_field(finding: Finding, key: str) -> str:
    raw = finding.raw_data if isinstance(finding.raw_data, dict) else {}
    return _text(raw.get(key))


def _evidence_contents(finding: Finding) -> list[str]:
    return [_text(item.content) for item in finding.evidence if _text(item.content)]


def _has_replay_marker(value: str) -> bool:
    lower = value.lower()
    return any(marker in lower for marker in POC_REPLAY_MARKERS)


def _first_replay_line(value: str) -> str:
    text = _text(value)
    if not text:
        return ""
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        if _HTTP_REQUEST_LINE_RE.search(candidate) or _has_replay_marker(candidate):
            return candidate
    if _HTTP_REQUEST_LINE_RE.search(text) or _has_replay_marker(text):
        return text
    return ""


def _extract_replay_command(finding: Finding) -> str:
    explicit = _text(finding.replay_command) or _raw_field(finding, "replay_command")
    if explicit:
        return explicit
    for value in [
        finding.poc_script_code,
        finding.poc_description,
        _raw_field(finding, "request_or_payload"),
        *_evidence_contents(finding),
    ]:
        replay = _first_replay_line(_text(value))
        if replay:
            return replay
    return ""


def _acceptance_status(finding: Finding) -> str:
    raw_status = _raw_field(finding, "acceptance_status").lower()
    if raw_status:
        return raw_status
    if finding.status == FindingStatus.confirmed:
        return "accepted"
    if finding.status in {FindingStatus.false_positive, FindingStatus.unconfirmed}:
        return "rejected"
    return "open"


def _has_repro_evidence(finding: Finding) -> bool:
    return bool(
        _text(finding.poc_script_code)
        or _evidence_contents(finding)
        or _raw_field(finding, "request_or_payload")
        or _raw_field(finding, "response_or_effect")
    )


def _is_bugbounty_accepted(finding: Finding) -> bool:
    status = _acceptance_status(finding)
    if status == "rejected":
        return False
    if status != "accepted":
        return False

    replay = _extract_replay_command(finding)
    if finding.effective_severity in _HIGH_VALUE_SEVERITIES:
        return bool(_text(finding.impact) and replay and _has_repro_evidence(finding))
    return bool(replay or _has_repro_evidence(finding))


def _serialize_bugbounty_evidence(finding: Finding) -> list[dict[str, str | None]]:
    return [
        {
            "type": item.evidence_type,
            "title": item.title,
            "content": item.content,
            "file_path": item.file_path,
            "content_type": item.content_type,
        }
        for item in finding.evidence
    ]


def _serialize_bugbounty_finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.effective_severity.value,
        "finding_type": finding.finding_type,
        "target": finding.target,
        "affected_component": finding.affected_component,
        "status": finding.status.value,
        "acceptance_status": _acceptance_status(finding),
        "accepted": True,
        "impact": _text(finding.impact),
        "technical_analysis": _text(finding.technical_analysis),
        "reproduction": {
            "summary": _text(finding.poc_description),
            "replay_command": _extract_replay_command(finding),
            "request_or_payload": _raw_field(finding, "request_or_payload"),
            "response_or_effect": _raw_field(finding, "response_or_effect"),
            "control_comparison": _raw_field(finding, "control_comparison"),
            "poc": _text(finding.poc_script_code),
        },
        "evidence": _serialize_bugbounty_evidence(finding),
        "remediation": _text(finding.remediation),
        "references": [ref.model_dump(mode="json") for ref in finding.references],
    }


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

    def export_bugbounty(
        self,
        report_data: ReportData,
        output_path: Path,
    ) -> Path:
        """Export accepted, replayable findings for bug bounty submission.

        This lightweight shape intentionally excludes open/refuted findings and
        keeps each finding centered on impact, replay, PoC, and evidence.
        """
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        accepted = [
            finding for finding in report_data.findings if _is_bugbounty_accepted(finding)
        ]
        severity_counts = {
            severity.value: sum(
                1 for finding in accepted if finding.effective_severity == severity
            )
            for severity in Severity
        }
        data: dict[str, Any] = {
            "schema_version": "vxis.bugbounty.v1",
            "export_type": "bugbounty",
            "scan": {
                "scan_id": report_data.scan_id,
                "target": report_data.target,
                "client_name": report_data.client_name,
                "scan_date": report_data.scan_date,
            },
            "summary": {
                "accepted_findings": len(accepted),
                "source_findings": len(report_data.findings),
                "suppressed_findings": max(len(report_data.findings) - len(accepted), 0),
                "severity_counts": severity_counts,
            },
            "findings": [_serialize_bugbounty_finding(finding) for finding in accepted],
        }

        output_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        _logger.info(
            "Exported %d accepted bug bounty finding(s) to JSON: %s",
            len(accepted),
            output_path,
        )
        return output_path
