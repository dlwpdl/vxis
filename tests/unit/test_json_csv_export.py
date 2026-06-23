"""Unit tests for VXIS JSON and CSV export modules.

Covers:
- JSON export with findings
- JSON export with full report data
- CSV export with findings
- Empty findings handling
- List field serialization in CSV
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path


from vxis.models.finding import CVSSVector, Finding, FindingStatus, Severity
from vxis.report.csv_export import CSVExporter
from vxis.report.generator import ReportData
from vxis.report.json_export import JSONExporter


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def make_finding(
    id: str = "f-001",
    title: str = "SQL Injection",
    severity: Severity = Severity.high,
    finding_type: str = "sqli",
    description: str = "Unsanitised input passed to SQL query.",
    **overrides,
) -> Finding:
    """Return a minimal valid Finding with sensible defaults."""
    defaults: dict = dict(
        id=id,
        scan_id="scan-001",
        title=title,
        description=description,
        severity=severity,
        target="192.168.1.10",
        finding_type=finding_type,
        source_plugin="test_plugin",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def make_report_data(
    findings: list[Finding] | None = None,
    **overrides,
) -> ReportData:
    """Return a populated ReportData with sensible defaults."""
    defaults: dict = dict(
        scan_id="scan-abc-123",
        client_name="Acme Corp",
        target="acme.com",
        scan_date="2026-03-20",
        findings=findings if findings is not None else [],
        author="Jane Smith",
        company_name="VXIS Security",
    )
    defaults.update(overrides)
    return ReportData(**defaults)


# ---------------------------------------------------------------------------
# JSON export tests
# ---------------------------------------------------------------------------


class TestJSONExporterFindings:
    """Tests for JSONExporter.export_findings."""

    def test_export_findings_creates_file(self, tmp_path: Path) -> None:
        findings = [make_finding()]
        out = tmp_path / "findings.json"

        result = JSONExporter().export_findings(findings, out)

        assert result.exists()
        assert result == out.resolve()

    def test_export_findings_valid_json_array(self, tmp_path: Path) -> None:
        findings = [
            make_finding(id="f-001", title="SQL Injection"),
            make_finding(id="f-002", title="XSS", severity=Severity.medium, finding_type="xss"),
        ]
        out = tmp_path / "findings.json"

        JSONExporter().export_findings(findings, out)
        data = json.loads(out.read_text(encoding="utf-8"))

        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["title"] == "SQL Injection"
        assert data[1]["title"] == "XSS"

    def test_export_findings_severity_as_string(self, tmp_path: Path) -> None:
        findings = [make_finding(severity=Severity.critical)]
        out = tmp_path / "findings.json"

        JSONExporter().export_findings(findings, out)
        data = json.loads(out.read_text(encoding="utf-8"))

        assert data[0]["severity"] == "critical"

    def test_export_findings_datetime_serialized(self, tmp_path: Path) -> None:
        dt = datetime(2026, 3, 20, 12, 0, 0, tzinfo=timezone.utc)
        findings = [make_finding(discovered_at=dt)]
        out = tmp_path / "findings.json"

        JSONExporter().export_findings(findings, out)
        data = json.loads(out.read_text(encoding="utf-8"))

        # Pydantic mode="json" serializes datetime as ISO string
        assert "2026-03-20" in data[0]["discovered_at"]

    def test_export_findings_pretty_printed(self, tmp_path: Path) -> None:
        findings = [make_finding()]
        out = tmp_path / "findings.json"

        JSONExporter().export_findings(findings, out)
        text = out.read_text(encoding="utf-8")

        # Pretty-printed JSON contains newlines and indentation
        assert "\n" in text
        assert "  " in text

    def test_export_empty_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "empty.json"

        JSONExporter().export_findings([], out)
        data = json.loads(out.read_text(encoding="utf-8"))

        assert data == []

    def test_export_findings_creates_parent_dirs(self, tmp_path: Path) -> None:
        out = tmp_path / "sub" / "dir" / "findings.json"

        JSONExporter().export_findings([make_finding()], out)

        assert out.resolve().exists()


class TestJSONExporterReport:
    """Tests for JSONExporter.export_report."""

    def test_export_report_creates_file(self, tmp_path: Path) -> None:
        report = make_report_data(findings=[make_finding()])
        out = tmp_path / "report.json"

        result = JSONExporter().export_report(report, out)

        assert result.exists()

    def test_export_report_contains_metadata(self, tmp_path: Path) -> None:
        report = make_report_data(findings=[make_finding()])
        out = tmp_path / "report.json"

        JSONExporter().export_report(report, out)
        data = json.loads(out.read_text(encoding="utf-8"))

        assert data["scan_id"] == "scan-abc-123"
        assert data["client_name"] == "Acme Corp"
        assert data["target"] == "acme.com"
        assert data["scan_date"] == "2026-03-20"
        assert data["company_name"] == "VXIS Security"
        assert data["author"] == "Jane Smith"

    def test_export_report_contains_findings(self, tmp_path: Path) -> None:
        findings = [
            make_finding(id="f-001"),
            make_finding(id="f-002", title="XSS", finding_type="xss"),
        ]
        report = make_report_data(findings=findings)
        out = tmp_path / "report.json"

        JSONExporter().export_report(report, out)
        data = json.loads(out.read_text(encoding="utf-8"))

        assert data["total_findings"] == 2
        assert len(data["findings"]) == 2

    def test_export_report_contains_severity_counts(self, tmp_path: Path) -> None:
        findings = [
            make_finding(id="f-001", severity=Severity.high),
            make_finding(id="f-002", severity=Severity.medium, finding_type="xss"),
        ]
        report = make_report_data(findings=findings)
        out = tmp_path / "report.json"

        JSONExporter().export_report(report, out)
        data = json.loads(out.read_text(encoding="utf-8"))

        assert data["severity_counts"]["high"] == 1
        assert data["severity_counts"]["medium"] == 1
        assert data["severity_counts"]["critical"] == 0

    def test_export_report_contains_risk_score(self, tmp_path: Path) -> None:
        report = make_report_data(findings=[make_finding(severity=Severity.critical)])
        out = tmp_path / "report.json"

        JSONExporter().export_report(report, out)
        data = json.loads(out.read_text(encoding="utf-8"))

        assert "risk_score" in data
        assert isinstance(data["risk_score"], (int, float))

    def test_export_report_empty_findings(self, tmp_path: Path) -> None:
        report = make_report_data(findings=[])
        out = tmp_path / "report.json"

        JSONExporter().export_report(report, out)
        data = json.loads(out.read_text(encoding="utf-8"))

        assert data["total_findings"] == 0
        assert data["findings"] == []
        assert data["risk_score"] == 0.0


class TestJSONExporterBugBounty:
    """Tests for JSONExporter.export_bugbounty."""

    def test_export_bugbounty_contains_only_accepted_replayable_findings(
        self, tmp_path: Path
    ) -> None:
        accepted = make_finding(
            id="f-accepted",
            status=FindingStatus.confirmed,
            impact="The attacker can extract account records from the orders API.",
            technical_analysis="Payload response differed from the baseline control request.",
            poc_description="Send the replay command and compare the 200 response to baseline 403.",
            poc_script_code="GET /api/orders?id=1%20OR%201=1 HTTP/1.1\nHost: target.test",
            replay_command="curl -i 'https://target.test/api/orders?id=1%20OR%201=1'",
            raw_data={
                "acceptance_status": "accepted",
                "request_or_payload": "id=1 OR 1=1",
                "response_or_effect": "200 response includes other user order rows",
                "control_comparison": "id=1 returns one row; payload returns many rows",
            },
        )
        suppressed = make_finding(
            id="f-open",
            status=FindingStatus.open,
            impact="Looks interesting but has not been accepted.",
            replay_command="curl -i https://target.test/admin",
            poc_script_code="GET /admin HTTP/1.1\nHost: target.test",
        )
        report = make_report_data(findings=[accepted, suppressed])
        out = tmp_path / "bugbounty.json"

        JSONExporter().export_bugbounty(report, out)
        data = json.loads(out.read_text(encoding="utf-8"))

        assert data["schema_version"] == "vxis.bugbounty.v1"
        assert data["export_type"] == "bugbounty"
        assert data["summary"]["accepted_findings"] == 1
        assert data["summary"]["suppressed_findings"] == 1
        assert data["summary"]["severity_counts"]["high"] == 1
        assert [finding["id"] for finding in data["findings"]] == ["f-accepted"]
        exported = data["findings"][0]
        assert exported["accepted"] is True
        assert exported["impact"].startswith("The attacker can extract")
        assert exported["reproduction"]["replay_command"].startswith("curl -i")
        assert exported["reproduction"]["control_comparison"].startswith("id=1 returns")

    def test_export_bugbounty_extracts_raw_http_replay_when_command_missing(
        self, tmp_path: Path
    ) -> None:
        finding = make_finding(
            id="f-http",
            status=FindingStatus.confirmed,
            impact="Authenticated data is exposed through a direct object reference.",
            poc_script_code=(
                "GET /api/users/2 HTTP/1.1\n"
                "Host: target.test\n\n"
                "HTTP/1.1 200 OK\n"
                '{"email":"victim@example.com"}'
            ),
        )
        report = make_report_data(findings=[finding])
        out = tmp_path / "bugbounty.json"

        JSONExporter().export_bugbounty(report, out)
        data = json.loads(out.read_text(encoding="utf-8"))

        assert data["summary"]["accepted_findings"] == 1
        assert data["findings"][0]["reproduction"]["replay_command"] == (
            "GET /api/users/2 HTTP/1.1"
        )


# ---------------------------------------------------------------------------
# CSV export tests
# ---------------------------------------------------------------------------


class TestCSVExporterFindings:
    """Tests for CSVExporter.export_findings."""

    def test_export_findings_creates_file(self, tmp_path: Path) -> None:
        findings = [make_finding()]
        out = tmp_path / "findings.csv"

        result = CSVExporter().export_findings(findings, out)

        assert result.exists()
        assert result == out.resolve()

    def test_export_findings_has_header_row(self, tmp_path: Path) -> None:
        out = tmp_path / "findings.csv"

        CSVExporter().export_findings([make_finding()], out)

        with out.open(encoding="utf-8") as fh:
            reader = csv.reader(fh)
            header = next(reader)

        expected_headers = [
            "severity",
            "title",
            "target",
            "port",
            "finding_type",
            "source_plugin",
            "confidence",
            "cvss_score",
            "cve_ids",
            "cwe_ids",
            "status",
            "remediation",
            "discovered_at",
        ]
        assert header == expected_headers

    def test_export_findings_correct_values(self, tmp_path: Path) -> None:
        finding = make_finding(
            title="SQL Injection",
            severity=Severity.high,
            port=443,
            remediation="Use parameterised queries",
        )
        out = tmp_path / "findings.csv"

        CSVExporter().export_findings([finding], out)

        with out.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            row = next(reader)

        assert row["severity"] == "high"
        assert row["title"] == "SQL Injection"
        assert row["port"] == "443"
        assert row["remediation"] == "Use parameterised queries"
        assert row["target"] == "192.168.1.10"

    def test_export_findings_multiple_rows(self, tmp_path: Path) -> None:
        findings = [
            make_finding(id="f-001", title="SQLi"),
            make_finding(id="f-002", title="XSS", finding_type="xss"),
        ]
        out = tmp_path / "findings.csv"

        CSVExporter().export_findings(findings, out)

        with out.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)

        assert len(rows) == 2
        assert rows[0]["title"] == "SQLi"
        assert rows[1]["title"] == "XSS"

    def test_export_empty_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "empty.csv"

        CSVExporter().export_findings([], out)

        with out.open(encoding="utf-8") as fh:
            reader = csv.reader(fh)
            rows = list(reader)

        # Header only, no data rows
        assert len(rows) == 1

    def test_export_findings_list_fields_semicolon_joined(self, tmp_path: Path) -> None:
        finding = make_finding(
            cve_ids=["CVE-2024-1234", "CVE-2024-5678"],
            cwe_ids=["CWE-89", "CWE-79"],
        )
        out = tmp_path / "findings.csv"

        CSVExporter().export_findings([finding], out)

        with out.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            row = next(reader)

        assert row["cve_ids"] == "CVE-2024-1234;CVE-2024-5678"
        assert row["cwe_ids"] == "CWE-89;CWE-79"

    def test_export_findings_empty_list_fields(self, tmp_path: Path) -> None:
        finding = make_finding(cve_ids=[], cwe_ids=[])
        out = tmp_path / "findings.csv"

        CSVExporter().export_findings([finding], out)

        with out.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            row = next(reader)

        assert row["cve_ids"] == ""
        assert row["cwe_ids"] == ""

    def test_export_findings_cvss_score(self, tmp_path: Path) -> None:
        cvss = CVSSVector(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=9.8,
        )
        finding = make_finding(cvss=cvss)
        out = tmp_path / "findings.csv"

        CSVExporter().export_findings([finding], out)

        with out.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            row = next(reader)

        assert row["cvss_score"] == "9.8"

    def test_export_findings_no_cvss(self, tmp_path: Path) -> None:
        finding = make_finding()  # cvss defaults to None
        out = tmp_path / "findings.csv"

        CSVExporter().export_findings([finding], out)

        with out.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            row = next(reader)

        assert row["cvss_score"] == ""

    def test_export_findings_none_port(self, tmp_path: Path) -> None:
        finding = make_finding()  # port defaults to None
        out = tmp_path / "findings.csv"

        CSVExporter().export_findings([finding], out)

        with out.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            row = next(reader)

        assert row["port"] == ""

    def test_export_findings_creates_parent_dirs(self, tmp_path: Path) -> None:
        out = tmp_path / "nested" / "dir" / "findings.csv"

        CSVExporter().export_findings([make_finding()], out)

        assert out.resolve().exists()
