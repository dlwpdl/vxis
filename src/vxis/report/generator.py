"""Report generator for VXIS security assessment reports.

Uses Jinja2 templating to produce professional HTML security reports
in NCC Group style. PDF generation is stubbed pending WeasyPrint availability.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vxis.models.finding import Finding, Severity
from vxis.report.charts import severity_bar_svg, severity_donut_svg

if TYPE_CHECKING:
    pass

_logger = logging.getLogger(__name__)

# Severity ordering for consistent report presentation
_SEVERITY_ORDER: list[str] = [
    Severity.critical.value,
    Severity.high.value,
    Severity.medium.value,
    Severity.low.value,
    Severity.informational.value,
]

# Weighted multipliers for risk score calculation (CVSS-inspired weighting)
_SEVERITY_WEIGHTS: dict[str, float] = {
    Severity.critical.value: 10.0,
    Severity.high.value: 7.0,
    Severity.medium.value: 4.0,
    Severity.low.value: 1.5,
    Severity.informational.value: 0.1,
}

# Default methodology text used when none is provided
_DEFAULT_METHODOLOGY = (
    "VXIS conducted this assessment using a combination of automated scanning and manual "
    "verification techniques. The methodology follows industry-standard frameworks including "
    "OWASP Testing Guide (OTGv4), PTES (Penetration Testing Execution Standard), and "
    "NIST SP 800-115. Automated tools were used for initial discovery and coverage, "
    "with manual analysis applied to validate findings, eliminate false positives, and "
    "identify logic-level vulnerabilities that automated tooling cannot detect."
)


@dataclass
class ReportData:
    """Aggregated data required to render a security assessment report.

    All rendering-time computation (counts, grouping, risk score) is performed
    lazily via properties so the dataclass remains a simple value container.
    """

    scan_id: str
    client_name: str
    target: str
    scan_date: str
    findings: list[Finding]
    company_name: str = "VXIS Security"
    author: str = ""
    logo_path: str | None = None
    executive_summary: str = ""
    methodology: str = field(default=_DEFAULT_METHODOLOGY)

    @property
    def severity_counts(self) -> dict[str, int]:
        """Return a count of findings per severity level.

        All severity levels are present in the result (defaulting to 0) so
        templates can iterate the full set without conditional checks.
        """
        counts: dict[str, int] = {s: 0 for s in _SEVERITY_ORDER}
        for finding in self.findings:
            key = finding.effective_severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Return findings grouped by effective severity in canonical order.

        Each key is always present even when its list is empty so templates
        can safely iterate without missing-key guards.
        """
        grouped: dict[str, list[Finding]] = {s: [] for s in _SEVERITY_ORDER}
        for finding in self.findings:
            key = finding.effective_severity.value
            grouped[key].append(finding)
        # Sort each group by title for deterministic output
        for group in grouped.values():
            group.sort(key=lambda f: f.title)
        return grouped

    @property
    def total_findings(self) -> int:
        """Total number of findings in this report."""
        return len(self.findings)

    @property
    def risk_score(self) -> float:
        """Weighted risk score normalised to the 0–10 range.

        Scoring formula: sum(weight * count) divided by a reference maximum
        that assumes all findings are Critical. Clamped to [0, 10].

        An empty finding set returns 0.0.
        """
        if not self.findings:
            return 0.0

        counts = self.severity_counts
        raw = sum(_SEVERITY_WEIGHTS[sev] * counts[sev] for sev in _SEVERITY_ORDER)

        # Reference maximum: every finding is Critical
        max_possible = _SEVERITY_WEIGHTS[Severity.critical.value] * len(self.findings)
        if max_possible == 0:
            return 0.0

        score = (raw / max_possible) * 10.0
        return round(min(score, 10.0), 2)


# ---------------------------------------------------------------------------
# Jinja2 custom filters
# ---------------------------------------------------------------------------

def _filter_severity_color(severity: str) -> str:
    """Map a severity string to its canonical hex colour."""
    colours: dict[str, str] = {
        "critical": "#7B2C34",
        "high": "#C0392B",
        "medium": "#E67E22",
        "low": "#2ECC71",
        "informational": "#3498DB",
    }
    return colours.get(severity.lower(), "#888888")


def _filter_severity_badge(severity: str) -> str:
    """Return an HTML <span> badge for the given severity level."""
    colour = _filter_severity_color(severity)
    label = severity.upper()
    return (
        f'<span class="severity-badge" '
        f'style="background-color:{colour};">'
        f'{label}</span>'
    )


class ReportGenerator:
    """Jinja2-based HTML report generator for VXIS security assessments.

    Templates are resolved from *template_dir* (defaults to the ``templates``
    subdirectory adjacent to this module). Custom Jinja2 filters are registered
    at construction time so templates can use them directly.
    """

    def __init__(self, template_dir: Path | None = None) -> None:
        if template_dir is None:
            template_dir = Path(__file__).parent / "templates"

        self._template_dir = template_dir
        self._env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

        # Register custom filters
        self._env.filters["severity_color"] = _filter_severity_color
        self._env.filters["severity_badge"] = _filter_severity_badge

        # Register chart helpers as global functions accessible from templates
        self._env.globals["severity_donut_svg"] = severity_donut_svg
        self._env.globals["severity_bar_svg"] = severity_bar_svg

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def render_html(
        self,
        data: ReportData,
        template_name: str = "profiles/default.html",
    ) -> str:
        """Render *data* using the named Jinja2 template and return HTML.

        Parameters
        ----------
        data:
            Populated :class:`ReportData` instance.
        template_name:
            Path to the template relative to *template_dir*.

        Returns
        -------
        str
            Rendered HTML document as a Unicode string.
        """
        template = self._env.get_template(template_name)
        return template.render(
            report=data,
            severity_order=_SEVERITY_ORDER,
        )

    def generate_html_file(
        self,
        data: ReportData,
        output_path: Path,
        template_name: str = "profiles/default.html",
    ) -> Path:
        """Render the report to an HTML file at *output_path*.

        Parent directories are created automatically. The rendered content is
        written as UTF-8.

        Returns
        -------
        Path
            The resolved output path (same as *output_path* after resolution).
        """
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        html = self.render_html(data, template_name)
        output_path.write_text(html, encoding="utf-8")
        return output_path

    def generate_pdf(
        self,
        data: ReportData,
        output_path: Path,
        template_name: str = "profiles/default.html",
    ) -> Path:
        """Generate a PDF report by rendering HTML then converting via *wkhtmltopdf*.

        The method first writes a temporary HTML file using :meth:`generate_html_file`,
        then shells out to ``wkhtmltopdf`` to produce the final PDF.

        Parameters
        ----------
        data:
            Populated :class:`ReportData` instance.
        output_path:
            Destination path for the PDF file.
        template_name:
            Jinja2 template path relative to *template_dir*.

        Returns
        -------
        Path
            The resolved *output_path*.

        Raises
        ------
        RuntimeError
            If ``wkhtmltopdf`` is not found on ``$PATH`` or if the conversion
            process exits with a non-zero return code.
        """
        output_path = output_path.resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Render an intermediate HTML file next to the target PDF
        html_path = output_path.with_suffix(".html")
        self.generate_html_file(data, html_path, template_name)

        pdf_path = _html_to_pdf(html_path, output_path)

        # Clean up the intermediate HTML file
        try:
            html_path.unlink()
        except OSError:
            _logger.debug("Could not remove intermediate HTML file: %s", html_path)

        return pdf_path


def _html_to_pdf(html_path: Path, pdf_path: Path) -> Path:
    """Convert an HTML file to PDF using ``wkhtmltopdf``.

    Parameters
    ----------
    html_path:
        Path to the source HTML file.
    pdf_path:
        Destination path for the generated PDF.

    Returns
    -------
    Path
        The resolved *pdf_path*.

    Raises
    ------
    RuntimeError
        If ``wkhtmltopdf`` is not installed or the conversion fails.
    """
    wkhtmltopdf = shutil.which("wkhtmltopdf")
    if wkhtmltopdf is None:
        raise RuntimeError(
            "PDF generation requires 'wkhtmltopdf' to be installed and on $PATH. "
            "Install it via your system package manager "
            "(e.g. 'apt install wkhtmltopdf' or 'brew install wkhtmltopdf'). "
            "Alternatively, use generate_html_file() and print to PDF from a browser."
        )

    cmd = [
        wkhtmltopdf,
        "--quiet",
        "--enable-local-file-access",
        str(html_path),
        str(pdf_path),
    ]

    _logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)  # noqa: S603

    if result.returncode != 0:
        raise RuntimeError(
            f"wkhtmltopdf exited with code {result.returncode}.\n"
            f"stderr: {result.stderr.strip()}"
        )

    return pdf_path
