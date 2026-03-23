"""VXIS report generation package.

Provides HTML/PDF report generation, SVG chart utilities, AI-assisted
executive summary generation, and JSON/CSV export for security assessment
reports.
"""

from vxis.report.generator import ReportData, ReportGenerator
from vxis.report.charts import severity_bar_svg, severity_donut_svg
from vxis.report.ai_summary import generate_executive_summary
from vxis.report.json_export import JSONExporter
from vxis.report.csv_export import CSVExporter

__all__ = [
    "ReportData",
    "ReportGenerator",
    "severity_bar_svg",
    "severity_donut_svg",
    "generate_executive_summary",
    "JSONExporter",
    "CSVExporter",
]
