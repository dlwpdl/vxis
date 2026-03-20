"""VXIS report generation package.

Provides HTML/PDF report generation, SVG chart utilities, and AI-assisted
executive summary generation for security assessment reports.
"""

from vxis.report.generator import ReportData, ReportGenerator
from vxis.report.charts import severity_bar_svg, severity_donut_svg
from vxis.report.ai_summary import generate_executive_summary

__all__ = [
    "ReportData",
    "ReportGenerator",
    "severity_bar_svg",
    "severity_donut_svg",
    "generate_executive_summary",
]
