"""Branding engine — applies white-label branding to HTML and DOCX reports.

The engine operates on :class:`~vxis.report.generator.ReportData` objects
(mutating a copy, not the original) and on rendered HTML strings.  It is
intentionally stateless beyond the :class:`~vxis.config.branding.BrandingConfig`
it holds, making it safe to reuse across multiple reports.
"""

from __future__ import annotations

import copy
import re
from typing import TYPE_CHECKING

from vxis.config.branding import BrandingConfig
from vxis.report.generator import ReportData

if TYPE_CHECKING:
    pass


class BrandingEngine:
    """Apply white-label branding to HTML and DOCX reports.

    Parameters
    ----------
    branding:
        The branding configuration to apply.
    """

    def __init__(self, branding: BrandingConfig) -> None:
        self.branding = branding

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def apply_to_html(self, html: str) -> str:
        """Replace branding placeholders in a rendered HTML report string.

        The following substitutions are performed:

        * ``{{ company_name }}`` / ``{{company_name}}`` — replaced with the
          configured company name.
        * ``{{ company_logo }}`` / ``{{company_logo}}`` — replaced with an
          ``<img>`` tag using the base64-encoded logo (or an empty string when
          no logo is configured).
        * ``{{ report_footer }}`` / ``{{report_footer}}`` — replaced with the
          formatted footer string.
        * ``{{ primary_color }}`` / ``{{primary_color}}`` — CSS hex colour.
        * ``{{ accent_color }}`` / ``{{accent_color}}`` — CSS hex colour.
        * A ``<style>`` block with CSS variable overrides is injected just
          before ``</head>`` when one is present.

        Parameters
        ----------
        html:
            The rendered HTML document string.

        Returns
        -------
        str
            HTML with branding placeholders substituted.
        """
        branding = self.branding

        # Build logo tag
        logo_b64 = branding.get_logo_base64()
        if logo_b64:
            logo_tag = (
                f'<img src="{logo_b64}" alt="{branding.company_name} logo" '
                f'style="max-height:48px;vertical-align:middle;" />'
            )
        else:
            logo_tag = f'<span style="font-weight:bold;">{branding.company_name}</span>'

        replacements: list[tuple[str, str]] = [
            ("company_name", branding.company_name),
            ("company_logo", logo_tag),
            ("report_footer", branding.formatted_footer()),
            ("primary_color", branding.primary_color),
            ("accent_color", branding.accent_color),
            ("report_classification", branding.report_classification),
        ]

        for key, value in replacements:
            # Match both {{ key }} and {{key}} variants (with optional whitespace)
            pattern = r"\{\{\s*" + re.escape(key) + r"\s*\}\}"
            html = re.sub(pattern, lambda m, v=value: v, html)

        # Inject CSS overrides before </head>
        css_override = self.get_css_overrides()
        if "</head>" in html:
            html = html.replace(
                "</head>",
                f"<style>{css_override}</style>\n</head>",
                1,
            )

        return html

    def apply_to_report_data(self, data: ReportData) -> ReportData:
        """Return a copy of *data* with branding fields populated.

        The original object is **not** mutated.

        Fields set on the copy:

        * ``company_name`` — from :attr:`~BrandingConfig.company_name`
        * ``logo_path`` — from :attr:`~BrandingConfig.logo_path` (as string)
        * ``author`` — from :attr:`~BrandingConfig.company_email` when the
          existing ``author`` field is empty, otherwise left unchanged.

        Parameters
        ----------
        data:
            Source :class:`~vxis.report.generator.ReportData` instance.

        Returns
        -------
        ReportData
            A shallow copy with branding overrides applied.
        """
        branded = copy.copy(data)
        branded.company_name = self.branding.company_name
        if self.branding.logo_path is not None:
            branded.logo_path = str(self.branding.logo_path)
        if not branded.author and self.branding.company_email:
            branded.author = self.branding.company_email
        return branded

    def get_css_overrides(self) -> str:
        """Generate a CSS snippet that applies the branding colour scheme.

        The snippet sets CSS custom properties on ``:root`` so that any
        template referencing ``var(--primary-color)`` or
        ``var(--accent-color)`` will automatically pick up the custom brand
        colours.

        Returns
        -------
        str
            A CSS string (without enclosing ``<style>`` tags).
        """
        return (
            ":root {\n"
            f"  --primary-color: {self.branding.primary_color};\n"
            f"  --accent-color: {self.branding.accent_color};\n"
            f"  --company-name: '{self.branding.company_name}';\n"
            "}\n"
            f"/* Branding: {self.branding.company_name} */\n"
            f"body {{ --brand-primary: {self.branding.primary_color}; "
            f"--brand-accent: {self.branding.accent_color}; }}\n"
        )
