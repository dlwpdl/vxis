"""White-label branding configuration for VXIS reports.

Allows operators to rebrand reports with custom company identity, colours,
and logo without modifying core report-generation logic.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class BrandingConfig:
    """White-label branding settings applied to HTML and DOCX reports.

    All fields have sensible defaults so the class can be instantiated
    without any arguments for the built-in VXIS brand.
    """

    company_name: str = "VXIS Security"
    company_address: str = ""
    company_website: str = ""
    company_email: str = ""
    logo_path: Path | None = None
    primary_color: str = "#1a1a2e"
    accent_color: str = "#e94560"
    report_footer: str = "Confidential — {company_name}"
    report_classification: str = "Client Confidential"

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    @classmethod
    def from_toml(cls, path: Path) -> "BrandingConfig":
        """Load branding from a TOML file.

        The TOML file should have a ``[branding]`` section (optional — if
        absent the whole file is treated as the branding mapping).

        Parameters
        ----------
        path:
            Absolute or relative path to the ``.toml`` file.

        Returns
        -------
        BrandingConfig
            Populated instance; missing keys fall back to defaults.

        Raises
        ------
        FileNotFoundError
            If *path* does not exist.
        """
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]

        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Branding config file not found: {path}")

        with path.open("rb") as fh:
            raw = tomllib.load(fh)

        # Support both top-level keys and a [branding] section
        data: dict = raw.get("branding", raw)

        logo_raw: str | None = data.get("logo_path")
        logo_path = Path(logo_raw) if logo_raw else None

        return cls(
            company_name=data.get("company_name", "VXIS Security"),
            company_address=data.get("company_address", ""),
            company_website=data.get("company_website", ""),
            company_email=data.get("company_email", ""),
            logo_path=logo_path,
            primary_color=data.get("primary_color", "#1a1a2e"),
            accent_color=data.get("accent_color", "#e94560"),
            report_footer=data.get("report_footer", "Confidential — {company_name}"),
            report_classification=data.get("report_classification", "Client Confidential"),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_logo_base64(self) -> str | None:
        """Read the logo file and return a base64-encoded data URI string.

        The returned string can be embedded directly in an HTML ``<img>``
        ``src`` attribute::

            <img src="{{ branding.get_logo_base64() }}" />

        Returns
        -------
        str | None
            Base64-encoded data URI (e.g. ``data:image/png;base64,...``) or
            ``None`` when no logo path is configured or the file does not exist.
        """
        if self.logo_path is None:
            return None

        logo_path = Path(self.logo_path)
        if not logo_path.exists():
            return None

        suffix = logo_path.suffix.lower().lstrip(".")
        # Normalise common extensions to valid MIME types
        mime_map = {
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "png": "image/png",
            "gif": "image/gif",
            "svg": "image/svg+xml",
            "webp": "image/webp",
        }
        mime = mime_map.get(suffix, f"image/{suffix}")

        raw_bytes = logo_path.read_bytes()
        encoded = base64.b64encode(raw_bytes).decode("ascii")
        return f"data:{mime};base64,{encoded}"

    def formatted_footer(self) -> str:
        """Return the report footer with ``{company_name}`` substituted."""
        return self.report_footer.format(company_name=self.company_name)
