"""Unit tests for white-label branding configuration and engine.

Covers:
- BrandingConfig dataclass defaults
- BrandingConfig.from_toml loading
- get_logo_base64 with a real PNG file and with no logo configured
- BrandingEngine.apply_to_report_data — sets company name from branding
- BrandingEngine.get_css_overrides — contains both colour values
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

import pytest

from vxis.config.branding import BrandingConfig
from vxis.report.branding_engine import BrandingEngine
from vxis.report.generator import ReportData


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tiny_png(path: Path) -> None:
    """Write a minimal valid 1x1 pixel red PNG to *path*.

    The PNG is constructed manually so the test has no dependency on Pillow
    or any other image library.
    """
    def _chunk(chunk_type: bytes, data: bytes) -> bytes:
        length = struct.pack(">I", len(data))
        crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
        return length + chunk_type + data + crc

    # PNG signature
    signature = b"\x89PNG\r\n\x1a\n"

    # IHDR: 1x1, 8-bit RGB
    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    ihdr = _chunk(b"IHDR", ihdr_data)

    # IDAT: single red pixel (filter byte 0x00 + R G B)
    raw_row = b"\x00\xFF\x00\x00"  # filter=None, R=255, G=0, B=0
    compressed = zlib.compress(raw_row)
    idat = _chunk(b"IDAT", compressed)

    # IEND
    iend = _chunk(b"IEND", b"")

    path.write_bytes(signature + ihdr + idat + iend)


def _make_branding_toml(path: Path, **overrides) -> None:
    """Write a minimal branding TOML file to *path*."""
    lines = [
        f'company_name = "{overrides.get("company_name", "Acme Security")}"',
        f'company_email = "{overrides.get("company_email", "security@acme.example")}"',
        f'primary_color = "{overrides.get("primary_color", "#0d1b2a")}"',
        f'accent_color = "{overrides.get("accent_color", "#ff6b35")}"',
    ]
    if "logo_path" in overrides:
        lines.append(f'logo_path = "{overrides["logo_path"]}"')
    path.write_text("\n".join(lines), encoding="utf-8")


def _make_minimal_report_data() -> ReportData:
    return ReportData(
        scan_id="test-001",
        client_name="Test Client",
        target="example.com",
        scan_date="2025-01-01",
        findings=[],
    )


# ---------------------------------------------------------------------------
# BrandingConfig defaults
# ---------------------------------------------------------------------------


class TestBrandingConfigDefaults:
    def test_default_company_name(self) -> None:
        branding = BrandingConfig()
        assert branding.company_name == "VXIS Security"

    def test_default_primary_color(self) -> None:
        branding = BrandingConfig()
        assert branding.primary_color == "#1a1a2e"

    def test_default_accent_color(self) -> None:
        branding = BrandingConfig()
        assert branding.accent_color == "#e94560"

    def test_default_logo_path_is_none(self) -> None:
        branding = BrandingConfig()
        assert branding.logo_path is None

    def test_default_report_footer_contains_placeholder(self) -> None:
        branding = BrandingConfig()
        assert "{company_name}" in branding.report_footer

    def test_default_classification(self) -> None:
        branding = BrandingConfig()
        assert branding.report_classification == "Client Confidential"

    def test_formatted_footer_substitutes_company_name(self) -> None:
        branding = BrandingConfig(company_name="AcmeSec")
        footer = branding.formatted_footer()
        assert "AcmeSec" in footer
        assert "{company_name}" not in footer


# ---------------------------------------------------------------------------
# BrandingConfig.from_toml
# ---------------------------------------------------------------------------


class TestBrandingConfigFromToml:
    def test_loads_company_name(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "branding.toml"
        _make_branding_toml(toml_file, company_name="FooCorp Security")
        branding = BrandingConfig.from_toml(toml_file)
        assert branding.company_name == "FooCorp Security"

    def test_loads_primary_color(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "branding.toml"
        _make_branding_toml(toml_file, primary_color="#abcdef")
        branding = BrandingConfig.from_toml(toml_file)
        assert branding.primary_color == "#abcdef"

    def test_loads_accent_color(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "branding.toml"
        _make_branding_toml(toml_file, accent_color="#123456")
        branding = BrandingConfig.from_toml(toml_file)
        assert branding.accent_color == "#123456"

    def test_loads_email(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "branding.toml"
        _make_branding_toml(toml_file, company_email="hello@example.com")
        branding = BrandingConfig.from_toml(toml_file)
        assert branding.company_email == "hello@example.com"

    def test_missing_keys_fall_back_to_defaults(self, tmp_path: Path) -> None:
        toml_file = tmp_path / "branding.toml"
        toml_file.write_text('company_name = "Minimal"\n', encoding="utf-8")
        branding = BrandingConfig.from_toml(toml_file)
        assert branding.accent_color == "#e94560"  # default
        assert branding.logo_path is None

    def test_raises_file_not_found(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            BrandingConfig.from_toml(tmp_path / "nonexistent.toml")

    def test_branding_section_takes_precedence(self, tmp_path: Path) -> None:
        """TOML files with a [branding] section should be parsed from that section."""
        toml_file = tmp_path / "branding.toml"
        toml_file.write_text(
            "[branding]\n"
            'company_name = "SectionCorp"\n'
            'primary_color = "#ff0000"\n',
            encoding="utf-8",
        )
        branding = BrandingConfig.from_toml(toml_file)
        assert branding.company_name == "SectionCorp"
        assert branding.primary_color == "#ff0000"


# ---------------------------------------------------------------------------
# BrandingConfig.get_logo_base64
# ---------------------------------------------------------------------------


class TestGetLogoBase64:
    def test_returns_none_when_no_logo_path(self) -> None:
        branding = BrandingConfig()
        assert branding.get_logo_base64() is None

    def test_returns_none_when_logo_file_missing(self, tmp_path: Path) -> None:
        branding = BrandingConfig(logo_path=tmp_path / "missing.png")
        assert branding.get_logo_base64() is None

    def test_returns_base64_data_uri_for_valid_png(self, tmp_path: Path) -> None:
        logo_path = tmp_path / "logo.png"
        _make_tiny_png(logo_path)
        branding = BrandingConfig(logo_path=logo_path)
        result = branding.get_logo_base64()
        assert result is not None
        assert result.startswith("data:image/png;base64,")

    def test_base64_string_is_non_empty(self, tmp_path: Path) -> None:
        logo_path = tmp_path / "logo.png"
        _make_tiny_png(logo_path)
        branding = BrandingConfig(logo_path=logo_path)
        result = branding.get_logo_base64()
        assert result is not None
        # Strip the prefix and verify there is actual data
        encoded_part = result.split(",", 1)[1]
        assert len(encoded_part) > 0

    def test_jpg_extension_produces_jpeg_mime(self, tmp_path: Path) -> None:
        # Write a dummy file with .jpg extension
        logo_path = tmp_path / "logo.jpg"
        logo_path.write_bytes(b"\xff\xd8\xff\xe0" + b"\x00" * 20)  # minimal JPEG-ish bytes
        branding = BrandingConfig(logo_path=logo_path)
        result = branding.get_logo_base64()
        assert result is not None
        assert result.startswith("data:image/jpeg;base64,")


# ---------------------------------------------------------------------------
# BrandingEngine.apply_to_report_data
# ---------------------------------------------------------------------------


class TestBrandingEngineApplyToReportData:
    def test_sets_company_name(self) -> None:
        branding = BrandingConfig(company_name="SecureCorp")
        engine = BrandingEngine(branding)
        data = _make_minimal_report_data()
        branded = engine.apply_to_report_data(data)
        assert branded.company_name == "SecureCorp"

    def test_does_not_mutate_original(self) -> None:
        branding = BrandingConfig(company_name="SecureCorp")
        engine = BrandingEngine(branding)
        data = _make_minimal_report_data()
        original_name = data.company_name
        _ = engine.apply_to_report_data(data)
        assert data.company_name == original_name

    def test_sets_logo_path_when_provided(self, tmp_path: Path) -> None:
        logo = tmp_path / "logo.png"
        _make_tiny_png(logo)
        branding = BrandingConfig(company_name="LogoCorp", logo_path=logo)
        engine = BrandingEngine(branding)
        data = _make_minimal_report_data()
        branded = engine.apply_to_report_data(data)
        assert branded.logo_path == str(logo)

    def test_logo_path_not_set_when_branding_has_none(self) -> None:
        branding = BrandingConfig(company_name="NoCorp", logo_path=None)
        engine = BrandingEngine(branding)
        data = _make_minimal_report_data()
        branded = engine.apply_to_report_data(data)
        # logo_path should remain whatever it was on the source (None or empty)
        assert branded.logo_path is None

    def test_sets_author_from_branding_email_when_author_empty(self) -> None:
        branding = BrandingConfig(
            company_name="Corp", company_email="team@corp.example"
        )
        engine = BrandingEngine(branding)
        data = _make_minimal_report_data()
        data.author = ""
        branded = engine.apply_to_report_data(data)
        assert branded.author == "team@corp.example"

    def test_does_not_overwrite_existing_author(self) -> None:
        branding = BrandingConfig(
            company_name="Corp", company_email="team@corp.example"
        )
        engine = BrandingEngine(branding)
        data = _make_minimal_report_data()
        data.author = "Jane Doe"
        branded = engine.apply_to_report_data(data)
        assert branded.author == "Jane Doe"


# ---------------------------------------------------------------------------
# BrandingEngine.get_css_overrides
# ---------------------------------------------------------------------------


class TestBrandingEngineGetCssOverrides:
    def test_contains_primary_color(self) -> None:
        branding = BrandingConfig(primary_color="#aabbcc")
        engine = BrandingEngine(branding)
        css = engine.get_css_overrides()
        assert "#aabbcc" in css

    def test_contains_accent_color(self) -> None:
        branding = BrandingConfig(accent_color="#112233")
        engine = BrandingEngine(branding)
        css = engine.get_css_overrides()
        assert "#112233" in css

    def test_contains_css_custom_property_syntax(self) -> None:
        engine = BrandingEngine(BrandingConfig())
        css = engine.get_css_overrides()
        assert "--primary-color" in css
        assert "--accent-color" in css

    def test_returns_string(self) -> None:
        engine = BrandingEngine(BrandingConfig())
        css = engine.get_css_overrides()
        assert isinstance(css, str)
        assert len(css) > 0


# ---------------------------------------------------------------------------
# BrandingEngine.apply_to_html
# ---------------------------------------------------------------------------


class TestBrandingEngineApplyToHtml:
    def test_replaces_company_name_placeholder(self) -> None:
        branding = BrandingConfig(company_name="AcmeSec")
        engine = BrandingEngine(branding)
        html = "<h1>{{ company_name }}</h1>"
        result = engine.apply_to_html(html)
        assert "AcmeSec" in result
        assert "{{ company_name }}" not in result

    def test_injects_css_before_head_close(self) -> None:
        branding = BrandingConfig(primary_color="#ff0000")
        engine = BrandingEngine(branding)
        html = "<html><head></head><body></body></html>"
        result = engine.apply_to_html(html)
        assert "<style>" in result
        assert "#ff0000" in result
