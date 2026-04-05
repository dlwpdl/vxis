"""Unit tests for the VXIS CLI using typer.testing.CliRunner."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from vxis.cli.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# version command
# ---------------------------------------------------------------------------


class TestVersionCommand:
    def test_version_outputs_version_string(self):
        """The version command prints 'VXIS v<version>'."""
        from vxis import __version__

        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0, result.output
        assert "VXIS" in result.output
        assert __version__ in result.output

    def test_version_contains_semver_format(self):
        """The version string follows a semver-like pattern (digits with dots)."""
        import re

        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        # Matches patterns like v0.1.0 or 0.1.0
        assert re.search(r"\d+\.\d+\.\d+", result.output)


# ---------------------------------------------------------------------------
# plugins command
# ---------------------------------------------------------------------------


class TestPluginsCommand:
    def test_plugins_cmd_exits_zero(self):
        """The plugins command exits with code 0 when no plugins are discovered."""
        with patch("vxis.plugins.registry.discover_plugins", return_value={}):
            result = runner.invoke(app, ["plugins"])
        assert result.exit_code == 0

    def test_plugins_cmd_with_check_flag(self):
        """The plugins --check flag exits with code 0 when no plugins are found."""
        with patch("vxis.plugins.registry.discover_plugins", return_value={}):
            result = runner.invoke(app, ["plugins", "--check"])
        assert result.exit_code == 0

    def test_plugins_cmd_displays_plugin_table(self):
        """When plugins exist, their names appear in the output table."""
        from vxis.plugins.base import BasePlugin, PluginMeta
        from vxis.core.context import DAGContext, PluginOutput

        class FakePlugin(BasePlugin):
            @property
            def meta(self) -> PluginMeta:
                return PluginMeta(
                    name="fake-nmap",
                    version="1.0.0",
                    tool_binary="nmap",
                    category="scan",
                )

            def build_command(self, target, scan_profile, ctx, tool_config):
                return f"nmap {target}"

            def parse_output(self, raw_stdout, raw_stderr):
                return PluginOutput(plugin_name="fake-nmap")

        fake_registry = {"fake-nmap": FakePlugin()}

        with patch("vxis.plugins.registry.discover_plugins", return_value=fake_registry):
            result = runner.invoke(app, ["plugins"])

        assert result.exit_code == 0
        assert "fake-nmap" in result.output

    def test_plugins_cmd_shows_availability_with_check(self):
        """With --check, the output includes availability status."""
        from vxis.plugins.base import BasePlugin, PluginMeta
        from vxis.core.context import PluginOutput

        class FakePlugin(BasePlugin):
            @property
            def meta(self) -> PluginMeta:
                return PluginMeta(
                    name="fake-tool",
                    version="2.0.0",
                    tool_binary="nonexistent_binary_xyz",
                    category="recon",
                )

            def build_command(self, target, scan_profile, ctx, tool_config):
                return "nonexistent_binary_xyz"

            def parse_output(self, raw_stdout, raw_stderr):
                return PluginOutput(plugin_name="fake-tool")

        fake_registry = {"fake-tool": FakePlugin()}

        with patch("vxis.plugins.registry.discover_plugins", return_value=fake_registry):
            result = runner.invoke(app, ["plugins", "--check"])

        assert result.exit_code == 0
        assert "fake-tool" in result.output
        # Binary not on PATH so 'no' should appear
        assert "no" in result.output


# ---------------------------------------------------------------------------
# scan command --help
# ---------------------------------------------------------------------------


class TestScanCommandHelp:
    def test_scan_help_exits_zero(self):
        """scan --help exits with code 0."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0

    def test_scan_help_shows_target_argument(self):
        """scan --help output mentions the target argument."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "target" in result.output.lower()

    def test_scan_help_shows_profile_option(self):
        """scan --help output mentions the --profile option."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--profile" in result.output or "profile" in result.output.lower()

    def test_scan_help_shows_plugins_option(self):
        """scan --help output mentions the --plugins option."""
        import re
        result = runner.invoke(app, ["scan", "--help"])
        clean = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
        assert "--plugins" in clean or "plugins" in clean.lower()

    def test_scan_help_shows_no_report_option(self):
        """scan --help output mentions the --no-report flag."""
        result = runner.invoke(app, ["scan", "--help"])
        assert "--no-report" in result.output


# ---------------------------------------------------------------------------
# scan command functional tests (mocked orchestrator)
# ---------------------------------------------------------------------------


class TestScanCommand:
    """Functional tests that stub out the orchestrator so no real tools run."""

    def _make_mock_result(self, target: str = "example.com"):
        """Build a minimal ScanResult mock."""
        from datetime import timedelta
        from vxis.core.orchestrator import ScanResult

        from datetime import datetime, timezone

        start = datetime.now(timezone.utc)
        return ScanResult(
            scan_id="aaaabbbb-cccc-dddd-eeee-ffffffffffff",
            target=target,
            profile="standard",
            findings=[],
            tool_runs=[],
            started_at=start,
            finished_at=start + timedelta(seconds=5),
        )

    def test_scan_exits_zero_on_success(self):
        """scan command returns exit code 0 when the scan completes."""
        mock_result = self._make_mock_result()

        with (
            patch("vxis.cli.main._get_config", return_value=MagicMock()),
            patch("vxis.core.orchestrator.ScanOrchestrator.__init__", return_value=None),
            patch(
                "vxis.core.orchestrator.ScanOrchestrator.run_scan",
                new_callable=AsyncMock,
                return_value=mock_result,
            ),
        ):
            result = runner.invoke(app, ["scan", "example.com", "--no-report"])

        assert result.exit_code == 0

    def test_scan_displays_target_in_output(self):
        """scan output includes the target name."""
        mock_result = self._make_mock_result("scanme.example.com")

        with (
            patch("vxis.cli.main._get_config", return_value=MagicMock()),
            patch("vxis.core.orchestrator.ScanOrchestrator.__init__", return_value=None),
            patch(
                "vxis.core.orchestrator.ScanOrchestrator.run_scan",
                new_callable=AsyncMock,
                return_value=mock_result,
            ),
        ):
            result = runner.invoke(
                app, ["scan", "scanme.example.com", "--no-report"]
            )

        assert "scanme.example.com" in result.output

    def test_scan_exits_one_on_invalid_profile(self):
        """scan returns exit code 1 when an invalid profile is provided."""
        with (
            patch("vxis.cli.main._get_config", return_value=MagicMock()),
            patch(
                "vxis.core.orchestrator.ScanOrchestrator.run_scan",
                new_callable=AsyncMock,
                side_effect=ValueError("Profile 'badprofile' not found."),
            ),
        ):
            result = runner.invoke(
                app, ["scan", "example.com", "--profile", "badprofile"]
            )

        assert result.exit_code == 1

    def test_scan_no_report_flag_suppresses_report_path(self):
        """With --no-report the report path message is not shown."""
        mock_result = self._make_mock_result()

        with (
            patch("vxis.cli.main._get_config", return_value=MagicMock()),
            patch(
                "vxis.core.orchestrator.ScanOrchestrator.run_scan",
                new_callable=AsyncMock,
                return_value=mock_result,
            ),
        ):
            result = runner.invoke(app, ["scan", "example.com", "--no-report"])

        # The "Report would be written to" message should not appear
        assert "Report would be written to" not in result.output


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


class TestReportCommand:
    def test_report_help_exits_zero(self):
        """report --help exits with code 0."""
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0

    def test_report_cmd_exits_zero(self):
        """report command exits with code 0 when report generates successfully."""
        with patch("vxis.cli.main.asyncio.run", return_value=None):
            result = runner.invoke(app, ["report", "42"])
        assert result.exit_code == 0

    def test_report_cmd_mentions_scan_id(self):
        """report output includes the provided scan ID."""
        result = runner.invoke(app, ["report", "abc-123"])
        assert "abc-123" in result.output


# ---------------------------------------------------------------------------
# Top-level app --help
# ---------------------------------------------------------------------------


class TestTopLevelHelp:
    def test_app_help_exits_zero(self):
        """vxis --help exits with code 0."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_app_help_lists_scan_command(self):
        """Top-level --help mentions the scan command."""
        result = runner.invoke(app, ["--help"])
        assert "scan" in result.output

    def test_app_help_lists_plugins_command(self):
        """Top-level --help mentions the plugins command."""
        result = runner.invoke(app, ["--help"])
        assert "plugins" in result.output

    def test_app_help_lists_version_command(self):
        """Top-level --help mentions the version command."""
        result = runner.invoke(app, ["--help"])
        assert "version" in result.output
