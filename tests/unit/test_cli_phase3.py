"""Unit tests for Phase 3 CLI commands: batch and export.

Verifies that the new commands are registered, have correct --help output,
and validate their inputs appropriately.
"""

from __future__ import annotations

from pathlib import Path
from typer.main import get_command
from typer.testing import CliRunner

from vxis.cli.main import app

runner = CliRunner()


def top_level_commands() -> set[str]:
    return set(get_command(app).commands)


def command_option_names(*path: str) -> set[str]:
    """Return registered option aliases without depending on Rich ANSI output."""
    command = get_command(app)
    for part in path:
        command = command.commands[part]
    names: set[str] = set()
    for param in command.params:
        names.update(getattr(param, "opts", ()) or ())
        names.update(getattr(param, "secondary_opts", ()) or ())
    return names


# ---------------------------------------------------------------------------
# batch command
# ---------------------------------------------------------------------------


class TestBatchCommand:
    def test_batch_help_shows_usage(self) -> None:
        """vxis batch --help must exit 0 and show usage information."""
        result = runner.invoke(app, ["batch", "--help"])

        assert result.exit_code == 0, (
            f"Expected exit code 0, got {result.exit_code}.\nOutput:\n{result.output}"
        )

    def test_batch_help_shows_csv_argument(self) -> None:
        """batch --help output must mention the csv-file argument."""
        result = runner.invoke(app, ["batch", "--help"])

        assert result.exit_code == 0
        output_lower = result.output.lower()
        # CSV file path argument should be described
        assert "csv" in output_lower, f"Expected 'csv' in help output, got:\n{result.output}"

    def test_batch_help_shows_profile_option(self) -> None:
        """batch command must register the --profile option."""
        names = command_option_names("batch")
        assert "--profile" in names
        assert "-p" in names

    def test_batch_help_shows_concurrent_option(self) -> None:
        """batch command must register the --concurrent option."""
        names = command_option_names("batch")
        assert "--concurrent" in names
        assert "-c" in names

    def test_batch_help_shows_output_option(self) -> None:
        """batch command must register the --output option."""
        names = command_option_names("batch")
        assert "--output" in names
        assert "-o" in names

    def test_batch_missing_csv_exits_nonzero(self, tmp_path: Path) -> None:
        """batch with a non-existent CSV file must exit with non-zero status."""
        missing = str(tmp_path / "does_not_exist.csv")
        result = runner.invoke(app, ["batch", missing])

        assert result.exit_code != 0, (
            f"Expected non-zero exit code for missing CSV, got 0.\nOutput:\n{result.output}"
        )

    def test_batch_is_registered_as_command(self) -> None:
        """'batch' must be a registered top-level CLI command."""
        assert "batch" in top_level_commands()


# ---------------------------------------------------------------------------
# export command
# ---------------------------------------------------------------------------


class TestExportCommand:
    def test_export_help_shows_usage(self) -> None:
        """vxis export --help must exit 0 and show usage information."""
        result = runner.invoke(app, ["export", "--help"])

        assert result.exit_code == 0, (
            f"Expected exit code 0, got {result.exit_code}.\nOutput:\n{result.output}"
        )

    def test_export_help_shows_scan_id_argument(self) -> None:
        """export --help must mention the scan-id argument."""
        result = runner.invoke(app, ["export", "--help"])

        assert result.exit_code == 0
        output_lower = result.output.lower()
        assert "scan" in output_lower or "id" in output_lower, (
            f"Expected scan id reference in help output:\n{result.output}"
        )

    def test_export_help_shows_format_option(self) -> None:
        """export command must register the --format option."""
        names = command_option_names("export")
        assert "--format" in names
        assert "-f" in names

    def test_export_help_shows_output_option(self) -> None:
        """export command must register the --output option."""
        names = command_option_names("export")
        assert "--output" in names
        assert "-o" in names

    def test_export_help_mentions_supported_formats(self) -> None:
        """export --help must mention at least one of the supported formats."""
        result = runner.invoke(app, ["export", "--help"])

        assert result.exit_code == 0
        # At least one supported format name must appear in the help text
        supported = ["docx", "html", "attestation"]
        mentioned = any(fmt in result.output.lower() for fmt in supported)
        assert mentioned, f"Expected one of {supported} in help output:\n{result.output}"

    def test_export_is_registered_as_command(self) -> None:
        """'export' must be a registered top-level CLI command."""
        assert "export" in top_level_commands()

    def test_export_invalid_format_exits_nonzero(self) -> None:
        """export with an unsupported format must exit with non-zero status."""
        result = runner.invoke(app, ["export", "scan-001", "--format", "pdf"])

        assert result.exit_code != 0, (
            f"Expected non-zero exit for unsupported format 'pdf', got 0.\nOutput:\n{result.output}"
        )

    def test_export_valid_format_docx_runs(self) -> None:
        """export with --format docx must not crash (even if DB lookup is a stub)."""
        result = runner.invoke(app, ["export", "scan-abc-123", "--format", "docx"])

        # May exit 0 or non-zero depending on DB availability; must not raise
        assert result.exception is None or isinstance(result.exception, SystemExit), (
            f"Unexpected exception: {result.exception}\nOutput:\n{result.output}"
        )

    def test_export_valid_format_attestation_runs(self) -> None:
        """export with --format attestation must not crash."""
        result = runner.invoke(app, ["export", "scan-abc-123", "--format", "attestation"])

        assert result.exception is None or isinstance(result.exception, SystemExit)

    def test_export_valid_format_html_runs(self) -> None:
        """export with --format html must not crash."""
        result = runner.invoke(app, ["export", "scan-abc-123", "--format", "html"])

        assert result.exception is None or isinstance(result.exception, SystemExit)
