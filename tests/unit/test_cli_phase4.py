"""Unit tests for Phase 4 CLI commands: client sub-command group.

Verifies that all client sub-commands are registered, show valid --help
output, and document their arguments/options correctly.  No actual file I/O
or scan execution is performed.
"""

from __future__ import annotations

from typer.testing import CliRunner

from vxis.cli.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# client group
# ---------------------------------------------------------------------------


class TestClientGroupHelp:
    def test_client_group_exits_zero(self) -> None:
        """vxis client --help must exit 0."""
        result = runner.invoke(app, ["client", "--help"])
        assert result.exit_code == 0, (
            f"Expected exit code 0, got {result.exit_code}.\nOutput:\n{result.output}"
        )

    def test_client_group_lists_subcommands(self) -> None:
        """vxis client --help output must list sub-commands."""
        result = runner.invoke(app, ["client", "--help"])
        assert result.exit_code == 0
        output_lower = result.output.lower()
        # At least one of the expected sub-commands should appear
        assert any(cmd in output_lower for cmd in ("add", "list", "show", "remove", "scan")), (
            f"Expected sub-commands not found in output:\n{result.output}"
        )


# ---------------------------------------------------------------------------
# client add
# ---------------------------------------------------------------------------


class TestClientAddHelp:
    def test_add_exits_zero(self) -> None:
        result = runner.invoke(app, ["client", "add", "--help"])
        assert result.exit_code == 0, (
            f"Expected exit code 0.\nOutput:\n{result.output}"
        )

    def test_add_shows_name_argument(self) -> None:
        result = runner.invoke(app, ["client", "add", "--help"])
        assert result.exit_code == 0
        assert "name" in result.output.lower(), (
            f"'name' argument not found in help output:\n{result.output}"
        )

    def test_add_shows_domains_argument(self) -> None:
        result = runner.invoke(app, ["client", "add", "--help"])
        assert result.exit_code == 0
        assert "domain" in result.output.lower(), (
            f"'domains' argument not found in help output:\n{result.output}"
        )

    def test_add_shows_industry_option(self) -> None:
        result = runner.invoke(app, ["client", "add", "--help"])
        assert result.exit_code == 0
        assert "--industry" in result.output or "-i" in result.output, (
            f"--industry option not found in help output:\n{result.output}"
        )

    def test_add_shows_contact_option(self) -> None:
        result = runner.invoke(app, ["client", "add", "--help"])
        assert result.exit_code == 0
        assert "--contact" in result.output, (
            f"--contact option not found in help output:\n{result.output}"
        )

    def test_add_shows_email_option(self) -> None:
        result = runner.invoke(app, ["client", "add", "--help"])
        assert result.exit_code == 0
        assert "--email" in result.output, (
            f"--email option not found in help output:\n{result.output}"
        )


# ---------------------------------------------------------------------------
# client list
# ---------------------------------------------------------------------------


class TestClientListHelp:
    def test_list_exits_zero(self) -> None:
        result = runner.invoke(app, ["client", "list", "--help"])
        assert result.exit_code == 0, (
            f"Expected exit code 0.\nOutput:\n{result.output}"
        )

    def test_list_help_contains_description(self) -> None:
        result = runner.invoke(app, ["client", "list", "--help"])
        assert result.exit_code == 0
        # The help text should mention clients
        assert "client" in result.output.lower(), (
            f"Expected 'client' in list --help output:\n{result.output}"
        )


# ---------------------------------------------------------------------------
# client show
# ---------------------------------------------------------------------------


class TestClientShowHelp:
    def test_show_exits_zero(self) -> None:
        result = runner.invoke(app, ["client", "show", "--help"])
        assert result.exit_code == 0, (
            f"Expected exit code 0.\nOutput:\n{result.output}"
        )

    def test_show_mentions_client_id_argument(self) -> None:
        result = runner.invoke(app, ["client", "show", "--help"])
        assert result.exit_code == 0
        assert "client" in result.output.lower() or "id" in result.output.lower(), (
            f"Expected client ID mention in show --help:\n{result.output}"
        )


# ---------------------------------------------------------------------------
# client remove
# ---------------------------------------------------------------------------


class TestClientRemoveHelp:
    def test_remove_exits_zero(self) -> None:
        result = runner.invoke(app, ["client", "remove", "--help"])
        assert result.exit_code == 0, (
            f"Expected exit code 0.\nOutput:\n{result.output}"
        )

    def test_remove_mentions_client_id(self) -> None:
        result = runner.invoke(app, ["client", "remove", "--help"])
        assert result.exit_code == 0
        assert "client" in result.output.lower() or "id" in result.output.lower(), (
            f"Expected client ID mention in remove --help:\n{result.output}"
        )


# ---------------------------------------------------------------------------
# client scan
# ---------------------------------------------------------------------------


class TestClientScanHelp:
    def test_scan_exits_zero(self) -> None:
        result = runner.invoke(app, ["client", "scan", "--help"])
        assert result.exit_code == 0, (
            f"Expected exit code 0.\nOutput:\n{result.output}"
        )

    def test_scan_shows_profile_option(self) -> None:
        result = runner.invoke(app, ["client", "scan", "--help"])
        assert result.exit_code == 0
        assert "--profile" in result.output or "-p" in result.output, (
            f"--profile option not found in client scan --help:\n{result.output}"
        )

    def test_scan_mentions_client_id_argument(self) -> None:
        result = runner.invoke(app, ["client", "scan", "--help"])
        assert result.exit_code == 0
        assert "client" in result.output.lower() or "id" in result.output.lower(), (
            f"Expected client ID mention in scan --help:\n{result.output}"
        )


# ---------------------------------------------------------------------------
# Existing scan command still accepts --client option
# ---------------------------------------------------------------------------


class TestScanCommandClientOption:
    def test_scan_help_shows_client_option(self) -> None:
        """vxis scan --help must document the --client flag added in Phase 4."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--client" in result.output, (
            f"--client option not found in scan --help:\n{result.output}"
        )
