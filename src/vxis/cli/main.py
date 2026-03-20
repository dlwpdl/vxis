"""VXIS CLI — entry point for the security automation platform.

Commands:
  scan      Run a security scan against a target.
  report    Generate a report from existing scan results.
  plugins   List available plugins and verify tool binaries.
  version   Show VXIS version.
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

app = typer.Typer(
    name="vxis",
    help="VXIS — AI-powered security automation platform",
    no_args_is_help=True,
    pretty_exceptions_enable=False,
)
console = Console()
err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

_BANNER = r"""
 __   __ __  __  ____
 \ \ / /|  \/  ||_ _|
  \ V / | |\/| | | |
   \_/  |_|  |_||___|
"""


def _print_banner() -> None:
    """Render the VXIS ASCII banner using Rich."""
    console.print(
        Panel(
            Text(_BANNER.strip(), style="bold cyan", justify="center"),
            subtitle="[dim]AI-powered security automation platform[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_config():
    """Load and return the default VXISConfig.

    Importing here avoids circular imports and keeps startup fast when the
    caller only needs --help output.
    """
    from vxis.config.schema import VXISConfig

    return VXISConfig()


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: str = typer.Argument(help="Target domain or IP address"),
    profile: str = typer.Option(
        "standard",
        "--profile",
        "-p",
        help="Scan profile: passive | stealth | standard | aggressive",
    ),
    plugins: Optional[str] = typer.Option(
        None,
        "--plugins",
        help="Comma-separated list of plugin names to run (default: all)",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to write the HTML report (default: ./report_<target>.html)",
    ),
    no_report: bool = typer.Option(
        False,
        "--no-report",
        help="Skip report generation after the scan",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose (DEBUG) logging",
    ),
) -> None:
    """Run a security scan against the target."""
    # Configure logging level
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    _print_banner()

    # Parse optional plugin list
    selected_plugins: list[str] | None = None
    if plugins:
        selected_plugins = [p.strip() for p in plugins.split(",") if p.strip()]

    # Display scan parameters
    param_table = Table.grid(padding=(0, 2))
    param_table.add_column(style="bold", no_wrap=True)
    param_table.add_column()
    param_table.add_row("Target:", f"[cyan]{target}[/cyan]")
    param_table.add_row("Profile:", f"[yellow]{profile}[/yellow]")
    if selected_plugins:
        param_table.add_row("Plugins:", ", ".join(selected_plugins))
    console.print(Panel(param_table, title="Scan Parameters", border_style="blue"))

    # --- Run scan ---
    config = _get_config()

    from vxis.core.orchestrator import ScanOrchestrator
    from vxis.core.scope import ScopeViolationError

    orchestrator = ScanOrchestrator(config)

    with console.status(
        f"[bold green]Scanning [cyan]{target}[/cyan] ...[/bold green]",
        spinner="dots",
    ):
        try:
            result = asyncio.run(
                orchestrator.run_scan(
                    target=target,
                    profile=profile,
                    selected_plugins=selected_plugins,
                )
            )
        except ScopeViolationError as exc:
            err_console.print(f"[bold red]Scope violation:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc
        except ValueError as exc:
            err_console.print(f"[bold red]Configuration error:[/bold red] {exc}")
            raise typer.Exit(code=1) from exc
        except Exception as exc:  # noqa: BLE001
            err_console.print(f"[bold red]Scan failed:[/bold red] {exc}")
            if verbose:
                console.print_exception()
            raise typer.Exit(code=1) from exc

    # --- Results summary table ---
    severity_order = ["critical", "high", "medium", "low", "informational"]
    severity_styles = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "informational": "dim",
    }

    summary_table = Table(
        title=f"Scan Results — {result.scan_id[:8]}",
        show_header=True,
        header_style="bold",
        border_style="green",
        expand=False,
    )
    summary_table.add_column("Severity", style="bold", no_wrap=True)
    summary_table.add_column("Count", justify="right")

    counts = result.severity_counts
    for sev in severity_order:
        count = counts.get(sev, 0)
        style = severity_styles.get(sev, "")
        summary_table.add_row(
            f"[{style}]{sev.capitalize()}[/{style}]",
            f"[{style}]{count}[/{style}]",
        )

    console.print(summary_table)

    # Tool run status table
    if result.tool_runs:
        run_table = Table(
            title="Plugin Execution Summary",
            show_header=True,
            header_style="bold dim",
            border_style="dim",
            expand=False,
        )
        run_table.add_column("Plugin", no_wrap=True)
        run_table.add_column("State", no_wrap=True)
        run_table.add_column("Duration", justify="right")

        state_styles = {
            "completed": "green",
            "failed": "red",
            "timed_out": "yellow",
            "skipped": "dim",
            "running": "cyan",
            "pending": "dim",
        }

        for run in result.tool_runs:
            state = run.get("state", "unknown")
            duration = run.get("duration_seconds")
            style = state_styles.get(state, "")
            duration_str = f"{duration:.1f}s" if duration is not None else "—"
            run_table.add_row(
                run["plugin"],
                f"[{style}]{state}[/{style}]",
                duration_str,
            )

        console.print(run_table)

    # Duration summary
    console.print(
        f"\n[bold green]Scan completed[/bold green] in "
        f"[cyan]{result.duration_seconds:.1f}s[/cyan]  |  "
        f"[bold]{len(result.findings)}[/bold] finding(s) after dedup + FP filtering"
    )

    # --- Report generation ---
    if not no_report:
        report_path = output or Path(f"report_{target.replace('/', '_')}.html")
        # Report generation is wired up when the report module is available.
        # For now, note the intended path.
        console.print(
            f"[dim]Report would be written to:[/dim] [underline]{report_path}[/underline]"
        )


@app.command()
def report(
    scan_id: str = typer.Argument(help="Scan ID (UUID) to generate a report for"),
    output: Path = typer.Option(
        Path("./report.html"),
        "--output",
        "-o",
        help="Path to write the HTML report",
    ),
    template: str = typer.Option(
        "default.html",
        "--template",
        "-t",
        help="Report template name",
    ),
) -> None:
    """Generate an HTML report from existing scan results."""
    console.print(
        f"[bold]Generating report[/bold] for scan [cyan]{scan_id}[/cyan] "
        f"using template '[yellow]{template}[/yellow]' ...",
    )
    console.print(
        f"[dim]Output path:[/dim] [underline]{output}[/underline]"
    )
    # Report generation module wired in Phase 1+.
    console.print("[yellow]Report generation not yet implemented.[/yellow]")


@app.command(name="plugins")
def plugins_cmd(
    check: bool = typer.Option(
        False,
        "--check",
        help="Verify that each plugin's tool binary is available on PATH",
    ),
) -> None:
    """List available plugins and (optionally) verify tool binaries."""
    from vxis.plugins.registry import discover_plugins

    registry = discover_plugins()

    table = Table(
        title="Available Plugins",
        show_header=True,
        header_style="bold",
        border_style="blue",
        expand=False,
    )
    table.add_column("Name", no_wrap=True, style="bold cyan")
    table.add_column("Version", no_wrap=True)
    table.add_column("Category", no_wrap=True)
    table.add_column("Binary", no_wrap=True)
    table.add_column("Dependencies")

    if check:
        table.add_column("Available", no_wrap=True)

    for name, plugin in sorted(registry.items()):
        meta = plugin.meta
        deps = ", ".join(meta.depends_on) if meta.depends_on else "—"

        row: list[str] = [
            name,
            meta.version,
            meta.category,
            meta.tool_binary,
            deps,
        ]

        if check:
            available = plugin.validate_environment()
            status = "[green]yes[/green]" if available else "[red]no[/red]"
            row.append(status)

        table.add_row(*row)

    if registry:
        console.print(table)
    else:
        console.print(
            "[yellow]No plugins discovered. "
            "Ensure vxis.plugins sub-packages contain concrete BasePlugin subclasses.[/yellow]"
        )

    console.print(f"\n[dim]{len(registry)} plugin(s) found.[/dim]")


@app.command()
def version() -> None:
    """Show VXIS version information."""
    from vxis import __version__

    console.print(f"VXIS v{__version__}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point registered in pyproject.toml."""
    app()


if __name__ == "__main__":
    main()
