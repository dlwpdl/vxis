"""VXIS CLI — entry point for the security automation platform.

Commands:
  scan      Run a security scan against a target.
  report    Generate a report from existing scan results.
  plugins   List available plugins and verify tool binaries.
  client    Manage clients (add / list / show / remove / scan).
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
# Client sub-command group
# ---------------------------------------------------------------------------

client_app = typer.Typer(help="Manage clients", no_args_is_help=True)
app.add_typer(client_app, name="client")

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
    client: Optional[str] = typer.Option(
        None,
        "--client",
        help="Client ID for branded report (loads client branding config)",
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

    from vxis.core.events import ScanEventBus, ScanSnapshotCollector
    from vxis.core.orchestrator import ScanOrchestrator
    from vxis.core.scope import ScopeViolationError
    from vxis.cli.live_display import ScanLiveDisplay

    event_bus = ScanEventBus()
    collector = ScanSnapshotCollector()
    event_bus.on_any(collector.handle_event)

    orchestrator = ScanOrchestrator(config, event_bus=event_bus)

    async def _run_with_live_display() -> "ScanResult":
        """Run the scan while updating the live TUI display."""
        scan_task = asyncio.create_task(
            orchestrator.run_scan(
                target=target,
                profile=profile,
                selected_plugins=selected_plugins,
            )
        )

        # Refresh loop: update TUI until scan finishes
        while not scan_task.done():
            display.update(collector.snapshot)
            await asyncio.sleep(0.25)

        # Final update
        display.update(collector.snapshot)
        return await scan_task

    display = ScanLiveDisplay(console)
    with display:
        try:
            result = asyncio.run(_run_with_live_display())
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
def batch(
    csv_file: Path = typer.Argument(help="CSV file with target portfolio"),
    profile: str = typer.Option(
        "standard",
        "--profile",
        "-p",
        help="Scan profile: passive | stealth | standard | aggressive",
    ),
    max_concurrent: int = typer.Option(
        3,
        "--concurrent",
        "-c",
        help="Maximum number of simultaneous scans",
    ),
    output_dir: Path = typer.Option(
        Path("./reports/batch"),
        "--output",
        "-o",
        help="Directory to write per-target and summary reports",
    ),
) -> None:
    """Batch scan multiple targets from a CSV portfolio file."""
    from vxis.core.batch import BatchScanner

    _print_banner()

    if not csv_file.exists():
        err_console.print(f"[bold red]Error:[/bold red] CSV file not found: {csv_file}")
        raise typer.Exit(code=1)

    config = _get_config()
    scanner = BatchScanner(config)

    try:
        targets = BatchScanner.load_targets(csv_file)
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[bold red]Failed to load CSV:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[bold]Batch scan:[/bold] {len(targets)} target(s) from "
        f"[cyan]{csv_file}[/cyan] using profile '[yellow]{profile}[/yellow]'"
    )
    console.print(
        f"[dim]Concurrency: {max_concurrent} | Output: {output_dir}[/dim]"
    )

    completed: list = []

    def _on_complete(result) -> None:
        completed.append(result)
        status = (
            "[green]OK[/green]"
            if result.succeeded
            else f"[red]FAILED[/red]: {result.error}"
        )
        console.print(
            f"  [{len(completed)}/{len(targets)}] "
            f"[cyan]{result.target.name}[/cyan] ({result.target.domain}) — {status}"
        )

    with console.status("[bold green]Running batch scan...[/bold green]", spinner="dots"):
        results = asyncio.run(
            scanner.run_batch(
                targets=targets,
                profile=profile,
                max_concurrent=max_concurrent,
                on_complete=_on_complete,
            )
        )

    # Generate per-target DOCX reports
    output_dir.mkdir(parents=True, exist_ok=True)

    from vxis.report.docx_export import DOCXReportGenerator
    from vxis.report.generator import ReportData
    from datetime import date

    docx_gen = DOCXReportGenerator()
    for result in results:
        if result.succeeded and result.scan_result:
            sr = result.scan_result
            report_data = ReportData(
                scan_id=sr.scan_id,
                client_name=result.target.name,
                target=result.target.domain,
                scan_date=date.today().isoformat(),
                findings=sr.findings,
            )
            safe_name = result.target.domain.replace(".", "_").replace("/", "_")
            docx_path = output_dir / f"{safe_name}.docx"
            try:
                docx_gen.generate(report_data, docx_path)
                console.print(f"  [dim]Report:[/dim] {docx_path}")
            except Exception as exc:  # noqa: BLE001
                err_console.print(
                    f"[yellow]Warning:[/yellow] Could not generate report for "
                    f"{result.target.name}: {exc}"
                )

    # Generate summary report
    summary_path = output_dir / "portfolio_summary.docx"
    try:
        scanner.generate_summary_report(results, summary_path)
        console.print(
            f"\n[bold green]Summary report:[/bold green] [underline]{summary_path}[/underline]"
        )
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[yellow]Warning:[/yellow] Could not generate summary report: {exc}")

    # Print final table
    success_count = sum(1 for r in results if r.succeeded)
    fail_count = len(results) - success_count
    console.print(
        f"\n[bold]Batch complete:[/bold] {success_count} succeeded, "
        f"{fail_count} failed out of {len(results)} target(s)."
    )


@app.command()
def export(
    scan_id: str = typer.Argument(help="Scan ID to export"),
    format: str = typer.Option(
        "docx",
        "--format",
        "-f",
        help="Output format: docx | html | attestation",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (default: ./<scan_id>.<format>)",
    ),
) -> None:
    """Export scan results to DOCX, HTML, or attestation letter."""
    supported_formats = {"docx", "html", "attestation"}
    if format not in supported_formats:
        err_console.print(
            f"[bold red]Unsupported format:[/bold red] '{format}'. "
            f"Choose from: {', '.join(sorted(supported_formats))}"
        )
        raise typer.Exit(code=1)

    # Resolve default output path
    ext_map = {"docx": "docx", "html": "html", "attestation": "docx"}
    ext = ext_map[format]
    out_path = output or Path(f"{scan_id}.{ext}")

    console.print(
        f"[bold]Exporting[/bold] scan [cyan]{scan_id}[/cyan] "
        f"as [yellow]{format}[/yellow] → [underline]{out_path}[/underline]"
    )

    # NOTE: Full database lookup is not yet wired — a ReportData must be
    # constructed from persisted scan records. The scaffolding below shows
    # where that lookup would occur once the DB query layer is extended.
    # For now we surface a clear informational message.
    console.print(
        "[yellow]Note:[/yellow] Database-backed scan retrieval is not yet implemented. "
        "Construct a ReportData object programmatically and pass it to "
        "DOCXReportGenerator or AttestationGenerator directly."
    )

    if format == "docx":
        console.print(
            "[dim]Use:[/dim] from vxis.report.docx_export import DOCXReportGenerator"
        )
    elif format == "attestation":
        console.print(
            "[dim]Use:[/dim] from vxis.report.attestation import AttestationGenerator"
        )
    elif format == "html":
        console.print(
            "[dim]Use:[/dim] from vxis.report.generator import ReportGenerator"
        )


@app.command()
def dashboard(
    host: str = typer.Option("127.0.0.1", "--host", help="Host address to bind"),
    port: int = typer.Option(8080, "--port", help="Port number to listen on"),
) -> None:
    """Launch the VXIS web dashboard."""
    import uvicorn
    from vxis.dashboard.app import app as dash_app

    console.print(
        f"[bold green]VXIS Dashboard[/bold green] running at "
        f"[underline cyan]http://{host}:{port}[/underline cyan]"
    )
    uvicorn.run(dash_app, host=host, port=port)


@app.command()
def version() -> None:
    """Show VXIS version information."""
    from vxis import __version__

    console.print(f"VXIS v{__version__}")


# ---------------------------------------------------------------------------
# Client sub-commands
# ---------------------------------------------------------------------------


def _get_client_manager():
    """Return a ClientManager pointed at the default clients directory."""
    from vxis.config.client_manager import ClientManager

    config = _get_config()
    clients_dir = config.data_dir / "clients"
    return ClientManager(clients_dir)


@client_app.command("add")
def client_add(
    name: str = typer.Argument(help="Client name (e.g. 'ACME Corporation')"),
    domains: str = typer.Argument(help="Comma-separated authorised target domains"),
    industry: str = typer.Option("", "--industry", "-i", help="Industry sector"),
    contact: str = typer.Option("", "--contact", help="Contact person name"),
    email: str = typer.Option("", "--email", help="Contact email address"),
) -> None:
    """Add a new client and persist its config as a TOML file."""
    from vxis.config.client_manager import Client, _slugify

    manager = _get_client_manager()
    domain_list = [d.strip() for d in domains.split(",") if d.strip()]
    client_id = _slugify(name)

    new_client = Client(
        id=client_id,
        name=name,
        domains=domain_list,
        industry=industry,
        contact_name=contact,
        contact_email=email,
    )

    try:
        path = manager.create_client(new_client)
        console.print(
            f"[bold green]Client added:[/bold green] [cyan]{name}[/cyan] "
            f"(id: [yellow]{client_id}[/yellow])\n"
            f"[dim]Config:[/dim] [underline]{path}[/underline]"
        )
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[bold red]Failed to add client:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc


@client_app.command("list")
def client_list() -> None:
    """List all managed clients with key metadata."""
    manager = _get_client_manager()
    clients = manager.list_clients()

    if not clients:
        console.print("[yellow]No clients found.[/yellow] Use [bold]vxis client add[/bold] to create one.")
        return

    table = Table(
        title="Managed Clients",
        show_header=True,
        header_style="bold",
        border_style="cyan",
        expand=False,
    )
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("Name", no_wrap=True)
    table.add_column("Domains")
    table.add_column("Industry", no_wrap=True)
    table.add_column("Contact")
    table.add_column("Created", no_wrap=True)

    for c in clients:
        table.add_row(
            c.id,
            c.name,
            ", ".join(c.domains) if c.domains else "—",
            c.industry or "—",
            c.contact_name or "—",
            c.created_at.strftime("%Y-%m-%d"),
        )

    console.print(table)
    console.print(f"\n[dim]{len(clients)} client(s) total.[/dim]")


@client_app.command("show")
def client_show(
    client_id: str = typer.Argument(help="Client ID slug (e.g. acme-corp)"),
) -> None:
    """Show detailed information for a specific client."""
    manager = _get_client_manager()
    c = manager.get_client(client_id)

    if c is None:
        err_console.print(f"[bold red]Client not found:[/bold red] {client_id}")
        raise typer.Exit(code=1)

    grid = Table.grid(padding=(0, 2))
    grid.add_column(style="bold dim", no_wrap=True)
    grid.add_column()

    grid.add_row("ID:", f"[cyan]{c.id}[/cyan]")
    grid.add_row("Name:", f"[bold]{c.name}[/bold]")
    grid.add_row("Domains:", ", ".join(c.domains) if c.domains else "—")
    grid.add_row("Exclude targets:", ", ".join(c.exclude_targets) or "—")
    grid.add_row(
        "Exclude ports:",
        ", ".join(str(p) for p in c.exclude_ports) if c.exclude_ports else "—",
    )
    grid.add_row("Industry:", c.industry or "—")
    grid.add_row("Contact:", c.contact_name or "—")
    grid.add_row("Email:", c.contact_email or "—")
    grid.add_row("Notes:", c.notes or "—")
    grid.add_row("Created:", c.created_at.strftime("%Y-%m-%d %H:%M UTC"))

    if c.branding:
        grid.add_row("Branding company:", c.branding.company_name)
        grid.add_row("Primary colour:", c.branding.primary_color)
        grid.add_row("Accent colour:", c.branding.accent_color)

    console.print(Panel(grid, title=f"Client: {c.name}", border_style="blue"))


@client_app.command("remove")
def client_remove(
    client_id: str = typer.Argument(help="Client ID slug to delete"),
) -> None:
    """Remove a client configuration."""
    manager = _get_client_manager()

    # Confirm the client exists first so we give a meaningful error
    existing = manager.get_client(client_id)
    if existing is None:
        err_console.print(f"[bold red]Client not found:[/bold red] {client_id}")
        raise typer.Exit(code=1)

    deleted = manager.delete_client(client_id)
    if deleted:
        console.print(
            f"[bold green]Removed client:[/bold green] [cyan]{client_id}[/cyan] "
            f"([dim]{existing.name}[/dim])"
        )
    else:
        err_console.print(f"[bold red]Failed to remove client:[/bold red] {client_id}")
        raise typer.Exit(code=1)


@client_app.command("scan")
def client_scan(
    client_id: str = typer.Argument(help="Client ID slug to scan"),
    profile: str = typer.Option(
        "standard",
        "--profile",
        "-p",
        help="Scan profile: passive | stealth | standard | aggressive",
    ),
) -> None:
    """Scan all of a client's authorised domains and generate branded reports."""
    from vxis.config.client_manager import ClientManager
    from vxis.core.orchestrator import ScanOrchestrator
    from vxis.core.scope import ScopeViolationError
    from vxis.report.branding_engine import BrandingEngine
    from vxis.report.generator import ReportData, ReportGenerator
    from datetime import date

    manager = _get_client_manager()
    c = manager.get_client(client_id)

    if c is None:
        err_console.print(f"[bold red]Client not found:[/bold red] {client_id}")
        raise typer.Exit(code=1)

    if not c.domains:
        err_console.print(
            f"[bold red]Client [cyan]{client_id}[/cyan] has no domains configured.[/bold red]"
        )
        raise typer.Exit(code=1)

    _print_banner()
    console.print(
        f"[bold]Scanning client:[/bold] [cyan]{c.name}[/cyan] "
        f"({len(c.domains)} domain(s)) | profile: [yellow]{profile}[/yellow]"
    )

    config = _get_config()
    orchestrator = ScanOrchestrator(config)

    # Optionally build branding engine if client has custom branding
    branding_engine: BrandingEngine | None = None
    if c.branding is not None:
        branding_engine = BrandingEngine(c.branding)

    report_gen = ReportGenerator()
    output_dir = config.report_output_dir / client_id
    output_dir.mkdir(parents=True, exist_ok=True)

    success_count = 0
    fail_count = 0

    for domain in c.domains:
        console.print(f"\n  [bold cyan]{domain}[/bold cyan] ...")
        try:
            result = asyncio.run(
                orchestrator.run_scan(
                    target=domain,
                    profile=profile,
                )
            )
        except (ScopeViolationError, ValueError) as exc:
            err_console.print(f"    [red]Skipped:[/red] {exc}")
            fail_count += 1
            continue
        except Exception as exc:  # noqa: BLE001
            err_console.print(f"    [red]Failed:[/red] {exc}")
            fail_count += 1
            continue

        # Build report data
        report_data = ReportData(
            scan_id=result.scan_id,
            client_name=c.name,
            target=domain,
            scan_date=date.today().isoformat(),
            findings=result.findings,
            company_name=c.branding.company_name if c.branding else config.report_company_name,
        )

        # Apply branding if configured
        if branding_engine is not None:
            report_data = branding_engine.apply_to_report_data(report_data)

        safe_domain = domain.replace(".", "_").replace("/", "_")
        report_path = output_dir / f"report_{safe_domain}.html"

        try:
            html = report_gen.render_html(report_data)
            if branding_engine is not None:
                html = branding_engine.apply_to_html(html)
            report_path.write_text(html, encoding="utf-8")
            console.print(
                f"    [green]Done[/green] — {len(result.findings)} finding(s) | "
                f"Report: [underline]{report_path}[/underline]"
            )
            success_count += 1
        except Exception as exc:  # noqa: BLE001
            err_console.print(f"    [yellow]Warning:[/yellow] Report generation failed: {exc}")
            success_count += 1  # scan itself succeeded

    console.print(
        f"\n[bold]Client scan complete:[/bold] {success_count} succeeded, "
        f"{fail_count} failed out of {len(c.domains)} domain(s)."
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point registered in pyproject.toml."""
    app()


if __name__ == "__main__":
    main()
