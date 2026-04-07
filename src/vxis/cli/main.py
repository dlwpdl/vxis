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
    no_args_is_help=False,
    invoke_without_command=True,
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
# Database migration sub-command group
# ---------------------------------------------------------------------------

db_app = typer.Typer(help="Database migration helpers (Alembic)", no_args_is_help=True)
app.add_typer(db_app, name="db")

# ---------------------------------------------------------------------------
# ASCII banner
# ---------------------------------------------------------------------------

_BANNER = r"""
__     __ __  __ ___  ____
\ \   / / \ \/ /|_ _|/ ___|
 \ \ / /   \  /  | | \___ \
  \ V /    /  \ _| |_ ___) |
   \_/    /_/\_\_____|____/
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


@app.callback()
def _app_callback(ctx: typer.Context) -> None:
    """인자 없이 vxis 실행 시 인터랙티브 모드 진입."""
    if ctx.invoked_subcommand is None:
        try:
            from vxis.cli.interactive import run_interactive
            run_interactive()
        except ImportError:
            # InquirerPy 미설치 시 기존 help 표시
            console.print("[yellow]인터랙티브 모드를 사용하려면: pip install InquirerPy[/yellow]")
            ctx.invoke(app, ["--help"])
        raise typer.Exit()


# ---------------------------------------------------------------------------
# Help — 전체 사용법 가이드
# ---------------------------------------------------------------------------


@app.command()
def help() -> None:
    """VXIS 전체 사용법 가이드 — 스캔, 리포트, 타겟, 파이프라인, 벤치마크."""
    _print_banner()

    from vxis.registry import (
        VERSION, WEB_PHASES, EXTERNAL_PHASES, FUTURE_PHASES,
        BENCHMARK_TARGETS, STAGE_NAMES,
    )
    from rich.markdown import Markdown
    from rich.table import Table

    console.print(f"  [bold]v{VERSION}[/bold]\n")

    guide = """## 스캔

```bash
# 벤치마크 스캔 (스코어링 + HTML 리포트 자동 생성)
python tools/growth_loop_runner.py --targets mutillidae --iterations 1

# 여러 타겟
python tools/growth_loop_runner.py --targets dvwa,juice-shop,webgoat --iterations 1

# 시간 제한 (KST 06시까지 반복)
python tools/growth_loop_runner.py --targets dvwa --until 06:00

# CLI 직접 스캔 (Brain-First 파이프라인)
vxis scan http://localhost:8081                    # LLM API Brain 자율 실행
vxis scan http://localhost:8081 --interactive      # Claude Code가 Brain (MCP)
vxis scan http://localhost:8081 -g                 # Ghost 익명화 켜기
vxis scan http://localhost:8081 --resume <ckpt>    # 체크포인트 재개
```

## 리포트

```bash
vxis report <SCAN_ID> -o reports/output.html
vxis export <SCAN_ID> --format docx                # DOCX/JSON/CSV/Attestation
```

## Self-Growth Intelligence (`vxis news`)

```bash
vxis news pending              # 검토 대기 중인 자가성장 제안
vxis news show <PROPOSAL_ID>   # 제안 상세 보기
vxis news approve <PROPOSAL_ID># 수동 승인 → 자동 적용
vxis news reject <PROPOSAL_ID> # 거부
vxis news rollback <PROPOSAL_ID>
vxis news digest --days 7      # 주간 요약
vxis news stats                # 부트스트랩 모드 + 누적 통계
```

## MCP 서버 (외부 Brain 연동)

```bash
# Claude Code에 VXIS를 도구로 등록
claude mcp add vxis python -m vxis.mcp_server

# 41개 primitive 툴 노출: sense_*/pattern_*/kb_*/session_*/
#   ghost_*/chain_*/output_*/phase_*/scope_*
```

## 기타 명령어

```bash
vxis plugins          # 플러그인 목록
vxis setup            # 도구 설치 현황
vxis diff <ID1> <ID2> # 두 스캔 비교
vxis trend '*'        # 전체 타겟 점수 추이
vxis dashboard        # 웹 대시보드
vxis kb               # 취약점 지식베이스
vxis schedule         # 지속 모니터링 스케줄
vxis client           # 클라이언트 관리
vxis integrations     # Slack/Discord/Jira/Linear/GitHub
vxis version          # 버전 정보
```
"""
    console.print(Markdown(guide))

    # ── Pipeline Phases (registry에서 동적 생성) ──
    console.print("\n[bold]Pipeline Phases[/bold]\n")
    phase_table = Table(show_header=True, header_style="bold cyan")
    phase_table.add_column("Phase", width=8)
    phase_table.add_column("Name", width=45)
    phase_table.add_column("Stage", width=20)

    prev_stage = ""
    for p in WEB_PHASES:
        stage_label = STAGE_NAMES.get(p.stage, p.stage)
        if p.stage != prev_stage:
            phase_table.add_row("", "", "", style="dim")
            prev_stage = p.stage
        phase_table.add_row(f"P{p.id}", p.name, stage_label)

    phase_table.add_row("", "", "", style="dim")
    for p in EXTERNAL_PHASES:
        phase_table.add_row(f"P{p.id}", f"{p.name} [dim](GHA)[/dim]", "External", style="dim")
    for p in FUTURE_PHASES:
        phase_table.add_row(f"P{p.id}", f"{p.name} [dim](planned)[/dim]", "Future", style="dim")

    console.print(phase_table)

    # ── Benchmark Targets (registry에서 동적 생성) ──
    console.print("\n[bold]Benchmark Targets[/bold]\n")
    target_table = Table(show_header=True, header_style="bold cyan")
    target_table.add_column("Name", width=12)
    target_table.add_column("Port", width=10)
    target_table.add_column("Category", width=10)
    target_table.add_column("Description", width=30)
    target_table.add_column("Docker", width=30)

    for t in BENCHMARK_TARGETS:
        port = t.port.split(":")[0]
        docker_cmd = f"docker run -d -p {t.port} {t.image}" if t.image else f"docker compose ({t.compose})"
        target_table.add_row(t.name, port, t.category, t.description, docker_cmd)

    console.print(target_table)


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


def _convert_finding_records(records) -> list:
    """Convert a list of FindingRecord ORM rows to Pydantic Finding models.

    Mirrors the conversion logic used in the dashboard module so that CLI
    report generation produces identical Finding objects.
    """
    from vxis.models.finding import (
        CVSSVector,
        Evidence,
        Finding,
        FindingStatus,
        MitreAttack,
        Reference,
        Severity,
    )

    findings: list[Finding] = []
    for rec in records:
        cvss = None
        if rec.cvss_score is not None and rec.cvss_vector:
            cvss = CVSSVector(vector_string=rec.cvss_vector, base_score=rec.cvss_score)

        mitre = None
        if rec.mitre_attack:
            mitre = MitreAttack(**rec.mitre_attack)

        evidence = [Evidence(**e) for e in (rec.evidence or [])]
        references = [Reference(**r) for r in (rec.references or [])]

        findings.append(
            Finding(
                id=str(rec.id),
                scan_id=str(rec.scan_id),
                title=rec.title,
                description=rec.description,
                severity=Severity(rec.severity),
                status=FindingStatus(rec.status),
                target=rec.target,
                affected_component=rec.affected_component or "",
                port=rec.port,
                protocol=rec.protocol,
                finding_type=rec.finding_type,
                cvss=cvss,
                cve_ids=rec.cve_ids or [],
                cwe_ids=rec.cwe_ids or [],
                mitre_attack=mitre,
                source_plugin=rec.source_plugin,
                source_plugins=rec.source_plugins or [],
                confidence=rec.confidence,
                evidence=evidence,
                remediation=rec.remediation,
                references=references,
                analyst_severity=Severity(rec.analyst_severity)
                if rec.analyst_severity
                else None,
                analyst_notes=rec.analyst_notes,
                discovered_at=rec.discovered_at,
                updated_at=rec.updated_at,
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: str = typer.Argument(help="Target URL or domain"),
    profile: str = typer.Option(
        "standard",
        "--profile",
        "-p",
        help="Scan profile: stealth | standard | aggressive",
    ),
    ghost: bool = typer.Option(
        False,
        "--ghost",
        "-g",
        help="Ghost mode — 프록시 로테이션 + UA 위장 + 타이밍 지연",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to write the HTML report (default: reports/report_<target>_<date>.html)",
    ),
    resume: Optional[str] = typer.Option(
        None,
        "--resume",
        help="Resume from checkpoint file (skip completed phases)",
    ),
    interactive: bool = typer.Option(
        False,
        "--interactive",
        "-i",
        help="Claude Code가 Brain으로 작동 (stdin/stdout JSON)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose (DEBUG) logging",
    ),
    allow_inject: bool = typer.Option(
        False,
        "--allow-inject",
        help="Skip the interactive approval gate and auto-approve injection. "
             "ONLY use on targets you own / are explicitly authorized to test.",
    ),
) -> None:
    """Run a Brain-First security scan against the target.

    \b
    기본: LLM API Brain이 20 Phase 파이프라인을 자율 실행
    --interactive: Claude Code가 Brain (stdin/stdout JSON 프로토콜)
    --resume: 이전 스캔의 체크포인트에서 재개
    """
    # Logging policy: TUI(non-interactive)는 로그를 파일로 보냄 → Live 간섭 0
    # interactive 모드는 stdin/stdout이 JSON 프로토콜이라 stderr로 보내야 함
    log_level = logging.DEBUG if verbose else logging.INFO
    log_path: Optional[Path] = None

    if interactive:
        logging.basicConfig(
            stream=sys.stderr,
            level=log_level,
            format="%(asctime)s [%(name)s] %(message)s",
            datefmt="%H:%M:%S",
        )
    else:
        # Route ALL logs to file so Rich Live TUI is never interrupted
        from datetime import datetime as _dt
        log_dir = Path("logs")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_path = log_dir / f"scan_{_dt.now().strftime('%Y%m%d_%H%M%S')}.log"

        # Reset any previous handlers (re-runs in same session)
        root_logger = logging.getLogger()
        for h in list(root_logger.handlers):
            root_logger.removeHandler(h)

        file_handler = logging.FileHandler(log_path, mode="w", encoding="utf-8")
        file_handler.setLevel(log_level)
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        root_logger.addHandler(file_handler)
        root_logger.setLevel(log_level)
        # Silence noisy library loggers from polluting the file too much
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    _print_banner()

    from vxis.registry import VERSION, WEB_PHASES
    from vxis.cli.preflight import run_preflight
    from vxis.cli.scan_display import ScanLiveDisplay

    # ── Pre-flight checks ──────────────────────────────────
    console.print("[dim]Running pre-flight checks...[/dim]")
    pf = run_preflight(target, ghost=ghost, interactive=interactive)

    pf_table = Table.grid(padding=(0, 2))
    pf_table.add_column(style="bold", no_wrap=True)
    pf_table.add_column()
    _t_status = f"[green]✓ {pf.target_latency_ms:.0f}ms[/green]" if pf.target_reachable else "[red]✗ unreachable[/red]"
    pf_table.add_row("Target:", f"[cyan]{target}[/cyan] {_t_status}")
    _b_status = f"[green]✓ {pf.brain_backend}[/green]" if pf.brain_ready else "[red]✗ no Brain[/red]"
    pf_table.add_row("Brain:", _b_status)
    _d_status = "[green]✓ available[/green]" if pf.docker_available else "[yellow]⚠ not available[/yellow]"
    pf_table.add_row("Docker:", _d_status)
    _g_status = "[green]✓ set[/green]" if pf.github_token else "[yellow]⚠ not set[/yellow]"
    pf_table.add_row("GitHub Token:", _g_status)
    if ghost:
        _p_status = f"[green]✓ {pf.proxy_pool_size} proxies[/green]" if pf.proxy_pool_size else "[yellow]⚠ empty pool (UA only)[/yellow]"
        pf_table.add_row("Proxy Pool:", _p_status)
    if log_path is not None:
        pf_table.add_row("Logs:", f"[dim]{log_path}[/dim] (tail -f to follow)")

    console.print(Panel(pf_table, title="Pre-flight", border_style="cyan"))

    if pf.warnings:
        for w in pf.warnings:
            console.print(f"  [yellow]⚠ {w}[/yellow]")

    if pf.errors:
        for e in pf.errors:
            err_console.print(f"  [red]✗ {e}[/red]")

    if not pf.can_scan:
        err_console.print("\n[bold red]Pre-flight failed. Fix errors above and retry.[/bold red]")
        raise typer.Exit(code=2)

    # ── Live display 준비 ───────────────────────────────────
    brain_label = "Claude Code" if interactive else pf.brain_backend
    display = ScanLiveDisplay(console, target, profile, brain_label, ghost, VERSION)
    display.init_phases(WEB_PHASES)

    ctx = None

    async def _run():
        nonlocal ctx
        from vxis.pipeline.pipeline import ScanPipeline

        if interactive:
            from vxis.agent.brain_interactive import InteractiveBrain
            brain = InteractiveBrain()
        else:
            from vxis.agent.brain import AgentBrain
            brain = AgentBrain()

        # Config + 환경변수로 profile/ghost 전파
        import os as _os
        _os.environ["VXIS_SCAN_PROFILE"] = profile
        if ghost:
            _os.environ["VXIS_GHOST"] = "1"

        config = None
        try:
            from vxis.config.schema import VXISConfig
            config = VXISConfig()
            config.active_profile = profile
        except Exception:
            pass

        _target = f"ghost://{target}" if ghost and not target.startswith("ghost://") else target

        # Live refresh 루프 — pipeline 진행 중 주기적 refresh
        import asyncio as _aio

        async def _refresh_loop():
            while True:
                display.refresh()
                await _aio.sleep(0.25)

        # ── Injection approval gate: 알려진 벤치마크 자동 통과, 그 외 사용자 승인 필수 ──
        _BENCHMARK_PORTS = {"8081", "3000", "8888", "8082", "8083", "5013", "4000"}
        _BENCHMARK_HOSTS = {"localhost", "127.0.0.1"}
        _t_lower = target.lower()
        _is_benchmark = (
            allow_inject  # 명시적 우회 — 책임은 사용자
            or any(f":{port}" in _t_lower for port in _BENCHMARK_PORTS)
            and any(h in _t_lower for h in _BENCHMARK_HOSTS)
        )

        async def _injection_gate(summary: dict) -> str:
            """Live TUI를 잠시 멈추고 3-way 선택: full / readonly / deny."""
            # Live 정지
            try:
                if display._live is not None:
                    display._live.stop()
            except Exception:
                pass

            console.print()
            console.print(Panel.fit(
                f"[bold red]⚠ INJECTION APPROVAL REQUIRED[/bold red]\n\n"
                f"Target: [cyan]{summary.get('target')}[/cyan]\n"
                f"Title:  {summary.get('title') or '(none)'}\n"
                f"Frameworks: {', '.join(summary.get('frameworks') or []) or '(none)'}\n"
                f"Phases to run: {summary.get('phase_count')} "
                f"(SQLi/XSS/RCE/SSRF/Path/Cmd 등)\n\n"
                f"[bold]Choose mode:[/bold]\n"
                f"  [green]R[/green] = [green]read-only[/green] (GET/HEAD probes only; POST/PUT/DELETE go to deferred queue)\n"
                f"  [yellow]F[/yellow] = [yellow]full[/yellow] (all HTTP methods auto-execute — may MUTATE DATA)\n"
                f"  [red]N[/red] = [red]deny[/red] (skip injection entirely, recon-only)\n\n"
                f"[dim]Default is R (safest). F on customer products can DELETE/MODIFY real data.[/dim]",
                title="VXIS Safety Gate",
                border_style="red",
            ))
            try:
                answer = input("Mode? [R]eadonly / [F]ull / [N]o (default R): ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                answer = ""

            if answer in ("f", "full", "yes", "y"):
                mode = "full"
                console.print("[yellow]⚠ FULL mode — all methods will auto-execute[/yellow]")
            elif answer in ("n", "no", "deny"):
                mode = "deny"
                console.print("[red]❌ DENIED — recon-only[/red]")
            else:
                mode = "readonly"
                console.print("[green]✅ READ-ONLY mode — GET/HEAD only; mutations deferred to end-of-scan approval[/green]")
            console.print()

            # Live 재시작
            try:
                display.__enter__()
            except Exception:
                pass
            return mode

        async def _deferred_approval(actions: list) -> list[bool]:
            """Per-action y/N prompt for data-mutating operations.

            Pauses the Live TUI, shows each queued action with risk level,
            method, URL and payload, and returns a list of booleans aligned
            with the input list.
            """
            try:
                if display._live is not None:
                    display._live.stop()
            except Exception:
                pass

            console.print()
            console.print(Panel.fit(
                f"[bold yellow]⚠ DATA-MUTATING ACTIONS — PER-ACTION APPROVAL[/bold yellow]\n\n"
                f"Brain queued [cyan]{len(actions)}[/cyan] requests that would "
                f"mutate data (POST/PUT/PATCH/DELETE).\n"
                f"You will be asked to approve each one individually.\n\n"
                f"[dim]Press Enter (or n) to DENY — safe default.[/dim]",
                title="Deferred Action Approval",
                border_style="yellow",
            ))

            approvals: list[bool] = []
            for action in actions:
                risk_icon = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(action.risk, "⚪")
                console.print(
                    f"\n  {risk_icon} [bold]#{action.id}[/bold] "
                    f"[{action.risk.upper()}] "
                    f"[cyan]{action.method}[/cyan] "
                    f"{action.url}"
                )
                console.print(f"     [dim]{action.description_en[:140]}[/dim]")
                if action.data:
                    import json as _j
                    data_preview = _j.dumps(action.data, ensure_ascii=False)[:200]
                    console.print(f"     [dim]data:[/dim] {data_preview}")

                try:
                    answer = input("     Approve? (y/N): ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    answer = ""
                ok = answer in ("y", "yes")
                approvals.append(ok)
                console.print(
                    f"     [{'green' if ok else 'red'}]"
                    f"{'✅ APPROVED' if ok else '❌ DENIED'}[/]"
                )

            _apv = sum(approvals)
            console.print(
                f"\n[bold]Summary:[/bold] {_apv}/{len(actions)} approved, "
                f"{len(actions) - _apv} denied\n"
            )

            try:
                display.__enter__()
            except Exception:
                pass
            return approvals

        pipeline = ScanPipeline(
            brain=brain,
            config=config,
            event_callback=display.handle_event,
            injection_approval_callback=_injection_gate,
            approval_callback=_deferred_approval,
            auto_approve_injection=_is_benchmark,
        )

        refresh_task = _aio.create_task(_refresh_loop())
        try:
            ctx = await pipeline.run(target=_target, resume_from=resume)
        finally:
            refresh_task.cancel()
            try:
                await refresh_task
            except _aio.CancelledError:
                pass

        # findings severity 카운팅
        for f in ctx.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            display.findings_count[sev] = display.findings_count.get(sev, 0) + 1
        display.total_findings = len(ctx.findings)
        display.refresh()

    try:
        with display:
            asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        raise typer.Exit(code=130)
    except Exception as exc:
        err_console.print(f"\n[bold red]Scan failed:[/bold red] {exc}")
        if verbose:
            console.print_exception()
        raise typer.Exit(code=1) from exc

    if ctx is None:
        err_console.print("[bold red]Scan produced no context[/bold red]")
        raise typer.Exit(code=1)

    # --- Final Results (Live display 종료 후) ---
    console.print()  # spacing after live display

    severity_order = ["critical", "high", "medium", "low", "informational"]
    severity_styles = {
        "critical": "bold red", "high": "red", "medium": "yellow",
        "low": "blue", "informational": "dim",
    }

    # Findings detail table
    if ctx.findings:
        finding_table = Table(
            title=f"[bold]Findings — {ctx.scan_id}[/bold]",
            show_header=True, header_style="bold",
            border_style="green",
        )
        finding_table.add_column("ID", no_wrap=True, width=12)
        finding_table.add_column("Severity", no_wrap=True, width=10)
        finding_table.add_column("Title", max_width=55)
        finding_table.add_column("Component", max_width=30, style="dim")

        for f in ctx.findings:
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev = sev_val.upper()
            style = severity_styles.get(sev_val, "")
            title = f.title.split("|||")[0][:55]
            finding_table.add_row(f.id, f"[{style}]{sev}[/{style}]", title, f.affected_component[:30])

        console.print(finding_table)
    else:
        console.print(Panel(
            "[yellow]No findings discovered.[/yellow]\n"
            "[dim]This could mean: target is well-secured, scan was limited, "
            "or pre-flight issues prevented full execution.[/dim]",
            title="No Findings",
            border_style="yellow",
        ))

    # Score
    vxis_score = getattr(ctx, "vxis_score", None)
    if vxis_score:
        score_color = "green" if vxis_score.total >= 700 else ("yellow" if vxis_score.total >= 400 else "red")
        console.print(
            f"\n[bold]VXIS Score:[/bold] "
            f"[{score_color}]{vxis_score.total:.1f}/1000[/{score_color}] "
            f"[bold]{vxis_score.grade}[/bold]"
        )

    # Summary line
    phase_failed = sum(1 for p in display.phases if p["status"] == "failed")
    summary_parts = [
        f"[bold green]Scan completed[/bold green]",
        f"[cyan]{ctx.duration_seconds:.1f}s[/cyan]",
        f"[bold]{len(ctx.findings)}[/bold] finding(s)",
        f"{len([p for p in display.phases if p['status'] == 'done'])}/{len(display.phases)} phases",
    ]
    if phase_failed:
        summary_parts.append(f"[red]{phase_failed} failed[/red]")
    console.print("  |  ".join(summary_parts))

    # Report path (Phase 6이 리포트 생성했으면)
    if ctx.findings:
        from urllib.parse import urlparse as _up
        _safe = _up(target.replace("ghost://", "")).netloc.replace(".", "_") or target.replace("/", "_")
        _report_path = Path(f"reports/VXIS_Pipeline_{_safe}.html")
        if _report_path.exists():
            console.print(f"[dim]Report:[/dim] [underline]{_report_path}[/underline]")

    # Exit code:
    # 0 = success with findings OR clean target (all phases OK)
    # 3 = scan completed but some phases failed (degraded)
    if phase_failed:
        raise typer.Exit(code=3)


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

    async def _generate() -> Path:
        from datetime import date

        from sqlalchemy import select

        from vxis.core.db import create_engine, get_session
        from vxis.models.db_models import FindingRecord, ScanRecord
        from vxis.models.finding import Finding
        from vxis.report.generator import ReportData, ReportGenerator

        config = _get_config()
        db_url = config.db_url
        if ":///" in db_url:
            _pfx, _path = db_url.split("///", 1)
            db_url = f"{_pfx}///{Path(_path).expanduser()}"
        engine = create_engine(db_url)

        async with get_session(engine) as session:
            # Look up the scan record
            result = await session.execute(
                select(ScanRecord).where(ScanRecord.id == int(scan_id))
            )
            scan = result.scalar_one_or_none()
            if scan is None:
                err_console.print(
                    f"[bold red]Scan not found:[/bold red] {scan_id}"
                )
                raise typer.Exit(code=1)

            # Load associated findings
            findings_result = await session.execute(
                select(FindingRecord).where(FindingRecord.scan_id == int(scan_id))
            )
            records: list[FindingRecord] = list(findings_result.scalars().all())

        # Convert FindingRecord ORM rows to Pydantic Finding models
        findings: list[Finding] = _convert_finding_records(records)

        report_data = ReportData(
            scan_id=str(scan_id),
            client_name=scan.target,
            target=scan.target,
            scan_date=scan.started_at.strftime("%Y-%m-%d") if scan.started_at else str(date.today()),
            findings=findings,
        )

        gen = ReportGenerator()
        out = gen.generate_html_file(report_data, output, template_name=f"profiles/{template}")
        await engine.dispose()
        return out

    try:
        result_path = asyncio.run(_generate())
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[bold red]Report generation failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[bold green]Report written to:[/bold green] [underline]{result_path}[/underline]"
    )


@app.command()
def attestation(
    scan_id: str = typer.Argument(help="Scan ID to generate an attestation letter for"),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (default: ./attestation_<scan_id>_<date>.docx)",
    ),
) -> None:
    """Generate a formal attestation letter (DOCX) for a completed scan."""
    from datetime import date

    out_path = output or Path(f"attestation_{scan_id}_{date.today().isoformat()}.docx")

    console.print(
        f"[bold]Generating attestation[/bold] for scan [cyan]{scan_id}[/cyan] "
        f"→ [underline]{out_path}[/underline]"
    )

    async def _generate() -> Path:
        from sqlalchemy import select

        from vxis.core.db import create_engine, get_session
        from vxis.models.db_models import FindingRecord, ScanRecord
        from vxis.models.finding import Finding
        from vxis.report.attestation import AttestationGenerator
        from vxis.report.generator import ReportData

        config = _get_config()
        db_url = config.db_url
        if ":///" in db_url:
            _pfx, _path = db_url.split("///", 1)
            db_url = f"{_pfx}///{Path(_path).expanduser()}"
        engine = create_engine(db_url)

        async with get_session(engine) as session:
            result = await session.execute(
                select(ScanRecord).where(ScanRecord.id == int(scan_id))
            )
            scan = result.scalar_one_or_none()
            if scan is None:
                err_console.print(
                    f"[bold red]Scan not found:[/bold red] {scan_id}"
                )
                raise typer.Exit(code=1)

            findings_result = await session.execute(
                select(FindingRecord).where(FindingRecord.scan_id == int(scan_id))
            )
            records: list[FindingRecord] = list(findings_result.scalars().all())

        findings: list[Finding] = _convert_finding_records(records)

        report_data = ReportData(
            scan_id=str(scan_id),
            client_name=scan.target,
            target=scan.target,
            scan_date=scan.started_at.strftime("%Y-%m-%d") if scan.started_at else str(date.today()),
            findings=findings,
        )

        gen = AttestationGenerator()
        generated = gen.generate(report_data, out_path)
        await engine.dispose()
        return generated

    try:
        result_path = asyncio.run(_generate())
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[bold red]Attestation generation failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[bold green]Attestation written to:[/bold green] [underline]{result_path}[/underline]"
    )


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
        expand=True,
    )
    table.add_column("Name", no_wrap=True, style="bold cyan", min_width=12)
    table.add_column("Version", no_wrap=True, min_width=6)
    table.add_column("Category", no_wrap=True, min_width=10)
    table.add_column("Binary", no_wrap=True, min_width=10)
    table.add_column("Dependencies", min_width=8)

    if check:
        table.add_column("Available", no_wrap=True)

    for name, plugin in sorted(registry.items()):
        meta = plugin.meta
        deps = ", ".join(meta.depends_on) if meta.depends_on else "—"

        row: list[str] = [
            name,
            plugin.detect_version(),
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
        help="Output format: docx | html | json | csv | attestation",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output file path (default: ./<scan_id>.<format>)",
    ),
) -> None:
    """Export scan results to DOCX, HTML, JSON, CSV, or attestation letter."""
    supported_formats = {"docx", "html", "json", "csv", "attestation"}
    if format not in supported_formats:
        err_console.print(
            f"[bold red]Unsupported format:[/bold red] '{format}'. "
            f"Choose from: {', '.join(sorted(supported_formats))}"
        )
        raise typer.Exit(code=1)

    # Resolve default output path
    ext_map = {"docx": "docx", "html": "html", "json": "json", "csv": "csv", "attestation": "docx"}
    ext = ext_map[format]
    out_path = output or Path(f"{scan_id}.{ext}")

    console.print(
        f"[bold]Exporting[/bold] scan [cyan]{scan_id}[/cyan] "
        f"as [yellow]{format}[/yellow] → [underline]{out_path}[/underline]"
    )

    async def _export() -> Path:
        from datetime import date

        from sqlalchemy import select

        from vxis.core.db import create_engine, get_session
        from vxis.models.db_models import FindingRecord, ScanRecord
        from vxis.models.finding import Finding
        from vxis.report.generator import ReportData

        config = _get_config()
        db_url = config.db_url
        if ":///" in db_url:
            _pfx, _path = db_url.split("///", 1)
            db_url = f"{_pfx}///{Path(_path).expanduser()}"
        engine = create_engine(db_url)

        async with get_session(engine) as session:
            result = await session.execute(
                select(ScanRecord).where(ScanRecord.id == int(scan_id))
            )
            scan = result.scalar_one_or_none()
            if scan is None:
                err_console.print(
                    f"[bold red]Scan not found:[/bold red] {scan_id}"
                )
                raise typer.Exit(code=1)

            findings_result = await session.execute(
                select(FindingRecord).where(FindingRecord.scan_id == int(scan_id))
            )
            records: list[FindingRecord] = list(findings_result.scalars().all())

        findings: list[Finding] = _convert_finding_records(records)

        report_data = ReportData(
            scan_id=str(scan_id),
            client_name=scan.target,
            target=scan.target,
            scan_date=scan.started_at.strftime("%Y-%m-%d") if scan.started_at else str(date.today()),
            findings=findings,
        )

        if format == "html":
            from vxis.report.generator import ReportGenerator

            gen = ReportGenerator()
            generated = gen.generate_html_file(report_data, out_path)
        elif format == "docx":
            from vxis.report.docx_export import DOCXReportGenerator

            gen = DOCXReportGenerator()
            generated = gen.generate(report_data, out_path)
        elif format == "json":
            from vxis.report.json_export import JSONExporter

            exporter = JSONExporter()
            generated = exporter.export_report(report_data, out_path)
        elif format == "csv":
            from vxis.report.csv_export import CSVExporter

            exporter = CSVExporter()
            generated = exporter.export_findings(findings, out_path)
        elif format == "attestation":
            from vxis.report.attestation import AttestationGenerator

            gen = AttestationGenerator()
            generated = gen.generate(report_data, out_path)
        else:
            # Should not be reachable due to earlier validation
            raise ValueError(f"Unsupported format: {format}")

        await engine.dispose()
        return generated

    try:
        result_path = asyncio.run(_export())
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[bold red]Export failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc

    console.print(
        f"[bold green]Exported to:[/bold green] [underline]{result_path}[/underline]"
    )


@app.command()
def setup() -> None:
    """도구 설치 현황 확인 및 미설치 도구 자동 설치."""
    from vxis.cli.installer import install_interactive
    install_interactive()


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


@app.command(name="dashboard-init")
def dashboard_init() -> None:
    """Initialise dashboard DB tables and seed default admin/admin user."""
    import asyncio

    from vxis.core.db import create_engine, init_db
    from vxis.dashboard.auth import ensure_default_admin

    async def _run() -> None:
        engine = create_engine("sqlite+aiosqlite:///vxis.db")
        await init_db(engine)
        created = await ensure_default_admin(engine)
        if created is not None:
            console.print(
                "[green]Default admin user created:[/green] "
                "username=[bold]admin[/bold] password=[bold]admin[/bold]"
            )
            console.print("[yellow]Change the password immediately.[/yellow]")
        else:
            console.print("[dim]Users already exist — no seeding performed.[/dim]")

    asyncio.run(_run())


@app.command(name="diff")
def diff_cmd(
    scan_id_a: int = typer.Argument(help="Baseline scan ID (older)"),
    scan_id_b: int = typer.Argument(help="Comparison scan ID (newer)"),
) -> None:
    """Compare two scans and show new, resolved, unchanged, and changed findings."""

    async def _diff() -> None:
        from vxis.core.scan_diff import compare_scans

        config = _get_config()
        result = await compare_scans(scan_id_a, scan_id_b, config.db_url)

        # Summary table
        summary_table = Table(
            title=f"Scan Diff: {scan_id_a} vs {scan_id_b}",
            show_header=True,
            header_style="bold",
            border_style="cyan",
            expand=False,
        )
        summary_table.add_column("Category", style="bold", no_wrap=True)
        summary_table.add_column("Count", justify="right")

        summary_table.add_row("[green]New[/green]", str(len(result.new_findings)))
        summary_table.add_row("[red]Resolved[/red]", str(len(result.resolved_findings)))
        summary_table.add_row("[yellow]Changed[/yellow]", str(len(result.changed_findings)))
        summary_table.add_row("[dim]Unchanged[/dim]", str(len(result.unchanged_findings)))
        console.print(summary_table)

        # New findings detail
        if result.new_findings:
            new_table = Table(
                title="New Findings",
                show_header=True,
                header_style="bold green",
                border_style="green",
                expand=False,
            )
            new_table.add_column("Title", no_wrap=True)
            new_table.add_column("Severity", no_wrap=True)
            new_table.add_column("Target")
            for f in result.new_findings:
                new_table.add_row(f.title, f.effective_severity.value, f.target)
            console.print(new_table)

        # Resolved findings detail
        if result.resolved_findings:
            res_table = Table(
                title="Resolved Findings",
                show_header=True,
                header_style="bold red",
                border_style="red",
                expand=False,
            )
            res_table.add_column("Title", no_wrap=True)
            res_table.add_column("Severity", no_wrap=True)
            res_table.add_column("Target")
            for f in result.resolved_findings:
                res_table.add_row(f.title, f.effective_severity.value, f.target)
            console.print(res_table)

        # Changed findings detail
        if result.changed_findings:
            chg_table = Table(
                title="Changed Findings (Severity)",
                show_header=True,
                header_style="bold yellow",
                border_style="yellow",
                expand=False,
            )
            chg_table.add_column("Title", no_wrap=True)
            chg_table.add_column("Old Severity", no_wrap=True)
            chg_table.add_column("New Severity", no_wrap=True)
            chg_table.add_column("Target")
            for cf in result.changed_findings:
                chg_table.add_row(
                    cf.finding.title,
                    cf.old_severity,
                    cf.new_severity,
                    cf.finding.target,
                )
            console.print(chg_table)

    try:
        asyncio.run(_diff())
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[bold red]Diff failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc


@app.command(name="trend")
def trend_cmd(
    target: str = typer.Argument(help="Target to show trend for (use '*' for portfolio)"),
    limit: int = typer.Option(30, "--limit", "-n", help="Maximum number of data points"),
) -> None:
    """Show severity trend over time for a target (or all targets with '*')."""

    async def _trend() -> None:
        from vxis.core.trend import get_portfolio_trend, get_trend

        config = _get_config()

        if target == "*":
            points = await get_portfolio_trend(config.db_url, limit=limit)
            title = "Portfolio Trend (all targets)"
        else:
            points = await get_trend(target, config.db_url, limit=limit)
            title = f"Trend: {target}"

        if not points:
            console.print("[yellow]No scan data found.[/yellow]")
            return

        table = Table(
            title=title,
            show_header=True,
            header_style="bold",
            border_style="blue",
            expand=False,
        )
        table.add_column("Scan ID", no_wrap=True, justify="right")
        table.add_column("Date", no_wrap=True)
        table.add_column("Critical", no_wrap=True, justify="right", style="bold red")
        table.add_column("High", no_wrap=True, justify="right", style="red")
        table.add_column("Medium", no_wrap=True, justify="right", style="yellow")
        table.add_column("Low", no_wrap=True, justify="right", style="blue")
        table.add_column("Info", no_wrap=True, justify="right", style="dim")
        table.add_column("Total", no_wrap=True, justify="right", style="bold")
        table.add_column("Risk", no_wrap=True, justify="right", style="bold cyan")

        for pt in points:
            sc = pt.severity_counts
            table.add_row(
                str(pt.scan_id),
                pt.date.strftime("%Y-%m-%d %H:%M"),
                str(sc.get("critical", 0)),
                str(sc.get("high", 0)),
                str(sc.get("medium", 0)),
                str(sc.get("low", 0)),
                str(sc.get("informational", 0)),
                str(pt.total_findings),
                f"{pt.risk_score:.1f}",
            )

        console.print(table)

    try:
        asyncio.run(_trend())
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[bold red]Trend query failed:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc


@app.command(name="agent-scan")
def agent_scan(
    target: str = typer.Argument(help="Target URL or domain"),
) -> None:
    """[DEPRECATED] Use 'vxis scan' instead. 'vxis scan --interactive' for Claude Code mode."""
    console.print("[yellow]agent-scan is deprecated. Use:[/yellow]")
    console.print("  [bold]vxis scan[/bold] <target>               # LLM API Brain")
    console.print("  [bold]vxis scan[/bold] <target> --interactive  # Claude Code Brain")
    raise typer.Exit(code=0)


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
# Knowledge Base commands
# ---------------------------------------------------------------------------

kb_app = typer.Typer(help="Browse the vulnerability knowledge base", no_args_is_help=True)
app.add_typer(kb_app, name="kb")


# ---------------------------------------------------------------------------
# Integrations sub-command group
# ---------------------------------------------------------------------------

integrations_app = typer.Typer(
    help="External integration hooks (Slack/Discord/Jira/Linear/GitHub)",
    no_args_is_help=True,
)
app.add_typer(integrations_app, name="integrations")


@integrations_app.command("test")
def integrations_test() -> None:
    """Send a test notification to every configured integration hook.

    Reads VXIS_SLACK_WEBHOOK / VXIS_DISCORD_WEBHOOK / VXIS_JIRA_* /
    VXIS_LINEAR_* / VXIS_GITHUB_* env vars. Hooks without configuration
    are skipped silently.
    """
    from vxis.integrations.registry import load_hooks_from_env

    hooks = load_hooks_from_env()
    if not hooks:
        console.print(
            "[yellow]No integration hooks configured.[/yellow] "
            "Set VXIS_SLACK_WEBHOOK / VXIS_DISCORD_WEBHOOK / VXIS_JIRA_* / "
            "VXIS_LINEAR_* / VXIS_GITHUB_* to enable."
        )
        return

    table = Table(title="Integration Test Results")
    table.add_column("Hook", style="cyan")
    table.add_column("Status")
    table.add_column("Detail", overflow="fold")

    for h in hooks:
        try:
            ok, detail = h.test()
        except Exception as exc:  # noqa: BLE001
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(h.name, status, (detail or "")[:200])

    console.print(table)


@kb_app.command("search")
def kb_search(
    keyword: str = typer.Argument(..., help="Search keyword (e.g. 'injection', 'xss', 'CWE-89')"),
) -> None:
    """Search the vulnerability knowledge base."""
    from vxis.knowledge import get_vuln_kb

    kb = get_vuln_kb()
    results = kb.search(keyword)

    if not results:
        console.print(f"[yellow]No results for '{keyword}'.[/yellow]")
        raise typer.Exit(1)

    table = Table(title=f"KB results for '{keyword}' ({len(results)} found)")
    table.add_column("Type", style="bold cyan", min_width=20)
    table.add_column("Title", min_width=25)
    table.add_column("CWE", min_width=10)
    table.add_column("OWASP Category", min_width=20)

    for r in results:
        table.add_row(r.vuln_type, r.title, r.cwe_id, r.owasp_category)

    console.print(table)


@kb_app.command("show")
def kb_show(
    vuln_type: str = typer.Argument(..., help="Vulnerability type key (e.g. 'sql_injection')"),
) -> None:
    """Show detailed remediation info for a vulnerability type."""
    from vxis.knowledge import get_vuln_kb

    kb = get_vuln_kb()
    info = kb.get_remediation(vuln_type)

    if info is None:
        console.print(f"[yellow]No KB entry for '{vuln_type}'.[/yellow]")
        console.print("Use [bold]vxis kb search <keyword>[/bold] to find entries.")
        raise typer.Exit(1)

    panel_lines = [
        f"[bold]Title:[/bold]    {info.title}",
        f"[bold]CWE:[/bold]      {info.cwe_id}",
        f"[bold]OWASP:[/bold]    {info.owasp_category}",
        "",
        f"[bold]Description:[/bold]\n{info.description}",
        "",
        "[bold]Remediation Steps:[/bold]",
    ]
    for i, step in enumerate(info.remediation_steps, 1):
        panel_lines.append(f"  {i}. {step}")

    if info.references:
        panel_lines.append("")
        panel_lines.append("[bold]References:[/bold]")
        for ref in info.references:
            panel_lines.append(f"  • {ref}")

    console.print(Panel("\n".join(panel_lines), title=f"[bold]{info.vuln_type}[/bold]", border_style="cyan"))


@kb_app.command("list")
def kb_list() -> None:
    """List all vulnerability types in the knowledge base."""
    from vxis.knowledge import get_vuln_kb

    kb = get_vuln_kb()
    types = kb.all_types

    table = Table(title=f"Vulnerability Knowledge Base ({len(types)} entries)")
    table.add_column("#", style="dim", width=4)
    table.add_column("Type", style="bold cyan")

    for i, t in enumerate(types, 1):
        table.add_row(str(i), t)

    console.print(table)


# ---------------------------------------------------------------------------
# Database migration commands
# ---------------------------------------------------------------------------


def _alembic_cfg():
    """Return an Alembic Config pointing at the project's alembic.ini."""
    from alembic.config import Config

    # Resolve alembic.ini relative to the installed package so it works
    # regardless of the current working directory.
    ini_path = Path(__file__).resolve().parents[3] / "alembic.ini"
    if not ini_path.exists():
        # Fallback: try CWD (editable install / dev checkout).
        ini_path = Path("alembic.ini")
    return Config(str(ini_path))


@db_app.command("upgrade")
def db_upgrade(
    revision: str = typer.Argument("head", help="Target revision (default: head)"),
) -> None:
    """Run database migrations up to the target revision."""
    from alembic import command

    cfg = _alembic_cfg()
    command.upgrade(cfg, revision)
    console.print(f"[bold green]Database upgraded to:[/bold green] {revision}")


@db_app.command("current")
def db_current() -> None:
    """Show the current migration revision."""
    from alembic import command

    cfg = _alembic_cfg()
    command.current(cfg, verbose=True)


@db_app.command("history")
def db_history() -> None:
    """Show the migration revision history."""
    from alembic import command

    cfg = _alembic_cfg()
    command.history(cfg, verbose=True)


# ---------------------------------------------------------------------------
# Scheduler — Continuous Monitoring + Auto-Retest|||지속 모니터링 및 자동 재테스트
# ---------------------------------------------------------------------------

schedule_app = typer.Typer(
    name="schedule",
    help="Continuous monitoring schedules|||지속 모니터링 스케줄",
    no_args_is_help=True,
)
app.add_typer(schedule_app, name="schedule")


def _run_scheduled_scan(target: str, profile: str) -> Optional[str]:
    """Invoke `vxis scan` as subprocess; returns generated scan_id or None.

    |||하위 프로세스로 vxis scan 실행. scan_id 반환.
    """
    import subprocess
    import sys as _sys

    try:
        proc = subprocess.run(
            [_sys.executable, "-m", "vxis.cli.main", "scan", target, "--profile", profile],
            capture_output=True,
            text=True,
            timeout=60 * 60 * 4,
        )
        if proc.returncode != 0:
            err_console.print(f"[red]Scheduled scan failed for {target}[/red]")
            err_console.print(proc.stderr[-2000:])
            return None
        # Try to parse a scan id from stdout (best-effort)
        for line in proc.stdout.splitlines():
            if "scan_id" in line.lower() or "scan id" in line.lower():
                console.print(f"[dim]{line}[/dim]")
        return None
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Scheduled scan exception:[/red] {exc}")
        return None


@schedule_app.command("add")
def schedule_add(
    target: str = typer.Argument(help="Target URL or domain"),
    cron: str = typer.Option(..., "--cron", help="Cron expression e.g. '0 */6 * * *' or '@daily'"),
    profile: str = typer.Option("standard", "--profile", "-p", help="Scan profile"),
) -> None:
    """Register a new scheduled scan|||새 예약 스캔 등록."""
    from vxis.scheduler import ScheduleStore

    store = ScheduleStore()
    sched = store.add_schedule(target=target, cron_expr=cron, profile=profile)
    console.print(
        Panel(
            f"[green]Schedule registered[/green]\n"
            f"  ID:       [bold]{sched.id}[/bold]\n"
            f"  Target:   {sched.target}\n"
            f"  Cron:     {sched.cron_expr}\n"
            f"  Profile:  {sched.profile}\n"
            f"  Next run: {sched.next_run}",
            title="vxis schedule add",
            border_style="green",
        )
    )


@schedule_app.command("list")
def schedule_list() -> None:
    """List all scheduled scans|||모든 예약 스캔 표시."""
    from vxis.scheduler import ScheduleStore

    store = ScheduleStore()
    schedules = store.list_schedules()
    if not schedules:
        console.print("[yellow]No schedules registered.|||등록된 스케줄이 없습니다.[/yellow]")
        return

    table = Table(title="VXIS Schedules", header_style="bold cyan", border_style="cyan")
    table.add_column("ID", style="bold")
    table.add_column("Target")
    table.add_column("Cron")
    table.add_column("Profile")
    table.add_column("Enabled")
    table.add_column("Last Run")
    table.add_column("Next Run")
    for s in schedules:
        table.add_row(
            s.id,
            s.target,
            s.cron_expr,
            s.profile,
            "[green]✓[/green]" if s.enabled else "[red]✗[/red]",
            s.last_run or "-",
            s.next_run or "-",
        )
    console.print(table)


@schedule_app.command("remove")
def schedule_remove(schedule_id: str = typer.Argument(help="Schedule ID")) -> None:
    """Remove a schedule|||스케줄 삭제."""
    from vxis.scheduler import ScheduleStore

    store = ScheduleStore()
    if store.remove_schedule(schedule_id):
        console.print(f"[green]Removed schedule {schedule_id}[/green]")
    else:
        err_console.print(f"[red]Schedule not found: {schedule_id}[/red]")
        raise typer.Exit(code=1)


@schedule_app.command("enable")
def schedule_enable(schedule_id: str = typer.Argument(help="Schedule ID")) -> None:
    """Enable a schedule|||스케줄 활성화."""
    from vxis.scheduler import ScheduleStore

    store = ScheduleStore()
    if store.enable(schedule_id):
        console.print(f"[green]Enabled {schedule_id}[/green]")
    else:
        raise typer.Exit(code=1)


@schedule_app.command("disable")
def schedule_disable(schedule_id: str = typer.Argument(help="Schedule ID")) -> None:
    """Disable a schedule|||스케줄 비활성화."""
    from vxis.scheduler import ScheduleStore

    store = ScheduleStore()
    if store.disable(schedule_id):
        console.print(f"[yellow]Disabled {schedule_id}[/yellow]")
    else:
        raise typer.Exit(code=1)


@schedule_app.command("run")
def schedule_run(schedule_id: str = typer.Argument(help="Schedule ID to run now")) -> None:
    """Manually trigger a scheduled scan|||예약 스캔 수동 실행."""
    from vxis.scheduler import ScheduleStore

    store = ScheduleStore()
    sched = store.get(schedule_id)
    if not sched:
        err_console.print(f"[red]Schedule not found: {schedule_id}[/red]")
        raise typer.Exit(code=1)

    console.print(f"[cyan]Running schedule {sched.id} → {sched.target}[/cyan]")
    _run_scheduled_scan(sched.target, sched.profile)
    store.mark_ran(sched.id)
    console.print(f"[green]Done. Next run: {store.get(sched.id).next_run}[/green]")


@schedule_app.command("tick")
def schedule_tick() -> None:
    """Run all due schedules; intended for crontab|||만기된 스케줄 모두 실행 (crontab용)."""
    from vxis.scheduler import ScheduleStore

    store = ScheduleStore()
    due = store.due_schedules()
    if not due:
        console.print("[dim]No due schedules.[/dim]")
        return

    for sched in due:
        console.print(f"[cyan]Running due schedule {sched.id} → {sched.target}[/cyan]")
        _run_scheduled_scan(sched.target, sched.profile)
        store.mark_ran(sched.id)

        # Diff against previous scan + regression notification
        try:
            asyncio.run(_diff_latest_two_for_target(sched.target))
        except Exception as exc:  # noqa: BLE001
            err_console.print(f"[yellow]Diff/notify skipped:[/yellow] {exc}")


async def _diff_latest_two_for_target(target: str) -> None:
    """Find the two most recent scans for target and diff them.

    |||타겟의 최신 두 스캔을 찾아 diff 실행.
    """
    from sqlalchemy import select

    from vxis.core.db import create_engine, get_session
    from vxis.core.scan_diff import compare_scans
    from vxis.models.db_models import ScanRecord

    config = _get_config()
    engine = create_engine(config.db_url)
    async with get_session(engine) as session:
        result = await session.execute(
            select(ScanRecord)
            .where(ScanRecord.target == target)
            .order_by(ScanRecord.created_at.desc())
            .limit(2)
        )
        scans = list(result.scalars().all())
    if len(scans) < 2:
        console.print("[dim]Not enough scans for diff yet.[/dim]")
        return

    new_scan, old_scan = scans[0], scans[1]
    diff = await compare_scans(old_scan.id, new_scan.id, config.db_url)
    console.print(
        f"[bold]Diff {old_scan.id} → {new_scan.id}:[/bold] "
        f"new={len(diff.new_findings)} resolved={len(diff.resolved_findings)} "
        f"changed={len(diff.changed_findings)} unchanged={len(diff.unchanged_findings)}"
    )

    if diff.new_findings or diff.changed_findings:
        console.print(
            "[bold red]⚠ Regression detected!|||회귀 발견![/bold red]"
        )
        try:
            from vxis.integrations import notify_regression  # type: ignore

            notify_regression(target=target, diff=diff)
        except Exception:
            pass


@schedule_app.command("install-cron")
def schedule_install_cron(
    interval_minutes: int = typer.Option(30, "--interval", "-i", help="Tick interval in minutes"),
) -> None:
    """Print a crontab line to install|||설치할 crontab 라인 출력."""
    import sys as _sys

    cwd = Path.cwd()
    py = _sys.executable
    line = (
        f"*/{interval_minutes} * * * * cd {cwd} && {py} -m vxis.cli.main schedule tick "
        f">> ~/.vxis/scheduler.log 2>&1  # vxis-scheduler"
    )
    console.print(
        Panel(
            f"[bold]Add this line to your crontab (`crontab -e`):[/bold]\n\n  {line}\n\n"
            f"|||\n[bold]아래 라인을 crontab에 추가하세요 (`crontab -e`):[/bold]\n\n  {line}",
            title="install-cron",
            border_style="cyan",
        )
    )


@app.command("retest")
def retest_cmd(
    scan_id: int = typer.Argument(help="Original scan ID to re-test"),
    profile: str = typer.Option("standard", "--profile", "-p", help="Scan profile"),
) -> None:
    """Re-scan the same target as a previous scan and diff with it.

    |||이전 스캔과 동일한 타겟을 재스캔하여 diff.
    """

    async def _retest() -> None:
        from sqlalchemy import select

        from vxis.core.db import create_engine, get_session
        from vxis.core.scan_diff import compare_scans
        from vxis.models.db_models import ScanRecord

        config = _get_config()
        engine = create_engine(config.db_url)
        async with get_session(engine) as session:
            result = await session.execute(
                select(ScanRecord).where(ScanRecord.id == scan_id)
            )
            original = result.scalar_one_or_none()
        if not original:
            err_console.print(f"[red]Scan {scan_id} not found[/red]")
            raise typer.Exit(code=1)

        target = original.target
        console.print(f"[cyan]Re-testing scan {scan_id} → {target}[/cyan]")
        _run_scheduled_scan(target, profile)

        # Find newest scan for that target (the one we just created)
        async with get_session(engine) as session:
            result = await session.execute(
                select(ScanRecord)
                .where(ScanRecord.target == target)
                .order_by(ScanRecord.created_at.desc())
                .limit(1)
            )
            new_scan = result.scalar_one_or_none()
        if not new_scan or new_scan.id == scan_id:
            err_console.print("[yellow]No new scan record found after retest[/yellow]")
            return

        diff = await compare_scans(scan_id, new_scan.id, config.db_url)
        console.print(
            Panel(
                f"Original: {scan_id}\nNew: {new_scan.id}\n"
                f"New findings:     {len(diff.new_findings)}\n"
                f"Resolved:         {len(diff.resolved_findings)}\n"
                f"Severity changed: {len(diff.changed_findings)}\n"
                f"Unchanged:        {len(diff.unchanged_findings)}",
                title="Retest Result|||재테스트 결과",
                border_style="cyan",
            )
        )

    try:
        asyncio.run(_retest())
    except typer.Exit:
        raise
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[red]Retest failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc


# ---------------------------------------------------------------------------
# News / Growth Layer sub-commands — Self-Growth Intelligence review
# ---------------------------------------------------------------------------

news_app = typer.Typer(
    help="Self-Growth Intelligence proposals — review, approve, reject",
    no_args_is_help=True,
)
app.add_typer(news_app, name="news")


def _load_proposals_from_dir(directory: Path) -> list[dict]:
    """Load all proposal JSON files from a directory."""
    if not directory.exists():
        return []
    import json as _json
    proposals = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = _json.loads(path.read_text())
            proposals.append(data)
        except Exception:
            continue
    return proposals


@news_app.command("pending")
def news_pending(
    risk: Optional[str] = typer.Option(None, "--risk", help="Filter by risk: low/medium/high/critical"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max proposals to show"),
) -> None:
    """List proposals waiting for review."""
    from pathlib import Path as _P
    pending_dir = _P(".vxis/signals/pending")
    proposals = _load_proposals_from_dir(pending_dir)

    if risk:
        proposals = [p for p in proposals if p.get("risk") == risk]

    if not proposals:
        console.print("[yellow]No pending proposals[/yellow]")
        return

    table = Table(title=f"Pending Proposals ({len(proposals)})", show_header=True)
    table.add_column("ID", no_wrap=True, width=24)
    table.add_column("Type", width=18)
    table.add_column("Risk", width=8)
    table.add_column("Conf", justify="right", width=6)
    table.add_column("Source", width=16)
    table.add_column("Rationale", max_width=40)

    risk_style = {"low": "green", "medium": "yellow", "high": "red", "critical": "bold red"}

    for p in proposals[:limit]:
        rid = p.get("proposal_id", "")[:22]
        ctype = p.get("change_type", "")[:18]
        risk_val = p.get("risk", "?")
        style = risk_style.get(risk_val, "")
        conf = p.get("confidence", 0)
        source = p.get("source_url", "")[:14]
        rat = p.get("rationale_en", "")[:38]
        table.add_row(
            rid, ctype, f"[{style}]{risk_val}[/{style}]",
            f"{conf:.2f}", source, rat,
        )

    console.print(table)


@news_app.command("show")
def news_show(
    proposal_id: str = typer.Argument(..., help="Proposal ID to display"),
) -> None:
    """Show full details of a proposal."""
    from pathlib import Path as _P
    import json as _json
    for subdir in ("pending", "applied", "rejected", "auto_applied"):
        path = _P(f".vxis/signals/{subdir}") / f"{proposal_id}.json"
        if path.exists():
            data = _json.loads(path.read_text())
            console.print(Panel(
                f"[bold]Proposal ID:[/bold] {data.get('proposal_id')}\n"
                f"[bold]Status:[/bold] {data.get('status', subdir)}\n"
                f"[bold]Change Type:[/bold] {data.get('change_type')}\n"
                f"[bold]Risk:[/bold] {data.get('risk')}\n"
                f"[bold]Confidence:[/bold] {data.get('confidence', 0):.2f}\n"
                f"[bold]Target File:[/bold] {data.get('target_file')}\n"
                f"[bold]Source:[/bold] {data.get('source_url')}\n"
                f"\n[bold cyan]Rationale (EN):[/bold cyan]\n{data.get('rationale_en', '')}\n"
                f"\n[bold cyan]Rationale (KO):[/bold cyan]\n{data.get('rationale_ko', '')}\n"
                f"\n[bold cyan]Change Data:[/bold cyan]\n{_json.dumps(data.get('change_data', {}), indent=2, ensure_ascii=False)}",
                title=f"Proposal: {proposal_id}",
                border_style="cyan",
            ))
            return
    err_console.print(f"[red]Proposal not found:[/red] {proposal_id}")
    raise typer.Exit(code=1)


@news_app.command("approve")
def news_approve(
    proposal_id: str = typer.Argument(..., help="Proposal ID to approve"),
) -> None:
    """Approve a pending proposal (moves to applied/).

    Note: actual code modification still requires dry_run=false in growth_bootstrap.toml.
    This command moves the proposal out of pending review queue.
    """
    from pathlib import Path as _P
    import json as _json
    import shutil
    from datetime import datetime, timezone

    pending_path = _P(".vxis/signals/pending") / f"{proposal_id}.json"
    if not pending_path.exists():
        err_console.print(f"[red]Not in pending queue:[/red] {proposal_id}")
        raise typer.Exit(code=1)

    applied_dir = _P(".vxis/signals/applied")
    applied_dir.mkdir(parents=True, exist_ok=True)

    data = _json.loads(pending_path.read_text())
    data["status"] = "applied"
    data["applied_at"] = datetime.now(timezone.utc).isoformat()

    applied_path = applied_dir / f"{proposal_id}.json"
    applied_path.write_text(_json.dumps(data, ensure_ascii=False, indent=2))
    pending_path.unlink()

    # Log to changelog
    try:
        from vxis.growth.changelog import ChangeLog
        log = ChangeLog()
        log.record("proposal_approved_manually", {
            "proposal_id": proposal_id,
            "change_type": data.get("change_type"),
        })
    except Exception:
        pass

    console.print(f"[green]✓ Approved:[/green] {proposal_id}")
    console.print(f"  Moved to: {applied_path}")
    console.print("[dim]Note: real code modification requires dry_run=false in configs/growth_bootstrap.toml[/dim]")


@news_app.command("reject")
def news_reject(
    proposal_id: str = typer.Argument(..., help="Proposal ID to reject"),
    reason: Optional[str] = typer.Option("", "--reason", "-r", help="Rejection reason"),
) -> None:
    """Reject a pending proposal (moves to rejected/)."""
    from pathlib import Path as _P
    import json as _json
    from datetime import datetime, timezone

    pending_path = _P(".vxis/signals/pending") / f"{proposal_id}.json"
    if not pending_path.exists():
        err_console.print(f"[red]Not in pending queue:[/red] {proposal_id}")
        raise typer.Exit(code=1)

    rejected_dir = _P(".vxis/signals/rejected")
    rejected_dir.mkdir(parents=True, exist_ok=True)

    data = _json.loads(pending_path.read_text())
    data["status"] = "rejected"
    data["rejected_at"] = datetime.now(timezone.utc).isoformat()
    data["rejection_reason"] = reason

    rejected_path = rejected_dir / f"{proposal_id}.json"
    rejected_path.write_text(_json.dumps(data, ensure_ascii=False, indent=2))
    pending_path.unlink()

    try:
        from vxis.growth.changelog import ChangeLog
        log = ChangeLog()
        log.record("proposal_rejected_manually", {
            "proposal_id": proposal_id,
            "reason": reason,
        })
    except Exception:
        pass

    console.print(f"[yellow]✗ Rejected:[/yellow] {proposal_id}")
    if reason:
        console.print(f"  Reason: {reason}")


@news_app.command("rollback")
def news_rollback(
    proposal_id: str = typer.Argument(..., help="Proposal ID to rollback"),
    reason: Optional[str] = typer.Option("manual", "--reason", "-r"),
) -> None:
    """Rollback a previously applied proposal."""
    try:
        from vxis.growth.rollback import rollback_proposal
        success = rollback_proposal(proposal_id, reason=reason)
        if success:
            console.print(f"[green]✓ Rolled back:[/green] {proposal_id}")
        else:
            err_console.print(f"[red]Rollback failed:[/red] {proposal_id} not found in applied/")
            raise typer.Exit(code=1)
    except Exception as exc:
        err_console.print(f"[red]Rollback error:[/red] {exc}")
        raise typer.Exit(code=1) from exc


@news_app.command("digest")
def news_digest(
    days: int = typer.Option(7, "--days", "-d", help="Days to summarize"),
) -> None:
    """Show growth activity summary for the last N days."""
    try:
        from vxis.growth.changelog import ChangeLog
        log = ChangeLog()
        summary = log.summary(days=days)
    except Exception as exc:
        err_console.print(f"[red]Digest error:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    table = Table(title=f"Growth Activity — Last {days} days", show_header=True)
    table.add_column("Event Type", style="bold")
    table.add_column("Count", justify="right")

    for event_type, count in sorted(summary.get("by_type", {}).items()):
        table.add_row(event_type, str(count))

    console.print(table)
    console.print(f"[dim]Total events: {summary.get('total_events', 0)}[/dim]")
    console.print(f"[dim]Since: {summary.get('since', '')}[/dim]")


@news_app.command("stats")
def news_stats() -> None:
    """Show current state of Self-Growth pipeline (inbox/pending/applied counts)."""
    from pathlib import Path as _P

    stats_table = Table(title="Self-Growth Pipeline State", show_header=True)
    stats_table.add_column("Directory", style="bold")
    stats_table.add_column("Count", justify="right")
    stats_table.add_column("Path", style="dim")

    dirs = [
        ("Inbox (raw signals)", ".vxis/signals/inbox"),
        ("Pending (review)",    ".vxis/signals/pending"),
        ("Applied",             ".vxis/signals/applied"),
        ("Rejected",            ".vxis/signals/rejected"),
        ("Extraction cache",    ".vxis/cache/extractions"),
    ]

    for label, path_str in dirs:
        path = _P(path_str)
        if path.exists():
            count = len(list(path.glob("*")))
        else:
            count = 0
        stats_table.add_row(label, str(count), path_str)

    console.print(stats_table)

    # Load and show bootstrap config
    try:
        from vxis.growth.config import load_bootstrap_config
        cfg = load_bootstrap_config()
        console.print()
        console.print(Panel(
            f"[bold]Dry-run:[/bold] {cfg['apply']['dry_run']}\n"
            f"[bold]Trust threshold:[/bold] {cfg['filtering']['trust_threshold_for_llm']}\n"
            f"[bold]Auto-apply threshold:[/bold] {cfg['apply']['auto_apply_threshold']}\n"
            f"[bold]Monthly LLM cap:[/bold] ${cfg['budget']['max_monthly_llm_usd']}\n"
            f"[bold]Signal analyze interval:[/bold] {cfg['polling']['signal_analyze_interval_hours']}h",
            title="Bootstrap Config",
            border_style="cyan",
        ))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point registered in pyproject.toml."""
    app()


if __name__ == "__main__":
    main()
