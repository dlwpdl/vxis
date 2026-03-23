"""VXIS Interactive CLI — 방향키 기반 인터랙티브 위자드.

`vxis` (인자 없이) 실행 시 메인 메뉴를 표시하고,
방향키로 옵션을 선택, 단계별로 스캔 파라미터를 입력받습니다.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from InquirerPy import inquirer
from InquirerPy.separator import Separator

console = Console()

# ── 스캔 카테고리 정의 ──────────────────────────────────────────

SCAN_CATEGORIES = {
    "zero_touch": {
        "name": "제로터치 (Passive)",
        "icon": "\U0001f50d",
        "desc": "대상에 직접 접촉 없이 OSINT만으로 정보 수집",
        "profile": "passive",
        "plugins": [
            "shodan", "crtsh", "subfinder", "dnstwist", "httpx",
        ],
    },
    "external": {
        "name": "외부 스캔 (External)",
        "icon": "\U0001f310",
        "desc": "웹/네트워크 취약점 + SSL/DNS + 시크릿 탐지",
        "profile": "standard",
        "plugins": [
            "nuclei", "nmap", "httpx", "testssl", "checkdmarc",
            "wafw00f", "trufflehog", "sslyze", "subfinder", "crtsh",
            "dnstwist", "shodan",
        ],
    },
    "internal": {
        "name": "내부 스캔 (Internal)",
        "icon": "\U0001f3e2",
        "desc": "Active Directory / 내부 네트워크 환경 진단",
        "profile": "standard",
        "tier": 2,
        "plugins": [
            "nmap", "bloodhound", "certipy", "netexec",
        ],
    },
    "code": {
        "name": "코드 스캔 (Code/Supply Chain)",
        "icon": "\U0001f4bb",
        "desc": "소스코드 + 의존성 + CI/CD 파이프라인 보안 점검",
        "profile": "standard",
        "plugins": [
            "semgrep", "bandit", "checkov", "poutine", "actionlint",
            "gitleaks", "confused", "trivy",
        ],
    },
    "cloud": {
        "name": "클라우드 (Cloud)",
        "icon": "\u2601\ufe0f",
        "desc": "AWS / Azure / GCP 설정 감사 + 컨테이너 보안",
        "profile": "standard",
        "plugins": [
            "prowler", "s3scanner", "trivy_k8s", "kube_bench",
        ],
    },
    "batch": {
        "name": "PE 포트폴리오 (Batch)",
        "icon": "\U0001f4ca",
        "desc": "CSV 파일의 다수 대상 일괄 스캔 + 리스크 등급 리포트",
        "profile": "standard",
        "plugins": [],  # uses all external plugins
    },
    "custom": {
        "name": "커스텀 스캔",
        "icon": "\U0001f6e0\ufe0f",
        "desc": "플러그인을 직접 선택하여 스캔",
        "profile": "standard",
        "plugins": [],
    },
}

PROFILES = {
    "passive": {
        "name": "Passive",
        "icon": "\U0001f441\ufe0f",
        "desc": "직접 접촉 없음 (OSINT만)",
    },
    "stealth": {
        "name": "Stealth",
        "icon": "\U0001f422",
        "desc": "IDS 우회용 저속 스캔",
    },
    "standard": {
        "name": "Standard",
        "icon": "\u26a1",
        "desc": "일반적인 속도 (권장)",
    },
    "aggressive": {
        "name": "Aggressive",
        "icon": "\U0001f680",
        "desc": "최대 속도 (랩 환경 전용)",
    },
}


# ── 배너 ────────────────────────────────────────────────────────

_BANNER = r"""
__     __ __  __ ___  ____
\ \   / / \ \/ /|_ _|/ ___|
 \ \ / /   \  /  | | \___ \
  \ V /    /  \ _| |_ ___) |
   \_/    /_/\_\_____|____/
"""


def print_banner() -> None:
    console.print(
        Panel(
            Text(_BANNER.strip(), style="bold cyan", justify="center"),
            subtitle="[dim]AI-powered security automation platform[/dim]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


# ── 메인 메뉴 ──────────────────────────────────────────────────

def main_menu() -> str | None:
    """메인 메뉴를 표시하고 선택된 액션을 반환."""
    choices = [
        {"name": "\U0001f50d  스캔 시작", "value": "scan"},
        {"name": "\U0001f4ca  스캔 결과 조회", "value": "results"},
        {"name": "\U0001f4c4  리포트 생성 / 내보내기", "value": "report"},
        {"name": "\U0001f50c  플러그인 관리", "value": "plugins"},
        {"name": "\U0001f464  클라이언트 관리", "value": "client"},
        {"name": "\U0001f310  대시보드 열기", "value": "dashboard"},
        Separator(),
        {"name": "\u2699\ufe0f   설정", "value": "settings"},
        {"name": "\u274c  종료", "value": "exit"},
    ]

    result = inquirer.select(
        message="무엇을 하시겠습니까?",
        choices=choices,
        pointer="\u276f",
        qmark="",
        amark="",
        instruction="(↑↓ 방향키로 선택, Enter 확인)",
    ).execute()

    return result


# ── 스캔 위자드 ────────────────────────────────────────────────

def scan_wizard() -> dict | None:
    """스캔 설정 위자드. 선택된 파라미터를 dict로 반환."""

    # Step 1: 스캔 유형 선택
    scan_choices = []
    for key, cat in SCAN_CATEGORIES.items():
        scan_choices.append({
            "name": f"{cat['icon']}  {cat['name']}    {cat['desc']}",
            "value": key,
        })

    scan_type = inquirer.select(
        message="스캔 유형을 선택하세요",
        choices=scan_choices,
        pointer="\u276f",
        qmark="\U0001f50d",
        amark="\u2705",
        instruction="(↑↓ 방향키)",
    ).execute()

    if scan_type is None:
        return None

    cat = SCAN_CATEGORIES[scan_type]

    # Batch는 별도 플로우
    if scan_type == "batch":
        return _batch_wizard()

    # Step 2: 타겟 입력
    target = inquirer.text(
        message="스캔 대상을 입력하세요",
        qmark="\U0001f3af",
        amark="\u2705",
        instruction="(도메인, IP, 또는 CIDR)",
        validate=lambda val: len(val.strip()) > 0,
        invalid_message="대상을 입력해주세요",
    ).execute()

    if not target:
        return None

    # Step 3: 스캔 강도 (제로터치는 passive 고정)
    if scan_type == "zero_touch":
        profile = "passive"
    else:
        profile_choices = []
        for key, prof in PROFILES.items():
            if scan_type == "zero_touch" and key != "passive":
                continue
            marker = " (권장)" if key == cat["profile"] else ""
            profile_choices.append({
                "name": f"{prof['icon']}  {prof['name']}   {prof['desc']}{marker}",
                "value": key,
            })

        profile = inquirer.select(
            message="스캔 강도를 선택하세요",
            choices=profile_choices,
            default=cat["profile"],
            pointer="\u276f",
            qmark="\u26a1",
            amark="\u2705",
        ).execute()

    # Step 4: 플러그인 선택 (커스텀일 때만)
    selected_plugins = cat["plugins"] if cat["plugins"] else None

    if scan_type == "custom":
        selected_plugins = _plugin_selector()
        if not selected_plugins:
            return None

    # Step 5: 플러그인 목록 표시 + 확인
    if selected_plugins:
        _show_plugin_summary(selected_plugins, target, profile, cat["name"])

    confirm = inquirer.confirm(
        message="스캔을 시작할까요?",
        default=True,
        qmark="\U0001f680",
        amark="\u2705",
    ).execute()

    if not confirm:
        console.print("[dim]스캔이 취소되었습니다.[/dim]")
        return None

    return {
        "target": target.strip(),
        "profile": profile,
        "plugins": selected_plugins,
        "scan_type": scan_type,
        "tier": cat.get("tier", 1),
    }


def _batch_wizard() -> dict | None:
    """PE 포트폴리오 배치 스캔 위자드."""
    csv_path = inquirer.filepath(
        message="CSV 파일 경로를 입력하세요",
        qmark="\U0001f4c1",
        amark="\u2705",
        validate=lambda val: val.strip().endswith(".csv"),
        invalid_message=".csv 파일을 선택해주세요",
    ).execute()

    if not csv_path:
        return None

    profile_choices = [
        {"name": f"{p['icon']}  {p['name']}   {p['desc']}", "value": k}
        for k, p in PROFILES.items()
    ]

    profile = inquirer.select(
        message="스캔 강도를 선택하세요",
        choices=profile_choices,
        default="standard",
        pointer="\u276f",
        qmark="\u26a1",
        amark="\u2705",
    ).execute()

    concurrent = inquirer.number(
        message="동시 스캔 수",
        default=3,
        min_allowed=1,
        max_allowed=10,
        qmark="\U0001f504",
        amark="\u2705",
    ).execute()

    return {
        "scan_type": "batch",
        "csv_path": csv_path,
        "profile": profile,
        "concurrent": int(concurrent),
    }


def _plugin_selector() -> list[str] | None:
    """체크박스로 플러그인 멀티 선택."""
    try:
        from vxis.plugins.registry import discover_plugins
        registry = discover_plugins()
    except Exception:
        console.print("[yellow]플러그인 목록을 불러올 수 없습니다.[/yellow]")
        return None

    # Group by category
    by_category: dict[str, list[str]] = {}
    for name, plugin in sorted(registry.items()):
        cat = plugin.meta.category
        by_category.setdefault(cat, []).append(name)

    choices = []
    for cat, names in sorted(by_category.items()):
        choices.append(Separator(f"── {cat} ──"))
        for name in names:
            plugin = registry[name]
            available = plugin.validate_environment()
            status = "" if available else " [미설치]"
            choices.append({
                "name": f"{name}{status}",
                "value": name,
                "enabled": available,
            })

    selected = inquirer.checkbox(
        message="실행할 플러그인을 선택하세요",
        choices=choices,
        pointer="\u276f",
        qmark="\U0001f50c",
        amark="\u2705",
        instruction="(Space 선택/해제, Enter 확인)",
    ).execute()

    return selected if selected else None


def _show_plugin_summary(
    plugins: list[str], target: str, profile: str, scan_name: str,
) -> None:
    """선택된 스캔 설정 요약 표시."""
    table = Table.grid(padding=(0, 1))
    table.add_column(style="bold", width=14)
    table.add_column()

    table.add_row("\U0001f3af 대상:", f"[cyan]{target}[/cyan]")
    table.add_row("\U0001f4cb 스캔 유형:", f"[yellow]{scan_name}[/yellow]")
    table.add_row("\u26a1 프로필:", f"[green]{profile}[/green]")

    # Plugin grid (4 columns)
    plugin_lines = []
    for i in range(0, len(plugins), 4):
        chunk = plugins[i:i + 4]
        line = "  ".join(f"\u2705 {p}" for p in chunk)
        plugin_lines.append(line)

    table.add_row(
        f"\U0001f50c 플러그인:",
        f"[dim]{len(plugins)}개 선택[/dim]",
    )

    console.print()
    console.print(Panel(table, title="스캔 설정 확인", border_style="blue"))
    for line in plugin_lines:
        console.print(f"  {line}")
    console.print()


# ── 결과 조회 ──────────────────────────────────────────────────

def results_menu() -> dict | None:
    """스캔 결과 조회 메뉴."""
    action = inquirer.select(
        message="조회할 항목을 선택하세요",
        choices=[
            {"name": "\U0001f4cb  최근 스캔 목록", "value": "list"},
            {"name": "\U0001f50d  스캔 ID로 조회", "value": "by_id"},
            {"name": "\u2b05\ufe0f   뒤로", "value": "back"},
        ],
        pointer="\u276f",
        qmark="\U0001f4ca",
        amark="\u2705",
    ).execute()

    if action == "back":
        return None
    if action == "by_id":
        scan_id = inquirer.text(
            message="스캔 ID를 입력하세요",
            qmark="\U0001f50d",
        ).execute()
        return {"action": "by_id", "scan_id": scan_id}
    return {"action": action}


# ── 리포트 메뉴 ────────────────────────────────────────────────

def report_menu() -> dict | None:
    """리포트 생성/내보내기 메뉴."""
    scan_id = inquirer.text(
        message="리포트를 생성할 스캔 ID를 입력하세요",
        qmark="\U0001f4c4",
        amark="\u2705",
    ).execute()

    if not scan_id:
        return None

    fmt = inquirer.select(
        message="출력 포맷을 선택하세요",
        choices=[
            {"name": "\U0001f4c4  HTML 리포트", "value": "html"},
            {"name": "\U0001f4d8  DOCX 리포트", "value": "docx"},
            {"name": "\u2709\ufe0f   Attestation Letter", "value": "attestation"},
            {"name": "\u2b05\ufe0f   취소", "value": "cancel"},
        ],
        pointer="\u276f",
        qmark="\U0001f4e4",
        amark="\u2705",
    ).execute()

    if fmt == "cancel":
        return None

    return {"scan_id": scan_id.strip(), "format": fmt}


# ── 전체 인터랙티브 루프 ────────────────────────────────────────

def run_interactive() -> None:
    """메인 인터랙티브 루프. `vxis` 실행 시 호출."""
    print_banner()
    console.print()

    while True:
        try:
            action = main_menu()
        except KeyboardInterrupt:
            console.print("\n[dim]종료합니다.[/dim]")
            break

        if action == "exit" or action is None:
            console.print("[dim]종료합니다.[/dim]")
            break

        try:
            _dispatch(action)
        except KeyboardInterrupt:
            console.print("\n[dim]취소되었습니다.[/dim]")
            continue


def _dispatch(action: str) -> None:
    """메인 메뉴 액션 디스패치."""
    if action == "scan":
        params = scan_wizard()
        if params:
            _execute_scan(params)

    elif action == "results":
        result = results_menu()
        if result:
            _show_results(result)

    elif action == "report":
        result = report_menu()
        if result:
            _generate_report(result)

    elif action == "plugins":
        from vxis.cli.installer import install_interactive
        install_interactive()

    elif action == "client":
        _client_menu()

    elif action == "dashboard":
        from vxis.cli.main import dashboard
        dashboard(host="127.0.0.1", port=8080)

    elif action == "settings":
        console.print("[dim]설정은 .env 파일 또는 VXIS_ 환경변수로 관리합니다.[/dim]")
        console.print("[dim]  예: VXIS_DB_URL, VXIS_LOG_LEVEL, VXIS_SHODAN_API_KEY[/dim]")


def _execute_scan(params: dict) -> None:
    """스캔 위자드 결과로 실제 스캔 실행."""
    import asyncio
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    if params["scan_type"] == "batch":
        from pathlib import Path
        from vxis.cli.main import batch
        batch(
            csv_file=Path(params["csv_path"]),
            profile=params["profile"],
            max_concurrent=params["concurrent"],
            output_dir=Path("./reports/batch"),
        )
        return

    from vxis.config.schema import VXISConfig
    from vxis.core.events import ScanEventBus, ScanSnapshotCollector
    from vxis.core.orchestrator import ScanOrchestrator
    from vxis.core.scope import ScopeViolationError
    from vxis.cli.live_display import ScanLiveDisplay

    config = VXISConfig()
    event_bus = ScanEventBus()
    collector = ScanSnapshotCollector()
    event_bus.on_any(collector.handle_event)

    orchestrator = ScanOrchestrator(config, event_bus=event_bus)

    selected_plugins = params.get("plugins")

    async def _run_with_display():
        scan_task = asyncio.create_task(
            orchestrator.run_scan(
                target=params["target"],
                profile=params["profile"],
                selected_plugins=selected_plugins,
                tier=params.get("tier", 1),
            )
        )
        while not scan_task.done():
            display.update(collector.snapshot)
            await asyncio.sleep(0.25)
        display.update(collector.snapshot)
        return await scan_task

    console.print(f"\n[bold cyan]스캔 시작:[/bold cyan] {params['target']} ({params['profile']})\n")

    try:
        display = ScanLiveDisplay(console)
        with display:
            result = asyncio.run(_run_with_display())
    except ScopeViolationError as exc:
        console.print(f"\n[bold red]스코프 위반:[/bold red] {exc}")
        return
    except Exception as exc:
        console.print(f"\n[bold red]스캔 실패:[/bold red] {exc}")
        import traceback
        console.print(f"[dim]{traceback.format_exc()}[/dim]")
        return

    # Results summary
    console.print(
        f"\n[bold green]스캔 완료[/bold green] "
        f"({result.duration_seconds:.1f}초) — "
        f"[bold]{len(result.findings)}[/bold]개 취약점 발견"
    )

    counts = result.severity_counts
    severity_colors = {
        "critical": "red", "high": "red", "medium": "yellow",
        "low": "blue", "informational": "dim",
    }
    parts = []
    for sev in ["critical", "high", "medium", "low", "informational"]:
        c = counts.get(sev, 0)
        if c > 0:
            color = severity_colors[sev]
            parts.append(f"[{color}]{sev}: {c}[/{color}]")
    if parts:
        console.print("  " + " | ".join(parts))


def _show_results(params: dict) -> None:
    """스캔 결과 조회."""
    import asyncio

    from vxis.config.schema import VXISConfig
    from vxis.core.db import create_engine, get_session
    from vxis.models.db_models import FindingRecord, ScanRecord

    config = VXISConfig()
    db_url = config.db_url
    if ":///" in db_url:
        prefix, path = db_url.split("///", 1)
        from pathlib import Path as P
        db_url = f"{prefix}///{P(path).expanduser()}"

    async def _query():
        from sqlalchemy import func, select

        engine = create_engine(db_url)

        try:
            async with get_session(engine) as session:
                if params["action"] == "by_id":
                    # 특정 스캔 상세 조회
                    scan_id = int(params["scan_id"])
                    scan_r = await session.execute(
                        select(ScanRecord).where(ScanRecord.id == scan_id)
                    )
                    scan = scan_r.scalar_one_or_none()
                    if scan is None:
                        console.print(f"[red]스캔 ID {scan_id}를 찾을 수 없습니다.[/red]")
                        return

                    findings_r = await session.execute(
                        select(FindingRecord).where(FindingRecord.scan_id == scan_id)
                    )
                    findings = list(findings_r.scalars().all())

                    # 스캔 정보
                    info = Table.grid(padding=(0, 2))
                    info.add_column(style="bold", width=14)
                    info.add_column()
                    info.add_row("\U0001f3af 대상:", f"[cyan]{scan.target}[/cyan]")
                    info.add_row("\U0001f4cb 프로필:", f"[yellow]{scan.profile}[/yellow]")
                    info.add_row("\U0001f4c5 시작:", str(scan.started_at))
                    info.add_row("\u2705 상태:", f"[green]{scan.status}[/green]")
                    info.add_row("\U0001f50d 발견:", f"[bold]{len(findings)}[/bold]개")
                    console.print(Panel(info, title=f"스캔 #{scan_id}", border_style="blue"))

                    if findings:
                        # Severity 테이블
                        sev_table = Table(
                            show_header=True, header_style="bold",
                            border_style="green", expand=False,
                        )
                        sev_table.add_column("심각도", no_wrap=True)
                        sev_table.add_column("건수", justify="right")
                        sev_table.add_column("주요 항목")

                        sev_colors = {
                            "critical": "bold red", "high": "red",
                            "medium": "yellow", "low": "blue", "informational": "dim",
                        }
                        sev_kr = {
                            "critical": "심각", "high": "높음",
                            "medium": "중간", "low": "낮음", "informational": "정보",
                        }

                        by_sev: dict[str, list] = {}
                        for f in findings:
                            s = f.effective_severity.lower()
                            by_sev.setdefault(s, []).append(f)

                        for sev in ["critical", "high", "medium", "low", "informational"]:
                            items = by_sev.get(sev, [])
                            if not items:
                                continue
                            style = sev_colors.get(sev, "")
                            titles = ", ".join(f.title[:40] for f in items[:3])
                            if len(items) > 3:
                                titles += f" (+{len(items) - 3})"
                            sev_table.add_row(
                                f"[{style}]{sev_kr.get(sev, sev)}[/{style}]",
                                f"[{style}]{len(items)}[/{style}]",
                                titles,
                            )

                        console.print(sev_table)

                else:
                    # 최근 스캔 목록
                    scans_r = await session.execute(
                        select(ScanRecord).order_by(ScanRecord.started_at.desc()).limit(15)
                    )
                    scans = list(scans_r.scalars().all())

                    if not scans:
                        console.print("[yellow]스캔 기록이 없습니다.[/yellow]")
                        return

                    table = Table(
                        title="\U0001f4cb 최근 스캔 목록",
                        show_header=True, header_style="bold",
                        border_style="cyan", expand=False,
                    )
                    table.add_column("ID", style="bold cyan", no_wrap=True)
                    table.add_column("대상", no_wrap=True)
                    table.add_column("프로필", no_wrap=True)
                    table.add_column("상태", no_wrap=True)
                    table.add_column("발견", justify="right")
                    table.add_column("시간", no_wrap=True)

                    for s in scans:
                        count_r = await session.execute(
                            select(func.count(FindingRecord.id)).where(
                                FindingRecord.scan_id == s.id
                            )
                        )
                        count = count_r.scalar_one_or_none() or 0

                        status_style = "green" if s.status == "completed" else "red"
                        time_str = s.started_at.strftime("%m-%d %H:%M") if s.started_at else "—"

                        table.add_row(
                            str(s.id),
                            s.target,
                            s.profile,
                            f"[{status_style}]{s.status}[/{status_style}]",
                            str(count),
                            time_str,
                        )

                    console.print(table)
                    console.print("[dim]상세 조회: 스캔 결과 조회 → 스캔 ID로 조회[/dim]")
        finally:
            await engine.dispose()

    try:
        asyncio.run(_query())
    except Exception as exc:
        console.print(f"[red]조회 실패:[/red] {exc}")


def _generate_report(params: dict) -> None:
    """리포트 생성."""
    from vxis.cli.main import export
    from pathlib import Path

    scan_id = params["scan_id"]
    fmt = params["format"]
    ext = {"html": "html", "docx": "docx", "attestation": "docx"}[fmt]
    output = Path(f"report_{scan_id}.{ext}")

    export(scan_id=scan_id, format=fmt, output=output)


def _client_menu() -> None:
    """클라이언트 관리 메뉴."""
    action = inquirer.select(
        message="클라이언트 관리",
        choices=[
            {"name": "\U0001f4cb  클라이언트 목록", "value": "list"},
            {"name": "\u2795  새 클라이언트 추가", "value": "add"},
            {"name": "\U0001f50d  클라이언트 상세 보기", "value": "show"},
            {"name": "\u2b05\ufe0f   뒤로", "value": "back"},
        ],
        pointer="\u276f",
        qmark="\U0001f464",
        amark="\u2705",
    ).execute()

    if action == "back":
        return

    if action == "list":
        from vxis.cli.main import client_list
        client_list()
    elif action == "add":
        _client_add_wizard()
    elif action == "show":
        client_id = inquirer.text(
            message="클라이언트 ID를 입력하세요",
            qmark="\U0001f50d",
        ).execute()
        if client_id:
            from vxis.cli.main import client_show
            client_show(client_id=client_id.strip())


def _client_add_wizard() -> None:
    """클라이언트 추가 위자드."""
    name = inquirer.text(
        message="클라이언트 이름",
        qmark="\U0001f3e2",
        validate=lambda v: len(v.strip()) > 0,
    ).execute()

    domains = inquirer.text(
        message="대상 도메인 (쉼표 구분)",
        qmark="\U0001f310",
        validate=lambda v: len(v.strip()) > 0,
    ).execute()

    industry = inquirer.text(
        message="업종 (선택사항)",
        qmark="\U0001f3ed",
        default="",
    ).execute()

    from vxis.cli.main import client_add
    client_add(
        name=name.strip(),
        domains=domains.strip(),
        industry=industry.strip(),
        contact="",
        email="",
    )
