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
            "subfinder", "httpx", "nmap", "nuclei", "testssl",
            "sslyze", "checkdmarc", "wafw00f", "trufflehog",
            "gitleaks", "crtsh", "dnstwist", "shodan",
        ],
    },
    "internal": {
        "name": "내부 스캔 (Internal)",
        "icon": "\U0001f3e2",
        "desc": "Active Directory / 내부 네트워크 환경 진단",
        "profile": "standard",
        "tier": 2,
        "plugins": [
            "nmap", "bloodhound", "certipy", "netexec", "linpeas",
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
            "prowler", "s3scanner", "trivy-k8s", "kube-bench",
        ],
    },
    "full": {
        "name": "풀 스캔 (Full)",
        "icon": "\U0001f680",
        "desc": "외부 + 코드 + 클라우드 모든 플러그인 전체 실행",
        "profile": "standard",
        "plugins": None,  # None = all available plugins
    },
    "batch": {
        "name": "PE 포트폴리오 (Batch)",
        "icon": "\U0001f4ca",
        "desc": "CSV 파일의 다수 대상 일괄 스캔 + 리스크 등급 리포트",
        "profile": "standard",
        "plugins": [],
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

    # 코드 스캔은 별도 입력 플로우
    if scan_type == "code":
        return _code_scan_wizard(cat)

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


def _code_scan_wizard(cat: dict) -> dict | None:
    """코드 스캔 위자드 — GitHub URL 또는 로컬 경로 입력."""

    source_type = inquirer.select(
        message="소스 코드 위치를 선택하세요",
        choices=[
            {"name": "\U0001f4c2  로컬 경로 (현재 디렉토리 또는 지정 경로)", "value": "local"},
            {"name": "\U0001f310  GitHub URL (자동 clone 후 스캔)", "value": "github"},
            {"name": "\u2b05\ufe0f   취소", "value": "cancel"},
        ],
        pointer="\u276f",
        qmark="\U0001f4bb",
        amark="\u2705",
    ).execute()

    if source_type == "cancel":
        return None

    if source_type == "local":
        path = inquirer.text(
            message="스캔할 경로를 입력하세요",
            qmark="\U0001f4c2",
            amark="\u2705",
            default=".",
            instruction="(현재 디렉토리: .)",
        ).execute()

        if not path:
            return None

        import os
        target = os.path.abspath(path.strip())

        if not os.path.isdir(target):
            console.print(f"[red]경로를 찾을 수 없습니다: {target}[/red]")
            return None

    else:
        # GitHub URL → clone
        repo_url = inquirer.text(
            message="GitHub 저장소 URL을 입력하세요",
            qmark="\U0001f310",
            amark="\u2705",
            instruction="(예: https://github.com/owner/repo)",
            validate=lambda v: "github.com" in v or "gitlab.com" in v or len(v.strip()) > 0,
        ).execute()

        if not repo_url:
            return None

        repo_url = repo_url.strip()
        if not repo_url.startswith("http"):
            repo_url = f"https://github.com/{repo_url}"

        import tempfile
        import subprocess

        clone_dir = tempfile.mkdtemp(prefix="vxis_codescan_")
        console.print(f"[dim]Cloning {repo_url} → {clone_dir}...[/dim]")

        try:
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, clone_dir],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode != 0:
                console.print(f"[red]Clone 실패:[/red] {result.stderr[:200]}")
                return None
            console.print(f"[green]Clone 완료[/green]")
        except Exception as exc:
            console.print(f"[red]Clone 실패:[/red] {exc}")
            return None

        target = clone_dir

    profile = inquirer.select(
        message="스캔 강도를 선택하세요",
        choices=[
            {"name": "\u26a1  Standard (권장)", "value": "standard"},
            {"name": "\U0001f680  Aggressive (전체 히스토리 포함)", "value": "aggressive"},
        ],
        default="standard",
        pointer="\u276f",
        qmark="\u26a1",
        amark="\u2705",
    ).execute()

    selected_plugins = cat["plugins"]

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
        "target": target,
        "profile": profile,
        "plugins": selected_plugins,
        "scan_type": "code",
        "tier": 1,
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
    """리포트 생성/내보내기 메뉴. 최근 스캔 목록을 먼저 보여줌."""
    import asyncio

    # 최근 스캔 목록 표시
    try:
        from vxis.config.schema import VXISConfig
        from vxis.core.db import create_engine as _ce, get_session as _gs
        from vxis.models.db_models import FindingRecord, ScanRecord
        from sqlalchemy import func, select

        config = VXISConfig()
        db_url = config.db_url
        if ":///" in db_url:
            prefix, path = db_url.split("///", 1)
            from pathlib import Path as _P
            db_url = f"{prefix}///{_P(path).expanduser()}"

        async def _list_scans():
            engine = _ce(db_url)
            try:
                async with _gs(engine) as session:
                    r = await session.execute(
                        select(ScanRecord).order_by(ScanRecord.started_at.desc()).limit(10)
                    )
                    scans = list(r.scalars().all())
                    scan_info = []
                    for s in scans:
                        cr = await session.execute(
                            select(func.count(FindingRecord.id)).where(FindingRecord.scan_id == s.id)
                        )
                        count = cr.scalar_one_or_none() or 0
                        time_str = s.started_at.strftime("%m-%d %H:%M") if s.started_at else "—"
                        scan_info.append((s.id, s.target, s.profile, count, time_str))
                    return scan_info
            finally:
                await engine.dispose()

        scans = asyncio.run(_list_scans())
        if scans:
            table = Table(
                title="\U0001f4cb 최근 스캔 목록",
                show_header=True, header_style="bold",
                border_style="cyan", expand=False,
            )
            table.add_column("ID", style="bold cyan")
            table.add_column("대상")
            table.add_column("프로필")
            table.add_column("발견", justify="right")
            table.add_column("시간")
            for sid, target, profile, count, time_str in scans:
                table.add_row(str(sid), target, profile, str(count), time_str)
            console.print(table)
            console.print()
        else:
            console.print("[yellow]스캔 기록이 없습니다.[/yellow]")
            return None
    except Exception:
        pass  # DB 연결 실패 시 ID 직접 입력으로 진행

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

    # ── Delta report (compare with previous scan) ─────────────────────────
    scan_id_str = str(getattr(result, "scan_id", ""))
    if scan_id_str:
        try:
            from vxis.config.schema import VXISConfig as _VXISConfig
            from vxis.core.db import create_engine as _create_engine
            from vxis.core.delta import compute_delta, format_delta_summary, get_previous_scan_findings

            _config = _VXISConfig()
            _db_url = _config.db_url
            if ":///" in _db_url:
                _prefix, _path = _db_url.split("///", 1)
                from pathlib import Path as _Path
                _db_url = f"{_prefix}///{_Path(_path).expanduser()}"

            _delta_engine = _create_engine(_db_url)

            async def _fetch_delta():
                prev_findings, prev_id = await get_previous_scan_findings(
                    _delta_engine, params["target"], scan_id_str
                )
                await _delta_engine.dispose()
                return prev_findings, prev_id

            _prev_findings, _prev_id = asyncio.run(_fetch_delta())

            if _prev_findings:
                console.print()
                _delta = compute_delta(
                    current_findings=result.findings,
                    previous_findings=_prev_findings,
                    target=params["target"],
                    current_scan_id=scan_id_str,
                    previous_scan_id=_prev_id,
                )
                console.print(format_delta_summary(_delta))
        except Exception:
            # Delta comparison is optional — silently skip on any error
            pass

    # ── Post-scan action menu ─────────────────────────────────────────────
    console.print()
    try:
        from InquirerPy import inquirer as _post_inquirer

        post_action = _post_inquirer.select(
            message="다음 작업을 선택하세요",
            choices=[
                {"name": "\U0001f4c4  리포트 생성 (HTML)", "value": "report_html"},
                {"name": "\U0001f4d8  리포트 생성 (DOCX)", "value": "report_docx"},
                {"name": "\U0001f4ca  결과 상세 보기", "value": "detail"},
                {"name": "\U0001f310  대시보드에서 보기", "value": "dashboard"},
                {"name": "\u2b05\ufe0f   메인 메뉴로", "value": "back"},
            ],
            pointer="\u276f",
            qmark="\u2705",
            amark="\u2705",
        ).execute()
    except KeyboardInterrupt:
        return

    if post_action == "back" or post_action is None:
        return

    if post_action in ("report_html", "report_docx"):
        _report_fmt = "html" if post_action == "report_html" else "docx"
        _safe_target = params["target"].replace("/", "_").replace(":", "_")
        _report_ext = _report_fmt
        _report_path = f"report_{_safe_target}.{_report_ext}"

        if post_action == "report_html":
            try:
                from datetime import date as _date
                from vxis.report.generator import ReportData, ReportGenerator

                _report_data = ReportData(
                    scan_id=scan_id_str,
                    client_name=params["target"],
                    target=params["target"],
                    scan_date=_date.today().isoformat(),
                    findings=result.findings,
                )
                _html = ReportGenerator().render_html(_report_data)
                with open(_report_path, "w", encoding="utf-8") as _fh:
                    _fh.write(_html)
                console.print(f"[green]HTML 리포트 저장됨:[/green] {_report_path}")
            except Exception as _exc:
                console.print(f"[red]HTML 리포트 생성 실패:[/red] {_exc}")

        else:  # report_docx
            try:
                from vxis.report.docx_export import DOCXReportGenerator
            except ImportError:
                console.print(
                    "[yellow]DOCX 내보내기를 사용할 수 없습니다.[/yellow] "
                    "python-docx 패키지를 설치하세요: pip install python-docx"
                )
                return

            try:
                from datetime import date as _date
                from pathlib import Path as _Path
                from vxis.report.generator import ReportData

                _report_data = ReportData(
                    scan_id=scan_id_str,
                    client_name=params["target"],
                    target=params["target"],
                    scan_date=_date.today().isoformat(),
                    findings=result.findings,
                )
                DOCXReportGenerator().generate(_report_data, _Path(_report_path))
                console.print(f"[green]DOCX 리포트 저장됨:[/green] {_report_path}")
            except Exception as _exc:
                console.print(f"[red]DOCX 리포트 생성 실패:[/red] {_exc}")

    elif post_action == "detail":
        if not result.findings:
            console.print("[dim]발견된 취약점이 없습니다.[/dim]")
            return

        _sev_colors = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "blue", "informational": "dim",
        }
        _detail_table = Table(
            title=f"\U0001f50d 취약점 목록 — {params['target']}",
            show_header=True,
            header_style="bold",
            border_style="cyan",
            expand=False,
        )
        _detail_table.add_column("심각도", no_wrap=True, width=12)
        _detail_table.add_column("제목", no_wrap=False)
        _detail_table.add_column("대상", no_wrap=True)
        _detail_table.add_column("신뢰도", justify="right", width=7)

        _sev_order_map = {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4,
        }
        _sorted = sorted(
            result.findings,
            key=lambda _f: _sev_order_map.get(
                _f.effective_severity.value if hasattr(_f.effective_severity, "value")
                else str(_f.effective_severity),
                5,
            ),
        )
        for _f in _sorted:
            _sev_val = (
                _f.effective_severity.value
                if hasattr(_f.effective_severity, "value")
                else str(_f.effective_severity)
            )
            _style = _sev_colors.get(_sev_val, "")
            _conf_pct = f"{int(_f.confidence * 100)}%"
            _detail_table.add_row(
                f"[{_style}]{_sev_val}[/{_style}]",
                _f.title[:60],
                _f.target[:40],
                _conf_pct,
            )
        console.print(_detail_table)

    elif post_action == "dashboard":
        console.print(
            "[cyan]대시보드 URL:[/cyan] http://127.0.0.1:8080"
            + (f"/scan/{scan_id_str}" if scan_id_str else "")
        )
        console.print("[dim]vxis dashboard 명령으로 서버를 시작할 수 있습니다.[/dim]")


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
