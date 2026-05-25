"""VXIS Tool Installer — 보안 도구 자동 설치.

macOS (brew), Linux (apt/snap/pip/go), 공통 (pip/go/cargo)를 자동 감지하여
VXIS 플러그인이 필요로 하는 보안 도구를 한번에 설치합니다.
"""

from __future__ import annotations

import platform
import shutil
import subprocess

from rich.console import Console
from rich.table import Table

console = Console()

# ── 도구별 설치 방법 ────────────────────────────────────────────
# key: tool_binary name (from plugin.meta.tool_binary)
# value: dict with install methods per platform

INSTALL_RECIPES: dict[str, dict[str, str | list[str]]] = {
    # ── ProjectDiscovery suite (Go binaries, brew available) ──
    "nuclei": {
        "brew": "nuclei",
        "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "desc": "취약점 스캐너",
    },
    "httpx": {
        "brew": "httpx",
        "go": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "desc": "HTTP 프로빙",
    },
    "subfinder": {
        "brew": "subfinder",
        "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "desc": "서브도메인 열거",
    },
    # ── Network scanning ──
    "nmap": {
        "brew": "nmap",
        "apt": "nmap",
        "desc": "포트/서비스 스캔",
    },
    # ── TLS/SSL ──
    "testssl.sh": {
        "brew": "testssl",
        "apt": "testssl.sh",
        "desc": "TLS/SSL 점검",
    },
    "sslyze": {
        "pip": "sslyze",
        "desc": "SSL 설정 분석",
    },
    # ── Secrets detection ──
    "trufflehog": {
        "brew": "trufflehog",
        "go": "github.com/trufflesecurity/trufflehog/v3@latest",
        "desc": "시크릿 탐지",
    },
    "gitleaks": {
        "brew": "gitleaks",
        "go": "github.com/gitleaks/gitleaks/v8@latest",
        "desc": "Git 시크릿 스캔",
    },
    # ── WAF / DNS ──
    "wafw00f": {
        "pip": "wafw00f",
        "desc": "WAF 탐지",
    },
    "checkdmarc": {
        "pip": "checkdmarc",
        "desc": "DMARC/SPF/DKIM 점검",
    },
    "dnstwist": {
        "pip": "dnstwist",
        "brew": "dnstwist",
        "desc": "도메인 타이포스쿼팅 탐지",
    },
    # ── Cloud security ──
    "prowler": {
        "pip": "prowler",
        "desc": "AWS/Azure/GCP 보안 감사",
    },
    "s3scanner": {
        "pip": "s3scanner",
        "desc": "S3 버킷 스캐너",
    },
    "trivy": {
        "brew": "trivy",
        "apt": "trivy",
        "desc": "컨테이너/IaC/SBOM 스캔",
    },
    # ── Code analysis ──
    "semgrep": {
        "pip": "semgrep",
        "brew": "semgrep",
        "desc": "정적 코드 분석",
    },
    "bandit": {
        "pip": "bandit",
        "desc": "Python 보안 분석",
    },
    "checkov": {
        "pip": "checkov",
        "desc": "IaC 보안 점검",
    },
    # ── AD / Internal ──
    "bloodhound-python": {
        "pip": "bloodhound",
        "desc": "AD 관계 수집",
    },
    "certipy": {
        "pip": "certipy-ad",
        "desc": "AD 인증서 공격",
    },
    "nxc": {
        "pip": "netexec",
        "desc": "네트워크 인증 테스트",
    },
    # ── CI/CD ──
    "actionlint": {
        "brew": "actionlint",
        "go": "github.com/rhysd/actionlint/cmd/actionlint@latest",
        "desc": "GitHub Actions 린트",
    },
    "poutine": {
        "brew": "poutine",
        "go": "github.com/boostsecurityio/poutine@latest",
        "desc": "CI/CD 보안 스캔",
    },
    # ── Misc ──
    "shodan": {
        "pip": "shodan",
        "desc": "Shodan CLI",
    },
    "swaks": {
        "brew": "swaks",
        "apt": "swaks",
        "desc": "SMTP 테스트",
    },
    "confused": {
        "go": "github.com/visma-prodsec/confused@latest",
        "desc": "의존성 혼동 체크",
    },
    "kube-bench": {
        "brew": "kube-bench",
        "go": "github.com/aquasecurity/kube-bench@latest",
        "desc": "K8s CIS 벤치마크",
    },
    "curl": {
        "brew": "curl",
        "apt": "curl",
        "desc": "HTTP 클라이언트 (crtsh 플러그인용)",
    },
}

# 스킵할 바이너리 (OS 기본 제공 또는 설치 불필요)
_SKIP_BINARIES = {"bash", "winpeas.exe"}


def _detect_os() -> str:
    """Detect OS: 'macos', 'linux', or 'other'."""
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system == "linux":
        return "linux"
    return "other"


def _has_command(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _run_install(command: list[str], desc: str) -> bool:
    """Run an install command, showing output."""
    console.print(f"  [dim]$ {' '.join(command)}[/dim]")
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            console.print(f"  [green]✓[/green] {desc}")
            return True
        else:
            stderr = result.stderr.strip()[:200]
            console.print(f"  [red]✗[/red] {desc}: {stderr}")
            return False
    except subprocess.TimeoutExpired:
        console.print(f"  [red]✗[/red] {desc}: 타임아웃")
        return False
    except FileNotFoundError:
        console.print(f"  [red]✗[/red] {desc}: 명령어를 찾을 수 없음")
        return False


def check_tools() -> tuple[list[str], list[str]]:
    """Check which tools are installed and which are missing.

    Returns (installed, missing) lists of binary names.
    """
    installed = []
    missing = []

    for binary in sorted(INSTALL_RECIPES.keys()):
        if binary in _SKIP_BINARIES:
            continue
        if _has_command(binary):
            installed.append(binary)
        else:
            missing.append(binary)

    return installed, missing


def show_status() -> None:
    """Show installation status of all tools."""
    installed, missing = check_tools()

    table = Table(
        title="🔌 VXIS 도구 설치 현황",
        show_header=True,
        header_style="bold",
        border_style="cyan",
        expand=True,
    )
    table.add_column("도구", no_wrap=True, min_width=16)
    table.add_column("설명", min_width=16)
    table.add_column("상태", no_wrap=True, justify="center")
    table.add_column("설치 방법", min_width=10)

    os_type = _detect_os()

    for binary, recipe in sorted(INSTALL_RECIPES.items()):
        if binary in _SKIP_BINARIES:
            continue

        desc = recipe.get("desc", "")
        is_installed = _has_command(binary)
        status = "[green]✓ 설치됨[/green]" if is_installed else "[red]✗ 미설치[/red]"

        # Determine best install method
        if os_type == "macos" and "brew" in recipe:
            method = f"brew install {recipe['brew']}"
        elif os_type == "linux" and "apt" in recipe:
            method = f"apt install {recipe['apt']}"
        elif "pip" in recipe:
            method = f"pip install {recipe['pip']}"
        elif "go" in recipe:
            method = "go install ..."
        else:
            method = "—"

        table.add_row(binary, desc, status, method)

    console.print(table)
    console.print(
        f"\n  [green]✓ 설치됨: {len(installed)}개[/green]  |  "
        f"[red]✗ 미설치: {len(missing)}개[/red]  |  "
        f"총 {len(installed) + len(missing)}개"
    )

    # Plugin flag validation — check for CLI compatibility issues
    try:
        from vxis.plugins.registry import discover_plugins

        registry = discover_plugins()
        console.print("\n[bold]🔍 플러그인 CLI 호환성 검증[/bold]")
        all_warnings: list[str] = []
        for name, plugin in sorted(registry.items()):
            if not plugin.validate_environment():
                continue
            warnings = plugin.validate_flags()
            version = plugin.get_tool_version()
            if warnings:
                for w in warnings:
                    console.print(f"  [yellow]⚠ {w}[/yellow]")
                    all_warnings.append(w)
            else:
                console.print(f"  [green]✓[/green] {name} (v{version}) — 모든 플래그 정상")
        if not all_warnings:
            console.print("  [green]모든 플러그인 호환성 확인 완료[/green]")
        else:
            console.print(
                f"\n  [yellow]⚠ {len(all_warnings)}개 경고 — 플러그인 업데이트 필요[/yellow]"
            )
    except Exception:
        pass  # Registry import 실패 시 조용히 넘어감


def install_missing(selected: list[str] | None = None) -> tuple[int, int]:
    """Install missing tools. Returns (success_count, fail_count)."""
    os_type = _detect_os()
    _, missing = check_tools()

    if selected:
        to_install = [b for b in selected if b in missing]
    else:
        to_install = missing

    if not to_install:
        console.print("[green]모든 도구가 이미 설치되어 있습니다.[/green]")
        return 0, 0

    # Check package managers
    has_brew = _has_command("brew")
    has_go = _has_command("go")
    has_pip = _has_command("pip3") or _has_command("pip")
    pip_cmd = "pip3" if _has_command("pip3") else "pip"

    if os_type == "macos" and not has_brew:
        console.print("[yellow]Homebrew가 설치되어 있지 않습니다.[/yellow]")
        console.print(
            '[dim]설치: /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"[/dim]'
        )

    console.print(f"\n[bold]🔧 {len(to_install)}개 도구 설치 시작...[/bold]\n")

    success = 0
    fail = 0

    for binary in to_install:
        recipe = INSTALL_RECIPES.get(binary, {})
        desc = recipe.get("desc", binary)
        console.print(f"[bold cyan]{binary}[/bold cyan] — {desc}")

        installed = False

        # Try brew first on macOS
        if os_type == "macos" and has_brew and "brew" in recipe:
            installed = _run_install(
                ["brew", "install", recipe["brew"]],
                f"{binary} (brew)",
            )

        # Try apt on Linux
        if not installed and os_type == "linux" and "apt" in recipe:
            installed = _run_install(
                ["sudo", "apt-get", "install", "-y", recipe["apt"]],
                f"{binary} (apt)",
            )

        # Try pip
        if not installed and has_pip and "pip" in recipe:
            installed = _run_install(
                [pip_cmd, "install", recipe["pip"]],
                f"{binary} (pip)",
            )

        # Try go install
        if not installed and has_go and "go" in recipe:
            installed = _run_install(
                ["go", "install", recipe["go"]],
                f"{binary} (go)",
            )

        if not installed:
            console.print(f"  [yellow]⚠ {binary} 설치 실패 — 수동 설치 필요[/yellow]")
            fail += 1
        else:
            success += 1

        console.print()

    console.print(
        f"[bold]설치 완료:[/bold] [green]{success}개 성공[/green], [red]{fail}개 실패[/red]"
    )
    return success, fail


def install_interactive() -> None:
    """Interactive tool installer with selection."""
    from InquirerPy import inquirer

    show_status()
    console.print()

    _, missing = check_tools()
    if not missing:
        return

    action = inquirer.select(
        message="어떻게 설치할까요?",
        choices=[
            {"name": f"🚀 미설치 도구 전체 설치 ({len(missing)}개)", "value": "all"},
            {"name": "✅ 선택해서 설치", "value": "select"},
            {"name": "⬅️  뒤로", "value": "back"},
        ],
        pointer="❯",
        qmark="🔧",
        amark="✅",
    ).execute()

    if action == "back":
        return

    if action == "all":
        install_missing()
    elif action == "select":
        choices = []
        for binary in missing:
            recipe = INSTALL_RECIPES.get(binary, {})
            desc = recipe.get("desc", "")
            choices.append(
                {
                    "name": f"{binary:20s} {desc}",
                    "value": binary,
                }
            )

        selected = inquirer.checkbox(
            message="설치할 도구를 선택하세요",
            choices=choices,
            pointer="❯",
            qmark="🔌",
            instruction="(Space 선택, Enter 확인)",
        ).execute()

        if selected:
            install_missing(selected)
