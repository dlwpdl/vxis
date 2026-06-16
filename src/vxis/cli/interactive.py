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

_DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"
_DEFAULT_OLLAMA_MODEL = "qwen2.5-coder:14b"
_DEFAULT_LLAMACPP_BASE_URL = "http://localhost:8080"
_DEFAULT_LLAMACPP_CONTEXT = 8192
_DEFAULT_LLAMACPP_MODEL = (
    "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m"
)
_LOCAL_LLM_PROVIDERS = {"ollama", "llamacpp"}
_CLOUD_PROVIDER_KEYS = {
    "together": "TOGETHER_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GOOGLE_API_KEY",
    "openai": "OPENAI_API_KEY",
}


def _configure_llm_environment(
    provider: str,
    model: str,
    base_url: str | None = None,
) -> str:
    """Set process env so AgentBrain uses the selected TUI backend."""
    import os

    provider = "gemini" if provider == "google" else provider.lower()
    os.environ["UPSTREAM_LLM_PROVIDER"] = provider
    os.environ["UPSTREAM_LLM_MODEL"] = model

    if provider == "ollama":
        resolved = (base_url or os.environ.get("VXIS_OLLAMA_BASE_URL") or _DEFAULT_OLLAMA_BASE_URL).rstrip("/")
        os.environ["VXIS_OLLAMA_BASE_URL"] = resolved
        os.environ["VXIS_OLLAMA_UNCENSORED_MODEL"] = model
        os.environ["VXIS_WORKER_LLM_PROVIDER"] = provider
        os.environ["VXIS_WORKER_LLM_MODEL"] = model
        os.environ["VXIS_WORKER_LLM_BASE_URL"] = resolved
        os.environ["VXIS_SUMMARIZER_LLM_PROVIDER"] = provider
        os.environ["VXIS_SUMMARIZER_LLM_MODEL"] = model
        os.environ["VXIS_SUMMARIZER_LLM_BASE_URL"] = resolved
        return resolved

    if provider == "llamacpp":
        resolved = (
            base_url
            or os.environ.get("VXIS_LLAMACPP_BASE_URL")
            or _DEFAULT_LLAMACPP_BASE_URL
        ).rstrip("/")
        os.environ["VXIS_LLAMACPP_BASE_URL"] = resolved
        os.environ["VXIS_LLAMACPP_MODEL"] = model
        os.environ["VXIS_WORKER_LLM_PROVIDER"] = provider
        os.environ["VXIS_WORKER_LLM_MODEL"] = model
        os.environ["VXIS_WORKER_LLM_BASE_URL"] = resolved
        os.environ["VXIS_SUMMARIZER_LLM_PROVIDER"] = provider
        os.environ["VXIS_SUMMARIZER_LLM_MODEL"] = model
        os.environ["VXIS_SUMMARIZER_LLM_BASE_URL"] = resolved
        return resolved

    os.environ["VXIS_DIRECTOR_LLM_PROVIDER"] = provider
    os.environ["VXIS_DIRECTOR_LLM_MODEL"] = model
    os.environ["VXIS_VERIFIER_LLM_PROVIDER"] = provider
    os.environ["VXIS_VERIFIER_LLM_MODEL"] = model
    return ""


def _cloud_provider_key_env(provider: str) -> str:
    """Return the required API-key env var for a cloud provider."""
    return _CLOUD_PROVIDER_KEYS.get("gemini" if provider == "google" else provider, "TOGETHER_API_KEY")


def _has_cloud_provider_key(provider: str) -> bool:
    """True when the selected cloud provider has credentials in env."""
    import os

    key_env = _cloud_provider_key_env(provider)
    if provider == "openai" and os.environ.get("LLM_API_KEY"):
        return True
    return bool(os.environ.get(key_env))


def _fetch_llamacpp_models(base_url: str, timeout: float = 2.5) -> list[str]:
    """Fetch model ids from llama.cpp's OpenAI-compatible /v1/models endpoint."""
    import json
    import urllib.request

    req = urllib.request.Request(f"{base_url.rstrip('/')}/v1/models", method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []

    data = payload.get("data", [])
    if not isinstance(data, list):
        return []

    model_ids: list[str] = []
    for item in data:
        if isinstance(item, dict) and item.get("id"):
            model_ids.append(str(item["id"]))
    return model_ids


def _fetch_json_url(url: str, timeout: float = 1.0) -> dict | None:
    """Best-effort JSON fetch for local runtime auto-detection."""
    import json
    import urllib.request

    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if not 200 <= getattr(resp, "status", 200) < 500:
                return None
            body = resp.read().decode("utf-8", errors="replace")
        payload = json.loads(body)
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _fetch_llamacpp_health(base_url: str, timeout: float = 1.0) -> dict:
    """Return llama.cpp/proxy health metadata when available."""
    return _fetch_json_url(f"{base_url.rstrip('/')}/health", timeout=timeout) or {}


def _default_llamacpp_context(health: dict | None = None) -> int:
    """Resolve the llama.cpp context prompt default without dropping below 8192."""
    import os

    env_value = os.environ.get("VXIS_LLAMACPP_CONTEXT", "").strip()
    if env_value.isdigit():
        return max(512, int(env_value))

    health_value = (health or {}).get("ctx_size")
    if isinstance(health_value, int):
        return max(512, health_value)
    if isinstance(health_value, str) and health_value.strip().isdigit():
        return max(512, int(health_value.strip()))

    return _DEFAULT_LLAMACPP_CONTEXT


def _default_llamacpp_base_url() -> str:
    """Prefer the local compact proxy when it is running, otherwise llama-server."""
    import os

    env_value = os.environ.get("VXIS_LLAMACPP_BASE_URL", "").strip()
    if env_value:
        return env_value.rstrip("/")

    compact_proxy = "http://127.0.0.1:8090"
    if _fetch_json_url(f"{compact_proxy}/v1/models", timeout=0.4) is not None:
        return compact_proxy

    return _DEFAULT_LLAMACPP_BASE_URL


def _check_local_llm_ready(provider: str, base_url: str, timeout: float = 2.5) -> tuple[bool, str]:
    """Verify the selected local runtime is reachable before starting a scan."""
    import urllib.request

    provider = provider.lower()
    if provider == "ollama":
        url = f"{base_url.rstrip('/')}/api/tags"
    elif provider == "llamacpp":
        url = f"{base_url.rstrip('/')}/v1/models"
    else:
        return False, f"unsupported local provider: {provider}"

    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", 200)
            if 200 <= status < 500:
                return True, f"{provider} reachable at {base_url.rstrip('/')}"
            return False, f"{provider} returned HTTP {status}"
    except Exception as exc:
        return False, f"{provider} unreachable at {base_url.rstrip('/')}: {exc}"

# ── 스캔 카테고리 정의 ──────────────────────────────────────────

SCAN_CATEGORIES = {
    "ai_auto": {
        "name": "AI 자율 스캔 (Agent Mode)",
        "icon": "\U0001f9e0",
        "desc": "AI 에이전트가 자율적으로 정찰→취약점→공격→검증 전 과정 수행",
        "profile": "crown",
        "plugins": None,  # agent decides
        "agent_mode": True,
    },
    "zero_touch": {
        "name": "제로터치 (정보 수집만)",
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
        "name": "정보 수집만",
        "icon": "\U0001f50d",
        "desc": "공개 정보와 가벼운 확인만 수행",
    },
    "standard": {
        "name": "안전 점검",
        "icon": "\U0001f6e1\ufe0f",
        "desc": "운영 서비스용: 읽기/확인 위주, 위험한 공격 실행 차단",
    },
    "crown": {
        "name": "실전 검증",
        "icon": "\U0001f3af",
        "desc": "권장: 취약점이 실제 피해로 이어지는지 승인 범위 안에서 확인",
    },
    "stealth": {
        "name": "조용한 점검",
        "icon": "\u25cc",
        "desc": "요청을 줄이고 천천히 확인",
    },
    "aggressive": {
        "name": "랩 전체 허용",
        "icon": "\U0001f680",
        "desc": "격리된 테스트 환경 전용: 강한 공격까지 허용",
    },
}


def _profile_display(profile: str) -> str:
    """Human-readable profile label for TUI summaries."""
    prof = PROFILES.get(profile)
    if not prof:
        return profile
    return f"{prof['name']} ({profile})"


# NOW-3 #3: parallel/serial agent execution. The agent-graph worker LLM semaphore
# (VXIS_LOCAL_WORKER_CONCURRENCY) caps how many sub-agents run at once: 1 = serial
# (deterministic, low resource); >1 = parallel (faster, heavier on the model).
_PARALLEL_WORKER_COUNT = 4


def _exec_mode_to_concurrency(mode: str) -> int:
    """serial → 1 worker; parallel → _PARALLEL_WORKER_COUNT. Fail-safe to serial."""
    return _PARALLEL_WORKER_COUNT if str(mode).strip().lower() == "parallel" else 1


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
        {"name": "\U0001f3ed  산업 스캔", "value": "industry"},
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

    # Step 3: 실행 모드 (제로터치는 passive 고정)
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
            message="어느 정도까지 직접 확인할까요?",
            choices=profile_choices,
            default=cat["profile"],
            pointer="\u276f",
            qmark="\U0001f6e1\ufe0f",
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
        message="어느 정도까지 직접 확인할까요?",
        choices=profile_choices,
        default="standard",
        pointer="\u276f",
        qmark="\U0001f6e1\ufe0f",
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
            console.print("[green]Clone 완료[/green]")
        except Exception as exc:
            console.print(f"[red]Clone 실패:[/red] {exc}")
            return None

        target = clone_dir

    profile = inquirer.select(
        message="코드를 어느 깊이까지 확인할까요?",
        choices=[
            {
                "name": "\U0001f6e1\ufe0f  안전 점검 - 현재 코드와 의존성 위주로 확인 (권장)",
                "value": "standard",
            },
            {
                "name": "\U0001f680  깊은 코드 점검 - 더 오래 걸리지만 더 넓게 확인",
                "value": "aggressive",
            },
        ],
        default="standard",
        pointer="\u276f",
        qmark="\U0001f6e1\ufe0f",
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
    table.add_row("\U0001f6e1\ufe0f 실행 모드:", f"[green]{_profile_display(profile)}[/green]")

    # Plugin grid (4 columns)
    plugin_lines = []
    for i in range(0, len(plugins), 4):
        chunk = plugins[i:i + 4]
        line = "  ".join(f"\u2705 {p}" for p in chunk)
        plugin_lines.append(line)

    table.add_row(
        "\U0001f50c 플러그인:",
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

    elif action == "industry":
        _industry_menu()

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

    # AI 자율 모드
    if params.get("scan_type") == "ai_auto" or SCAN_CATEGORIES.get(params.get("scan_type", ""), {}).get("agent_mode"):
        _execute_agent_scan(params)
        return

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

    console.print(
        f"\n[bold cyan]스캔 시작:[/bold cyan] "
        f"{params['target']} ({_profile_display(params['profile'])})\n"
    )

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

    # ── 학습 결과 표시 ─────────────────────────────────────────────────────
    try:
        effective = []
        ineffective = []
        failed_tools = []

        for tr in result.tool_runs:
            plugin = tr.get("plugin", "")
            state = tr.get("state", "")
            if state == "completed":
                plugin_findings = [f for f in result.findings if f.source_plugin == plugin]
                if plugin_findings:
                    effective.append(f"\u2705 {plugin} ({len(plugin_findings)}건)")
                else:
                    ineffective.append(f"\u26aa {plugin}")
            elif state in ("failed", "timed_out"):
                err = tr.get("error", "")[:40]
                failed_tools.append(f"\u274c {plugin}: {err}")
            elif state == "skipped":
                failed_tools.append(f"\u23ed {plugin} (스킵)")

        learn_lines = ["\U0001f9e0 [bold]학습 결과[/bold]"]
        if effective:
            learn_lines.append(f"  [green]효과적:[/green] {', '.join(effective)}")
        if ineffective:
            learn_lines.append(f"  [dim]발견 없음:[/dim] {', '.join(ineffective)}")
        if failed_tools:
            learn_lines.append(f"  [red]실패/스킵:[/red] {', '.join(failed_tools)}")
        learn_lines.append("  [dim]→ 다음 스캔에 자동 반영됩니다[/dim]")

        console.print()
        console.print("\n".join(learn_lines))
    except Exception:
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


def _industry_menu() -> None:
    """산업 스캔 메인 메뉴."""
    action = inquirer.select(
        message="산업 스캔 메뉴",
        choices=[
            {"name": "\U0001f4cb  도메인 리스트로 스캔 (CSV/텍스트)", "value": "csv_scan"},
            {"name": "\U0001f50d  GitHub에서 기업 발굴", "value": "github_discover"},
            {"name": "\U0001f4ca  이전 산업 스캔 결과 보기", "value": "view_results"},
            {"name": "\U0001f4e4  아웃리치 큐 관리 (승인/거절)", "value": "outreach"},
            {"name": "\u2b05\ufe0f   뒤로", "value": "back"},
        ],
        pointer="\u276f",
        qmark="\U0001f3ed",
        amark="\u2705",
    ).execute()

    if action == "back" or action is None:
        return

    if action == "csv_scan":
        _industry_csv_scan()
    elif action == "github_discover":
        _industry_github_discover()
    elif action == "view_results":
        _industry_view_results()
    elif action == "outreach":
        _industry_outreach_menu()


def _industry_csv_scan() -> None:
    """CSV 또는 텍스트 파일로 산업 스캔을 실행합니다."""
    import asyncio
    from pathlib import Path

    source_type = inquirer.select(
        message="도메인 소스를 선택하세요",
        choices=[
            {"name": "\U0001f4c4  CSV 파일 (name, domain, industry 컬럼)", "value": "csv"},
            {"name": "\U0001f4dd  텍스트 파일 (한 줄에 도메인 하나)", "value": "text"},
            {"name": "\u2b05\ufe0f   취소", "value": "cancel"},
        ],
        pointer="\u276f",
        qmark="\U0001f4cb",
        amark="\u2705",
    ).execute()

    if source_type == "cancel" or source_type is None:
        return

    file_path = inquirer.filepath(
        message="파일 경로를 입력하세요",
        qmark="\U0001f4c1",
        amark="\u2705",
    ).execute()

    if not file_path:
        return

    file_path = file_path.strip()

    industry_name = inquirer.text(
        message="산업 분류 이름을 입력하세요",
        qmark="\U0001f3ed",
        amark="\u2705",
        default="tech",
        instruction="(예: fintech, healthcare, ecommerce)",
    ).execute()

    max_concurrent = inquirer.number(
        message="동시 스캔 수",
        default=5,
        min_allowed=1,
        max_allowed=20,
        qmark="\U0001f504",
        amark="\u2705",
    ).execute()

    profile_choices = [
        {"name": "\U0001f50d  정보 수집만 - 공개 정보와 가벼운 확인만 수행", "value": "passive"},
        {
            "name": "\U0001f6e1\ufe0f  안전 점검 - 운영 서비스용, 위험한 공격 실행 차단",
            "value": "standard",
        },
        {
            "name": "\U0001f3af  실전 검증 - 실제 피해 가능성까지 승인 범위 안에서 확인",
            "value": "crown",
        },
        {
            "name": "\U0001f680  랩 전체 허용 - 격리된 테스트 환경 전용",
            "value": "aggressive",
        },
    ]

    profile = inquirer.select(
        message="어느 정도까지 직접 확인할까요?",
        choices=profile_choices,
        default="crown",
        pointer="\u276f",
        qmark="\U0001f6e1\ufe0f",
        amark="\u2705",
    ).execute()

    # 기업 발굴
    from vxis.industry.discovery import IndustryDiscovery

    discovery = IndustryDiscovery(industry=industry_name or "tech")
    try:
        if source_type == "csv":
            companies = discovery.discover_from_csv(file_path)
        else:
            text = Path(file_path).expanduser().read_text(encoding="utf-8")
            companies = discovery.discover_from_text(text)
    except Exception as exc:
        console.print(f"[red]파일 로드 실패:[/red] {exc}")
        return

    if not companies:
        console.print("[yellow]로드된 기업이 없습니다.[/yellow]")
        return

    console.print(
        f"\n[bold cyan]{len(companies)}개 기업[/bold cyan]을 발굴했습니다. "
        f"스캔을 시작합니다...\n"
    )

    confirm = inquirer.confirm(
        message=f"{len(companies)}개 기업을 스캔할까요? ({_profile_display(profile)})",
        default=True,
        qmark="\U0001f3ed",
        amark="\u2705",
    ).execute()

    if not confirm:
        console.print("[dim]취소되었습니다.[/dim]")
        return

    # 진행 상황 콜백
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("산업 스캔 중...", total=len(companies))

        def _on_progress(completed: int, total: int, company) -> None:
            progress.update(
                task,
                completed=completed,
                description=f"[cyan]{company.name}[/cyan] 완료 ({completed}/{total})",
            )

        from vxis.industry.scanner import IndustryScanner

        scanner = IndustryScanner(
            max_concurrent=int(max_concurrent),
            on_progress=_on_progress,
        )

        try:
            result = asyncio.run(
                scanner.scan_industry(companies, profile=profile)
            )
        except Exception as exc:
            console.print(f"[red]산업 스캔 실패:[/red] {exc}")
            return

    # 결과 요약 출력
    _show_industry_summary(result)

    # 리포트 생성 여부 묻기
    _offer_heatmap_report(result)


def _industry_github_discover() -> None:
    """GitHub에서 기업을 발굴하고 스캔합니다."""
    import asyncio

    keyword = inquirer.text(
        message="검색 키워드를 입력하세요",
        qmark="\U0001f50d",
        amark="\u2705",
        instruction="(예: SaaS, fintech, security, ecommerce)",
        validate=lambda v: len(v.strip()) > 0,
        invalid_message="키워드를 입력해주세요",
    ).execute()

    if not keyword:
        return

    country = inquirer.text(
        message="국가 필터 키워드",
        qmark="\U0001f310",
        amark="\u2705",
        default="korea",
        instruction="(예: korea, japan, singapore)",
    ).execute()

    max_results = inquirer.number(
        message="최대 발굴 기업 수",
        default=30,
        min_allowed=1,
        max_allowed=100,
        qmark="\U0001f522",
        amark="\u2705",
    ).execute()

    industry_name = inquirer.text(
        message="산업 분류 이름",
        qmark="\U0001f3ed",
        amark="\u2705",
        default=keyword.strip(),
    ).execute()

    console.print(f"\n[dim]GitHub에서 기업 발굴 중 (키워드: {keyword})...[/dim]\n")

    from vxis.industry.discovery import IndustryDiscovery

    discovery = IndustryDiscovery(industry=industry_name or keyword)

    try:
        companies = discovery.discover_by_github(
            keyword=keyword.strip(),
            country=country.strip() if country else "korea",
            max_results=int(max_results),
        )
    except Exception as exc:
        console.print(f"[red]GitHub 발굴 실패:[/red] {exc}")
        console.print("[dim]gh CLI가 설치 및 인증된 상태인지 확인하세요: gh auth login[/dim]")
        return

    if not companies:
        console.print("[yellow]발굴된 기업이 없습니다.[/yellow]")
        console.print("[dim]도메인이 공개된 GitHub 조직/사용자가 필요합니다.[/dim]")
        return

    console.print(f"\n[bold cyan]{len(companies)}개 기업[/bold cyan] 발굴 완료:")
    for c in companies[:10]:
        console.print(f"  [dim]-[/dim] {c.name} ({c.domain})")
    if len(companies) > 10:
        console.print(f"  [dim]... 외 {len(companies) - 10}개[/dim]")
    console.print()

    scan_now = inquirer.confirm(
        message="발굴된 기업을 지금 바로 스캔할까요?",
        default=True,
        qmark="\U0001f680",
        amark="\u2705",
    ).execute()

    if not scan_now:
        console.print("[dim]발굴만 완료했습니다. 스캔은 나중에 CSV로 진행할 수 있습니다.[/dim]")
        # CSV로 저장 제안
        save_csv = inquirer.confirm(
            message="발굴된 기업 목록을 CSV로 저장할까요?",
            default=True,
            qmark="\U0001f4c4",
            amark="\u2705",
        ).execute()
        if save_csv:
            _save_companies_csv(companies)
        return

    max_concurrent = inquirer.number(
        message="동시 스캔 수",
        default=5,
        min_allowed=1,
        max_allowed=20,
        qmark="\U0001f504",
        amark="\u2705",
    ).execute()

    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
    from vxis.industry.scanner import IndustryScanner

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("산업 스캔 중...", total=len(companies))

        def _on_progress(completed: int, total: int, company) -> None:
            progress.update(
                task,
                completed=completed,
                description=f"[cyan]{company.name}[/cyan] 완료 ({completed}/{total})",
            )

        scanner = IndustryScanner(
            max_concurrent=int(max_concurrent),
            on_progress=_on_progress,
        )

        try:
            result = asyncio.run(scanner.scan_industry(companies, profile="standard"))
        except Exception as exc:
            console.print(f"[red]산업 스캔 실패:[/red] {exc}")
            return

    _show_industry_summary(result)
    _offer_heatmap_report(result)


def _industry_view_results() -> None:
    """이전 산업 스캔 결과(히트맵 파일) 목록을 보여줍니다."""
    from pathlib import Path

    heatmap_dir = Path.home() / ".vxis" / "industry"
    if not heatmap_dir.exists():
        console.print("[yellow]저장된 산업 스캔 결과가 없습니다.[/yellow]")
        console.print(f"[dim]결과는 {heatmap_dir} 에 저장됩니다.[/dim]")
        return

    html_files = sorted(heatmap_dir.glob("*.html"), reverse=True)
    md_files = sorted(heatmap_dir.glob("*.md"), reverse=True)

    all_files = html_files + md_files
    if not all_files:
        console.print("[yellow]저장된 파일이 없습니다.[/yellow]")
        return

    from rich.table import Table

    table = Table(
        title="\U0001f4ca 산업 스캔 결과 파일",
        show_header=True,
        header_style="bold",
        border_style="cyan",
    )
    table.add_column("파일명", style="cyan")
    table.add_column("유형")
    table.add_column("크기", justify="right")
    table.add_column("수정일")

    from datetime import datetime

    for f in all_files[:20]:
        stat = f.stat()
        size = f"{stat.st_size / 1024:.1f} KB"
        mtime = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
        ftype = "HTML" if f.suffix == ".html" else "Markdown"
        table.add_row(f.name, ftype, size, mtime)

    console.print(table)
    console.print(f"\n[dim]저장 경로: {heatmap_dir}[/dim]")


def _industry_outreach_menu() -> None:
    """아웃리치 큐 관리 메뉴 (승인/거절)."""
    from vxis.industry.outreach import OutreachQueue

    queue = OutreachQueue()

    action = inquirer.select(
        message="아웃리치 큐 관리",
        choices=[
            {"name": "\U0001f4cb  대기 중인 항목 보기", "value": "list_pending"},
            {"name": "\u2705  항목 승인", "value": "approve"},
            {"name": "\u274c  항목 거절", "value": "reject"},
            {"name": "\U0001f4cb  전체 큐 보기", "value": "list_all"},
            {"name": "\u2b05\ufe0f   뒤로", "value": "back"},
        ],
        pointer="\u276f",
        qmark="\U0001f4e4",
        amark="\u2705",
    ).execute()

    if action == "back" or action is None:
        return

    if action in ("list_pending", "list_all"):
        items = queue.get_pending() if action == "list_pending" else queue.get_all()
        if not items:
            console.print("[yellow]항목이 없습니다.[/yellow]")
            return

        from rich.table import Table

        status_colors = {
            "pending": "yellow", "approved": "green",
            "rejected": "red", "sent": "blue",
        }
        table = Table(
            title="\U0001f4e4 아웃리치 큐",
            show_header=True, header_style="bold", border_style="cyan",
        )
        table.add_column("ID (앞 8자)", style="dim")
        table.add_column("기업명")
        table.add_column("도메인")
        table.add_column("등급")
        table.add_column("상태")
        table.add_column("생성일")

        for item in items:
            status = item.status
            color = status_colors.get(status, "white")
            table.add_row(
                item.item_id[:8],
                item.company.name,
                item.company.domain,
                item.company.security_grade or "-",
                f"[{color}]{status}[/{color}]",
                item.created_at[:10] if item.created_at else "-",
            )
        console.print(table)
        console.print(
            "\n[dim]승인/거절하려면 '아웃리치 큐 관리'에서 해당 액션을 선택하세요.[/dim]"
        )

    elif action in ("approve", "reject"):
        pending = queue.get_pending()
        if not pending:
            console.print("[yellow]대기 중인 항목이 없습니다.[/yellow]")
            return

        item_choices = [
            {
                "name": f"{item.item_id[:8]} — {item.company.name} ({item.company.domain})",
                "value": item.item_id,
            }
            for item in pending
        ]

        selected_id = inquirer.select(
            message="항목을 선택하세요",
            choices=item_choices,
            pointer="\u276f",
            qmark="\U0001f4e4",
            amark="\u2705",
        ).execute()

        if not selected_id:
            return

        notes = inquirer.text(
            message="메모를 입력하세요 (선택사항)",
            qmark="\U0001f4dd",
            amark="\u2705",
        ).execute()

        try:
            if action == "approve":
                updated = queue.approve(selected_id, notes=notes or "")
                console.print(
                    f"[green]승인됨:[/green] {updated.company.name} ({updated.item_id[:8]})"
                )
                console.print(
                    "[dim]주의: 실제 발송은 사람이 직접 처리해야 합니다. "
                    "VXIS는 자동 발송하지 않습니다.[/dim]"
                )
            else:
                updated = queue.reject(selected_id, reason=notes or "")
                console.print(
                    f"[red]거절됨:[/red] {updated.company.name} ({updated.item_id[:8]})"
                )
        except Exception as exc:
            console.print(f"[red]처리 실패:[/red] {exc}")


def _show_industry_summary(result: object) -> None:
    """산업 스캔 결과 요약을 콘솔에 출력합니다."""
    from rich.table import Table

    console.print(
        f"\n[bold green]산업 스캔 완료[/bold green] "
        f"({getattr(result, 'scan_duration', 0):.0f}초) — "
        f"[bold]{getattr(result, 'total_companies', 0)}[/bold]개 기업 분석\n"
    )

    grade_dist = getattr(result, "grade_distribution", {})
    avg_grade = getattr(result, "average_grade", "N/A")

    grade_table = Table(
        title="\U0001f4ca 보안 등급 분포",
        show_header=True, header_style="bold", border_style="cyan",
    )
    grade_table.add_column("등급", width=8)
    grade_table.add_column("기업 수", justify="right")

    grade_colors = {"A": "green", "B": "blue", "C": "yellow", "D": "red", "F": "bold red"}
    for grade in ["A", "B", "C", "D", "F"]:
        count = grade_dist.get(grade, 0)
        color = grade_colors.get(grade, "white")
        grade_table.add_row(f"[{color}]{grade}[/{color}]", str(count))

    console.print(grade_table)
    console.print(f"\n  평균 등급: [bold cyan]{avg_grade}[/bold cyan]")

    findings = getattr(result, "industry_findings", {})
    console.print(
        f"  Critical: [red]{findings.get('critical', 0)}[/red] | "
        f"High: [yellow]{findings.get('high', 0)}[/yellow] | "
        f"총 취약점: {sum(findings.values())}"
    )
    console.print()


def _offer_heatmap_report(result: object) -> None:
    """히트맵 리포트 생성 여부를 묻고 파일로 저장합니다."""
    from pathlib import Path

    gen_report = inquirer.confirm(
        message="히트맵 리포트를 생성할까요?",
        default=True,
        qmark="\U0001f4ca",
        amark="\u2705",
    ).execute()

    if not gen_report:
        return

    fmt = inquirer.select(
        message="리포트 형식을 선택하세요",
        choices=[
            {"name": "\U0001f310  HTML (시각적 히트맵)", "value": "html"},
            {"name": "\U0001f4dd  Markdown (텍스트)", "value": "md"},
            {"name": "\u2705  둘 다", "value": "both"},
        ],
        pointer="\u276f",
        qmark="\U0001f4ca",
        amark="\u2705",
    ).execute()

    if not fmt:
        return

    from datetime import datetime as _dt
    from vxis.industry.heatmap import generate_heatmap_report, generate_heatmap_html

    save_dir = Path.home() / ".vxis" / "industry"
    save_dir.mkdir(parents=True, exist_ok=True)
    ts = _dt.now().strftime("%Y%m%d_%H%M%S")

    saved = []

    if fmt in ("html", "both"):
        try:
            html_content = generate_heatmap_html(result)
            html_path = save_dir / f"industry_heatmap_{ts}.html"
            html_path.write_text(html_content, encoding="utf-8")
            saved.append(str(html_path))
        except Exception as exc:
            console.print(f"[red]HTML 리포트 생성 실패:[/red] {exc}")

    if fmt in ("md", "both"):
        try:
            md_content = generate_heatmap_report(result)
            md_path = save_dir / f"industry_heatmap_{ts}.md"
            md_path.write_text(md_content, encoding="utf-8")
            saved.append(str(md_path))
        except Exception as exc:
            console.print(f"[red]Markdown 리포트 생성 실패:[/red] {exc}")

    for path in saved:
        console.print(f"[green]리포트 저장됨:[/green] {path}")


def _save_companies_csv(companies: list) -> None:
    """발굴된 기업 목록을 CSV 파일로 저장합니다."""
    import csv
    from datetime import datetime as _dt
    from pathlib import Path

    save_dir = Path.home() / ".vxis" / "industry"
    save_dir.mkdir(parents=True, exist_ok=True)
    ts = _dt.now().strftime("%Y%m%d_%H%M%S")
    csv_path = save_dir / f"discovered_{ts}.csv"

    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["name", "domain", "industry", "notes"])
        writer.writeheader()
        for c in companies:
            writer.writerow({
                "name": c.name,
                "domain": c.domain,
                "industry": c.industry,
                "notes": c.notes,
            })

    console.print(f"[green]CSV 저장됨:[/green] {csv_path}")


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


def _select_local_llm() -> tuple[str, str, str] | None:
    """Prompt for a local LLM runtime and return (provider, model, base_url)."""
    import os

    runtime = inquirer.select(
        message="로컬 AI 런타임을 선택하세요",
        choices=[
            {"name": "Ollama — http://localhost:11434", "value": "ollama"},
            {"name": "llama.cpp server — OpenAI-compatible /v1", "value": "llamacpp"},
            {"name": "취소", "value": "cancel"},
        ],
        pointer="\u276f",
        qmark="\U0001f9e0",
        amark="\u2705",
    ).execute()

    if runtime in (None, "cancel"):
        return None

    def _prompt_context_window(
        *,
        message: str,
        env_key: str,
        default: int,
        minimum: int,
        maximum: int,
    ) -> int | None:
        raw = inquirer.text(
            message=message,
            default=os.environ.get(env_key, str(default)),
            qmark="\U0001f9e0",
            amark="\u2705",
            validate=lambda value: (
                value.strip().isdigit()
                and minimum <= int(value.strip()) <= maximum
            ),
            invalid_message=f"{minimum}~{maximum} 사이의 정수를 입력하세요",
        ).execute()
        if not raw:
            return None
        value = int(raw.strip())
        os.environ[env_key] = str(value)
        return value

    if runtime == "ollama":
        base_url = inquirer.text(
            message="Ollama base URL",
            default=os.environ.get("VXIS_OLLAMA_BASE_URL", _DEFAULT_OLLAMA_BASE_URL),
            qmark="\U0001f9e0",
            amark="\u2705",
        ).execute()
        if not base_url:
            return None

        if _prompt_context_window(
            message="Ollama context window",
            env_key="VXIS_OLLAMA_CONTEXT",
            default=32768,
            minimum=2048,
            maximum=262144,
        ) is None:
            return None

        model = inquirer.select(
            message="Ollama 모델을 선택하세요",
            choices=[
                {"name": "Qwen 2.5 Coder 14B (권장 기본값)", "value": _DEFAULT_OLLAMA_MODEL},
                {"name": "WhiteRabbitNeo 13B (무검열 연구)", "value": "whiterabbitneo:13b"},
                {"name": "Dolphin Mixtral 8x7B (범용)", "value": "dolphin-mixtral:8x7b"},
                {"name": "Custom Ollama model id", "value": "__custom__"},
            ],
            pointer="\u276f",
            qmark="\U0001f9e0",
            amark="\u2705",
        ).execute()

        if model == "__custom__":
            custom_model = inquirer.text(
                message="Ollama model id를 입력하세요",
                default=os.environ.get("VXIS_OLLAMA_UNCENSORED_MODEL", _DEFAULT_OLLAMA_MODEL),
                qmark="\U0001f9e0",
                amark="\u2705",
            ).execute()
            if not custom_model:
                console.print("[red]model id가 필요합니다.[/red]")
                return None
            model = custom_model.strip()

        return ("ollama", model, base_url.strip().rstrip("/"))

    base_url = inquirer.text(
        message="llama.cpp server base URL",
        default=_default_llamacpp_base_url(),
        qmark="\U0001f9e0",
        amark="\u2705",
    ).execute()
    if not base_url:
        return None
    base_url = base_url.strip().rstrip("/")
    health = _fetch_llamacpp_health(base_url)
    context_default = _default_llamacpp_context(health)

    if _prompt_context_window(
        message="llama.cpp context window (-c/--ctx-size와 맞추세요)",
        env_key="VXIS_LLAMACPP_CONTEXT",
        default=context_default,
        minimum=512,
        maximum=131072,
    ) is None:
        return None

    detected_models: list[str] = []
    try:
        detected_models = _fetch_llamacpp_models(base_url)
    except Exception:
        detected_models = []

    choices = []
    if detected_models:
        choices.append(Separator(f"── detected from {base_url}/v1/models ──"))
        choices.extend({"name": model_id, "value": model_id} for model_id in detected_models)
    else:
        console.print(
            f"[yellow]llama.cpp 서버 모델 목록을 읽지 못했습니다:[/yellow] {base_url}/v1/models"
        )

    choices.extend([
        Separator("── fallback/default ──"),
        {
            "name": f"Huihui Qwen3.6 35B A3B Q4_K_M ({_DEFAULT_LLAMACPP_MODEL})",
            "value": _DEFAULT_LLAMACPP_MODEL,
        },
        {"name": "Custom llama.cpp model id", "value": "__custom__"},
    ])

    model = inquirer.select(
        message="llama.cpp 모델을 선택하세요",
        choices=choices,
        pointer="\u276f",
        qmark="\U0001f9e0",
        amark="\u2705",
    ).execute()

    if model == "__custom__":
        custom_model = inquirer.text(
            message="llama.cpp 서버의 model id를 입력하세요",
            default=os.environ.get("VXIS_LLAMACPP_MODEL", _DEFAULT_LLAMACPP_MODEL),
            qmark="\U0001f9e0",
            amark="\u2705",
        ).execute()
        if not custom_model:
            console.print("[red]model id가 필요합니다.[/red]")
            return None
        model = custom_model.strip()

    if not model:
        return None
    return ("llamacpp", model, base_url)


def _run_brain_first_scan_from_tui(
    target: str,
    profile: str,
    *,
    allow_inject: bool = False,
    box_mode: str = "black",
) -> None:
    """Delegate TUI AI mode to the same Brain-first pipeline as `vxis scan`."""
    import typer

    from vxis.cli.main import scan as run_scan

    try:
        run_scan(
            target=target,
            manifest=None,
            profile=profile,
            ghost=False,
            output=None,
            no_report=False,
            resume=None,
            interactive=False,
            verbose=False,
            allow_inject=allow_inject,
            plugins=None,
            kind="web",
            box=box_mode,
        )
    except typer.Exit as exc:
        if exc.exit_code not in (0, None):
            console.print(f"[red]Brain-first scan exited with code {exc.exit_code}[/red]")


def _execute_agent_scan(params: dict) -> None:
    """AI 자율 에이전트 모드 실행."""
    import os

    target = params["target"]
    profile = params.get("profile", "crown")

    source_class = inquirer.select(
        message="AI 두뇌 소스를 선택하세요",
        choices=[
            {"name": "Cloud API — OpenAI / Anthropic / Gemini / Together", "value": "cloud"},
            {"name": "Local Runtime — Ollama / llama.cpp", "value": "local"},
        ],
        pointer="\u276f",
        qmark="\U0001f9e0",
        amark="\u2705",
        instruction="(↑↓ 방향키)",
    ).execute()

    if source_class is None:
        return

    if source_class == "local":
        local_selection = _select_local_llm()
        if local_selection is None:
            return
        provider, model, base_url = local_selection
    else:
        llm_choices = [
            Separator("── Together.ai (통합 게이트웨이) ──"),
            {"name": "\U0001f9e0 Kimi-K2.5 (1T params, 추론 특화, 권장)", "value": ("together", "moonshotai/Kimi-K2.5")},
            {"name": "\U0001f9e0 GLM-5 (744B params, 에이전트 특화)", "value": ("together", "zai-org/GLM-5")},
            {"name": "\U0001f9e0 DeepSeek-R1 (추론 체인)", "value": ("together", "deepseek-ai/DeepSeek-R1")},
            {"name": "\U0001f9e0 DeepSeek-V3 (범용)", "value": ("together", "deepseek-ai/DeepSeek-V3")},
            {"name": "\U0001f9e0 Qwen-72B (빠른 응답)", "value": ("together", "Qwen/Qwen2.5-72B-Instruct-Turbo")},
            {"name": "\U0001f9e0 Llama-3.3-70B (오픈소스)", "value": ("together", "meta-llama/Llama-3.3-70B-Instruct-Turbo")},
            Separator("── 직접 연결 (API 키 필요) ──"),
            {"name": "\U0001f7e3 Claude Opus 4.6 (Anthropic, 최강)", "value": ("anthropic", "claude-opus-4-6")},
            {"name": "\U0001f7e3 Claude Sonnet 4.6 (Anthropic, 균형)", "value": ("anthropic", "claude-sonnet-4-6")},
            {"name": "\U0001f7e2 Gemini 3.1 Pro (Google, 최신)", "value": ("gemini", "gemini-3.1-pro")},
            {"name": "\U0001f7e2 Gemini 2.5 Flash (Google, 빠름)", "value": ("gemini", "gemini-2.5-flash")},
            {"name": "\U0001f535 GPT-5.4 (OpenAI, 최신)", "value": ("openai", "gpt-5.4")},
            {"name": "\U0001f535 GPT-4o Mini (OpenAI, 저렴)", "value": ("openai", "gpt-4o-mini")},
        ]

        llm_selection = inquirer.select(
            message="AI 에이전트의 두뇌를 선택하세요",
            choices=llm_choices,
            pointer="\u276f",
            qmark="\U0001f9e0",
            amark="\u2705",
            instruction="(↑↓ 방향키)",
        ).execute()

        if llm_selection is None:
            return

        provider, model = llm_selection
        base_url = ""

    resolved_base_url = _configure_llm_environment(provider, model, base_url)

    if provider in _LOCAL_LLM_PROVIDERS:
        ready, message = _check_local_llm_ready(provider, resolved_base_url)
        if not ready:
            console.print(f"[red]{message}[/red]")
            if provider == "llamacpp":
                console.print(
                    "[dim]먼저 llama-server를 실행하세요. 예: "
                    "llama-server -m /path/to/model.gguf --host 127.0.0.1 --port 8080[/dim]"
                )
            return
        console.print(f"[green]{message}[/green]")

    # Check API key
    if provider not in _LOCAL_LLM_PROVIDERS and not _has_cloud_provider_key(provider):
        key_env = _cloud_provider_key_env(provider)
        api_key = inquirer.secret(
            message=f"{key_env}를 입력하세요",
            qmark="\U0001f511",
            amark="\u2705",
        ).execute()

        if api_key:
            os.environ[key_env] = api_key.strip()
        else:
            console.print("[red]API 키가 필요합니다.[/red]")
            return

    model_short = model.split("/")[-1] if "/" in model else model

    # Execution permission 선택 — AI reasoning stays broad; target actions stay inside this bound.
    # NOW-3 #2: each option carries an attack-level badge derived from the
    # profile ScanPolicy ceiling (●●● = full), so the attack level is
    # quantified right at the choice ("공격레벨 수치화").
    from vxis.agent.policy.scan_policy import attack_level_badge

    _ceiling_opts = [
        ("passive", "\U0001f50d", "정보 수집만", "공개 정보와 가벼운 확인만 수행"),
        ("standard", "\U0001f6e1\ufe0f", "안전 점검", "읽기/확인 위주, 위험한 공격 실행 차단"),
        ("crown", "\U0001f3af", "실전 검증", "실제 피해 가능성까지 승인 범위 안에서 확인 (권장)"),
        ("aggressive", "\U0001f680", "랩 전체 허용", "격리/명시 승인 환경에서만 강한 공격 허용"),
    ]
    _ceiling_choices = [
        {
            "name": f"{icon}  [공격력 {attack_level_badge(value)['bars']}] {label} - {desc}",
            "value": value,
        }
        for value, icon, label, desc in _ceiling_opts
    ]
    ceiling = inquirer.select(
        message="AI가 어디까지 직접 실행해도 될까요?  (공격력 ○○○ → ●●●)",
        choices=_ceiling_choices,
        default="crown",
        pointer="\u276f",
        qmark="\U0001f6e1\ufe0f",
        amark="\u2705",
        instruction="AI는 넓게 생각하되, 실제 실행은 이 선택 안에서만 진행합니다",
    ).execute()

    if ceiling is None:
        return

    # User-facing execution permission -> internal profile.
    ceiling_profile_map = {
        "passive": "passive",
        "standard": "standard",
        "crown": "crown",
        "aggressive": "aggressive",
    }
    profile = ceiling_profile_map.get(ceiling, "crown")

    # NOW-3 #3: parallel vs serial agent execution — sets the agent-graph worker
    # LLM concurrency (VXIS_LOCAL_WORKER_CONCURRENCY) for this run.
    import os as _os_exec

    exec_mode = inquirer.select(
        message="에이전트 실행 방식을 선택하세요",
        choices=[
            {"name": "🧵  직렬 - 한 번에 하나씩 (안정적 · 저비용 · 권장)", "value": "serial"},
            {"name": "⚡  병렬 - 여러 작업 동시 (빠름 · 모델 부하 큼)", "value": "parallel"},
        ],
        default="serial",
        pointer="❯",
        qmark="🧵",
        amark="✅",
    ).execute()
    if exec_mode is None:
        return
    _worker_n = _exec_mode_to_concurrency(exec_mode)
    _os_exec.environ["VXIS_LOCAL_WORKER_CONCURRENCY"] = str(_worker_n)
    _exec_mode_kr = "병렬" if exec_mode == "parallel" else "직렬"

    ceiling_kr = {
        "passive": "정보 수집만",
        "standard": "안전 점검",
        "crown": "실전 검증",
        "aggressive": "랩 전체 허용",
    }

    _badge = attack_level_badge(profile)
    console.print()
    console.print(Panel(
        f"[bold cyan]\U0001f9e0 VXIS AI Agent Mode[/bold cyan]\n\n"
        f"\U0001f3af 타겟: [white]{target}[/white]\n"
        f"⚫ 박스 모드: [white]블랙박스[/white] "
        f"[dim](외부 공격자 시점 · 소스/내부 정보 접근 없음)[/dim]\n"
        f"\U0001f6e1\ufe0f 실행 허용 범위: [yellow]{ceiling_kr.get(ceiling, ceiling)}[/yellow]\n"
        f"\U0001f4ca 공격 레벨: [bold]{_badge['bars']}[/bold] "
        f"[dim]{_badge['ceiling']}"
        f"{' · ' + ', '.join(_badge['flags']) if _badge['flags'] else ''}[/dim]\n"
        f"\U0001f9f5 실행 방식: [white]{_exec_mode_kr}[/white] [dim](동시 워커 {_worker_n})[/dim]\n"
        f"\U0001f9e0 AI 모델: [green]{model_short}[/green] ({provider})\n\n"
        f"[dim]AI는 넓게 생각하지만, 실제 요청과 공격 실행은 선택한 범위 안에서만 진행합니다.\n"
        f"정보 수집만 모드에서도 공개 정보에서 중요한 위험이 보이면 보고합니다.[/dim]",
        title="\U0001f9e0 Autonomous Pentesting",
        border_style="cyan",
    ))
    console.print()

    # NOW-3 #1: the web agent path is always black-box — pass it explicitly so the
    # pipeline ENFORCES "완전히 블랙박스" (no source-aware tools), not just derives it.
    _run_brain_first_scan_from_tui(
        target=target,
        profile=profile,
        allow_inject=False,
        box_mode="black",
    )


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
