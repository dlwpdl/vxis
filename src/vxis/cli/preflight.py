"""Pre-flight checks for VXIS scan — validate environment before pipeline starts."""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
import urllib.request


@dataclass
class PreflightResult:
    """스캔 시작 전 환경 검증 결과."""
    target_reachable: bool = False
    target_latency_ms: float = 0.0
    brain_backend: str = "unknown"  # "claude-code" | "api" | "none"
    brain_ready: bool = False
    docker_available: bool = False
    github_token: bool = False
    proxy_pool_size: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def can_scan(self) -> bool:
        """스캔 가능 여부 — target 도달 + Brain 준비되어야 함."""
        return self.target_reachable and self.brain_ready

    @property
    def has_warnings(self) -> bool:
        return len(self.warnings) > 0


def check_target_reachable(
    target: str, timeout: float = 5.0, kind: str = "web"
) -> tuple[bool, float]:
    """타겟 도달 가능 여부 체크.

    kind="web"  → HTTP HEAD/GET 시도 (URL/도메인 가정)
    kind="desktop" → 파일 시스템 경로 존재 여부 (.app/.exe/binary path)
    kind="mobile"/"game" → 일단 web 과 동일 (URL 입력 받는 형태). 후속 phase
        에서 ipa/apk/proto:port 형태로 분기 추가 예정.
    """
    import time

    if kind == "desktop":
        # macOS .app 번들이 들어오면 내부 Mach-O 까지 들어와도 OK,
        # 단순 디렉토리/파일 경로면 그것만으로 충분.
        t0 = time.monotonic()
        if os.path.exists(target):
            return True, (time.monotonic() - t0) * 1000
        return False, 0.0

    import urllib.request
    import urllib.error

    # ghost:// prefix 제거
    _target = target.replace("ghost://", "https://") if target.startswith("ghost://") else target
    if not _target.startswith(("http://", "https://")):
        _target = f"http://{_target}"

    t0 = time.monotonic()
    try:
        req = urllib.request.Request(_target, method="HEAD")
        urllib.request.urlopen(req, timeout=timeout)
        return True, (time.monotonic() - t0) * 1000
    except urllib.error.HTTPError:
        # HTTP 에러(4xx, 5xx)도 서버가 살아있다는 뜻
        return True, (time.monotonic() - t0) * 1000
    except Exception:
        # 404가 HEAD 안 받을 수 있음 → GET으로 재시도
        try:
            urllib.request.urlopen(_target, timeout=timeout)
            return True, (time.monotonic() - t0) * 1000
        except urllib.error.HTTPError:
            return True, (time.monotonic() - t0) * 1000
        except Exception:
            return False, 0.0


def _gemini_model_available(model: str, api_key: str, *, _opener=None) -> bool:
    """Cheap check that a Gemini model is actually callable with this key.

    Gemini's readiness used to be key-presence only, so a preview/unavailable
    model (e.g. gemini-3.1-pro-preview) showed Brain ✓ then 404'd every call →
    silent 0-finding scans. Fail-open: returns True when it can't tell (no
    key/model, transient network error); only a definitive 400/403/404 from the
    models endpoint returns False."""
    if not model or not api_key:
        return True
    import urllib.error

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}?key={api_key}"
    opener = _opener or urllib.request.urlopen
    try:
        req = urllib.request.Request(url, method="GET")
        with opener(req, timeout=3) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except urllib.error.HTTPError as exc:
        return exc.code not in (400, 403, 404)  # model missing/forbidden/bad request
    except Exception:
        return True  # transient/network — don't block a scan on the check itself


def check_brain(interactive: bool = False) -> tuple[str, bool]:
    """Brain 백엔드 상태 체크.

    Architecture:
        interactive=True   → InteractiveBrain (claude -p JSON bridge)
        interactive=False  → AgentBrain (LLM API only — no claude -p)

    For Claude Code as Brain, use either `vxis scan --interactive` or
    register the MCP server: `claude mcp add vxis python -m vxis.mcp_server`.
    """
    if interactive:
        if shutil.which("claude") is not None:
            return "claude-code", True
        return "claude-code (binary missing)", False

    # AgentBrain path — role-aware director backend required. Legacy
    # UPSTREAM_* still works, but if a frontier key is available the hybrid
    # resolver promotes it to director and keeps the local model as worker.
    from vxis.llm.hybrid_config import resolve_hybrid_model_config

    hybrid = resolve_hybrid_model_config(
        base_provider=os.environ.get("UPSTREAM_LLM_PROVIDER", ""),
        base_model=os.environ.get("UPSTREAM_LLM_MODEL", ""),
        env=os.environ,
    )
    provider = hybrid.director.provider
    model = hybrid.director.model
    if provider == "ollama":
        base_url = hybrid.director.base_url or os.environ.get("VXIS_OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        model = model or os.environ.get("VXIS_OLLAMA_UNCENSORED_MODEL", "qwen2.5-coder:14b")
        try:
            req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                if 200 <= getattr(resp, "status", 200) < 500:
                    return f"local:ollama/{model}", True
        except Exception:
            return f"local:ollama/{model} (unreachable)", False
    if provider == "llamacpp":
        base_url = hybrid.director.base_url or os.environ.get("VXIS_LLAMACPP_BASE_URL", "http://localhost:8080").rstrip("/")
        model = model or os.environ.get(
            "VXIS_LLAMACPP_MODEL",
            "huihui-qwen3.6-35b-a3b-claude-4.7-opus-abliterated-q4_k_m",
        )
        try:
            req = urllib.request.Request(f"{base_url}/v1/models", method="GET")
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                if 200 <= getattr(resp, "status", 200) < 500:
                    return f"local:llamacpp/{model}", True
        except Exception:
            return f"local:llamacpp/{model} (unreachable)", False

    api_key_envs = {
        "anthropic": "ANTHROPIC_API_KEY",
        "together":  "TOGETHER_API_KEY",
        "openai":    "OPENAI_API_KEY",
        "gemini":    "GOOGLE_API_KEY",
        "deepseek":   "DEEPSEEK_API_KEY",
    }
    key_env = api_key_envs.get(provider)
    has_key = bool(os.environ.get(key_env)) if key_env else False
    if provider == "openai" and os.environ.get("LLM_API_KEY"):
        has_key = True
    if provider == "gemini" and os.environ.get("GEMINI_API_KEY"):
        has_key = True

    if not has_key:
        return (
            "none (director LLM key missing — set VXIS_DIRECTOR_LLM plus provider key, "
            "or configure a reachable local legacy backend)",
            False,
        )

    # Verify the model is actually CALLABLE, not just that a key exists — a
    # wrong/unavailable model (e.g. a completions-only "gpt-5.3-codex", or a
    # preview Gemini) otherwise passes preflight then dies on every scan call.
    if provider == "gemini" and model:
        key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GEMINI_API_KEY", "")
        if not _gemini_model_available(model, key):
            return (
                f"api:gemini/{model} (model not callable with this key — pick a GA "
                f"model like gemini-2.5-pro)",
                False,
            )
    elif provider in ("openai", "together", "deepseek", "anthropic") and model:
        from vxis.llm.model_registry import get_model_info, list_models

        # Fast, no-network reject: an id we don't know about is almost always a
        # fat-fingered / stale value. Surface the valid options for a re-pick.
        if get_model_info(model) is None:
            valid = ", ".join(m.model_id for m in list_models(provider)) or "see model_registry"
            return (f"api:{provider}/{model} (unknown model — valid: {valid})", False)
        # Known model → confirm it actually answers with this key (auth/quota/endpoint).
        from vxis.agent.brain import AgentBrain

        ok, reason = AgentBrain().healthcheck()
        if not ok:
            return (f"api:{provider}/{model} (Brain call failed — {reason})", False)

    label = f"api:{provider}" + (f"/{model}" if model else "")
    return label, True


def _brain_unavailable_message(reason: str = "") -> str:
    """Compose the preflight 'no Brain' error. Surfaces check_brain's specific
    reason (e.g. 'model not callable — pick a GA model') instead of only the
    generic 'set a key' line, which infuriated users who HAD set a key but hit a
    non-callable (preview/unavailable) model or a bad key value."""
    base = (
        "No Brain backend available. Install 'claude' CLI, start Ollama/llama.cpp, or set "
        "ANTHROPIC_API_KEY / TOGETHER_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY"
    )
    detail = (reason or "").strip()
    # Suppress the no-key/no-backend labels ("none", "none (director LLM key
    # missing — set …)", "unknown") — base already says "set a key", so appending
    # them just duplicates the instruction. Keep specific reasons like
    # "api:gemini/… (model not callable …)" or "… (unreachable)".
    if detail and not detail.lower().startswith(("none", "unknown")):
        return f"{base}\n  → {detail}"
    return base


def check_docker() -> bool:
    """Docker daemon 접근 가능 여부."""
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=3,
        )
        return result.returncode == 0
    except Exception:
        return False


def check_github_token() -> bool:
    """GitHub API 토큰 설정 여부 (OSINT용)."""
    return bool(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))


def check_proxy_pool() -> int:
    """Ghost 모드용 프록시 풀 크기."""
    pool = os.environ.get("VXIS_PROXY_POOL", "")
    if not pool:
        return 0
    return len([p for p in pool.split(",") if p.strip()])


def run_preflight(
    target: str,
    ghost: bool = False,
    interactive: bool = False,
    kind: str = "web",
) -> PreflightResult:
    """전체 pre-flight 체크 실행.

    `kind` 는 target 의 surface 타입 — desktop 이면 파일 경로 존재 여부로
    reachability 를 판정한다 (HTTP probe 스킵).
    """
    result = PreflightResult()

    # 1. Target 도달
    result.target_reachable, result.target_latency_ms = check_target_reachable(target, kind=kind)
    if not result.target_reachable:
        if kind == "desktop":
            result.errors.append(f"Desktop target not found on disk: {target}")
        else:
            result.errors.append(f"Target unreachable: {target}")

    # 2. Brain 백엔드
    result.brain_backend, result.brain_ready = check_brain(interactive=interactive)
    if not result.brain_ready:
        result.errors.append(_brain_unavailable_message(result.brain_backend))

    # 3. Docker (sandbox/browser/tooling availability)
    result.docker_available = check_docker()
    if not result.docker_available:
        result.warnings.append("Docker not available — sandboxed scanners may be limited")

    # 4. GitHub token (optional upstream/news integrations)
    result.github_token = check_github_token()
    if not result.github_token:
        result.warnings.append("GITHUB_TOKEN not set — upstream/news integrations may be limited")

    # 5. Proxy pool (Ghost 모드)
    result.proxy_pool_size = check_proxy_pool()
    if ghost and result.proxy_pool_size == 0:
        result.warnings.append(
            "Ghost mode enabled but VXIS_PROXY_POOL is empty — "
            "only UA/timing evasion will be applied (no IP rotation)"
        )

    return result
