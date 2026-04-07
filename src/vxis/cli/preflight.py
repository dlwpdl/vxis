"""Pre-flight checks for VXIS scan — validate environment before pipeline starts."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urlparse


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


def check_target_reachable(target: str, timeout: float = 5.0) -> tuple[bool, float]:
    """타겟 URL/도메인 도달 가능 여부 체크 — HTTP HEAD 시도."""
    import time
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


def check_brain(interactive: bool = False) -> tuple[str, bool]:
    """Brain 백엔드 상태 체크.

    interactive=True (vxis scan --interactive): InteractiveBrain → claude -p
    interactive=False (기본): AgentBrain → UPSTREAM_LLM_PROVIDER/MODEL (env-driven)
    """
    if interactive:
        if shutil.which("claude") is not None:
            return "claude-code", True
        return "claude-code (binary missing)", False

    # AgentBrain path — show the actual provider/model that will run
    provider = os.environ.get("UPSTREAM_LLM_PROVIDER", "together")
    model = os.environ.get("UPSTREAM_LLM_MODEL", "")

    api_key_envs = {
        "anthropic": "ANTHROPIC_API_KEY",
        "together":  "TOGETHER_API_KEY",
        "openai":    "OPENAI_API_KEY",
        "gemini":    "GOOGLE_API_KEY",
    }
    key_env = api_key_envs.get(provider)
    has_key = bool(os.environ.get(key_env)) if key_env else False

    # Fallback: any provider that has a key
    if not has_key:
        for prov, env in api_key_envs.items():
            if os.environ.get(env):
                provider = prov
                has_key = True
                break

    if not has_key:
        return "none", False

    label = f"{provider}" + (f"/{model}" if model else "")
    return label, True


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


def run_preflight(target: str, ghost: bool = False, interactive: bool = False) -> PreflightResult:
    """전체 pre-flight 체크 실행."""
    result = PreflightResult()

    # 1. Target 도달
    result.target_reachable, result.target_latency_ms = check_target_reachable(target)
    if not result.target_reachable:
        result.errors.append(f"Target unreachable: {target}")

    # 2. Brain 백엔드
    result.brain_backend, result.brain_ready = check_brain(interactive=interactive)
    if not result.brain_ready:
        result.errors.append(
            "No Brain backend available. Install 'claude' CLI or set "
            "ANTHROPIC_API_KEY / TOGETHER_API_KEY / OPENAI_API_KEY / GOOGLE_API_KEY"
        )

    # 3. Docker (Phase 15 Digital Twin용)
    result.docker_available = check_docker()
    if not result.docker_available:
        result.warnings.append("Docker not available — Phase 15 Digital Twin will skip")

    # 4. GitHub 토큰 (Phase 13 OSINT용)
    result.github_token = check_github_token()
    if not result.github_token:
        result.warnings.append("GITHUB_TOKEN not set — Phase 13 OSINT will be limited")

    # 5. Proxy pool (Ghost 모드)
    result.proxy_pool_size = check_proxy_pool()
    if ghost and result.proxy_pool_size == 0:
        result.warnings.append(
            "Ghost mode enabled but VXIS_PROXY_POOL is empty — "
            "only UA/timing evasion will be applied (no IP rotation)"
        )

    return result
