"""VXIS LLM Client — CLI 구독 우선, API fallback.

호출 우선순위:
    1. claude CLI  (Claude Code/Max 구독 토큰, $0)
    2. gemini CLI  (Gemini 구독 토큰, $0)
    3. codex CLI   (OpenAI Codex 구독 토큰, $0)
    4. Together.ai API  (유료, 저렴)
    5. Direct API  (Anthropic/Google/OpenAI, 유료)

CLI 호출 = subprocess로 프롬프트를 파이프
API 호출 = urllib로 HTTP 요청
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import urllib.request
import urllib.error
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """통합 LLM 응답."""
    text: str
    provider: str  # "claude-cli", "gemini-cli", "codex-cli", "together-api", etc.
    model: str
    tokens_used: int = 0
    cost: float = 0.0  # $0 for CLI, estimated for API


# ── CLI Providers (구독 기반, $0) ────────────────────────────────

def _call_claude_cli(system: str, user: str, max_tokens: int = 4096) -> LLMResponse | None:
    """Claude Code CLI를 통해 구독 토큰 사용."""
    claude_bin = shutil.which("claude")
    if claude_bin is None:
        return None

    # claude CLI: pipe prompt via --print flag for non-interactive output
    prompt = f"{system}\n\n---\n\n{user}"

    try:
        result = subprocess.run(
            [claude_bin, "--print", "-p", prompt],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            return LLMResponse(
                text=result.stdout.strip(),
                provider="claude-cli",
                model="claude-subscription",
                cost=0.0,
            )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("claude CLI failed: %s", exc)

    return None


def _call_gemini_cli(system: str, user: str, max_tokens: int = 4096) -> LLMResponse | None:
    """Gemini CLI를 통해 구독 토큰 사용."""
    gemini_bin = shutil.which("gemini")
    if gemini_bin is None:
        return None

    prompt = f"{system}\n\n---\n\n{user}"

    try:
        result = subprocess.run(
            [gemini_bin, "-p", prompt],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            return LLMResponse(
                text=result.stdout.strip(),
                provider="gemini-cli",
                model="gemini-subscription",
                cost=0.0,
            )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("gemini CLI failed: %s", exc)

    return None


def _call_codex_cli(system: str, user: str, max_tokens: int = 4096) -> LLMResponse | None:
    """OpenAI Codex CLI를 통해 구독 토큰 사용."""
    codex_bin = shutil.which("codex")
    if codex_bin is None:
        return None

    prompt = f"{system}\n\n---\n\n{user}"

    try:
        result = subprocess.run(
            [codex_bin, "-p", prompt],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0 and result.stdout.strip():
            return LLMResponse(
                text=result.stdout.strip(),
                provider="codex-cli",
                model="codex-subscription",
                cost=0.0,
            )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.debug("codex CLI failed: %s", exc)

    return None


# ── API Providers (유료) ────────────────────────────────────────

def _call_api(system: str, user: str, max_tokens: int = 4096) -> LLMResponse | None:
    """upstream_watch의 LLM 모듈을 재활용 (Together.ai + fallback chain)."""
    try:
        from tools.upstream_watch.llm import chat
        response = chat(system_prompt=system, user_prompt=user, max_tokens=max_tokens)
        if response:
            return LLMResponse(
                text=response.text,
                provider=f"{response.provider}-api",
                model=response.model,
                cost=0.001,  # estimated
            )
    except ImportError:
        pass

    return None


# ── Unified Client ──────────────────────────────────────────────

# Provider preference order
_CLI_PROVIDERS = [
    ("claude-cli", _call_claude_cli),
    ("gemini-cli", _call_gemini_cli),
    ("codex-cli", _call_codex_cli),
]

_API_PROVIDERS = [
    ("api", _call_api),
]

# User can override with env var: VXIS_LLM_PROVIDER=claude-cli,gemini-cli,api
def _get_provider_order() -> list[tuple[str, callable]]:
    """환경변수로 우선순위 커스터마이징 가능."""
    override = os.environ.get("VXIS_LLM_PROVIDER", "")
    if override:
        name_to_fn = {name: fn for name, fn in _CLI_PROVIDERS + _API_PROVIDERS}
        order = []
        for name in override.split(","):
            name = name.strip()
            if name in name_to_fn:
                order.append((name, name_to_fn[name]))
        if order:
            return order

    return _CLI_PROVIDERS + _API_PROVIDERS


class LLMClient:
    """통합 LLM 클라이언트 — CLI 구독 우선, API fallback.

    Usage:
        client = LLMClient()
        response = await client.think(system="...", user="...")
        print(response.text, response.provider, response.cost)
    """

    def __init__(self) -> None:
        self._providers = _get_provider_order()
        self._usage_log: list[dict] = []

    async def think(
        self,
        system: str,
        user: str,
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """LLM 호출 — CLI 우선, API fallback."""
        for name, call_fn in self._providers:
            try:
                response = call_fn(system, user, max_tokens)
                if response is not None:
                    self._usage_log.append({
                        "provider": response.provider,
                        "model": response.model,
                        "cost": response.cost,
                    })
                    logger.info("LLM 응답: %s (%s, $%.4f)", name, response.model, response.cost)
                    return response
            except Exception as exc:
                logger.debug("LLM provider %s failed: %s", name, exc)
                continue

        # All failed
        return LLMResponse(
            text="[LLM 호출 실패 — 모든 provider 사용 불가]",
            provider="none",
            model="none",
        )

    async def think_with_tools(
        self,
        system: str,
        user: str,
        tools: list[dict],
        max_tokens: int = 8192,
    ):
        """Tool use는 API만 지원 (CLI는 tool calling 불가)."""
        # Anthropic API 직접 호출 (tool use 지원)
        try:
            import anthropic
            api_key = os.environ.get("ANTHROPIC_API_KEY", "")
            if api_key:
                client = anthropic.Anthropic(api_key=api_key)
                return client.messages.create(
                    model=os.environ.get("VXIS_LLM_MODEL", "claude-sonnet-4-20250514"),
                    max_tokens=max_tokens,
                    system=system,
                    tools=tools,
                    messages=[{"role": "user", "content": user}],
                )
        except ImportError:
            pass

        # Fallback: think without tools
        response = await self.think(system, user + "\n\nAvailable tools: " + json.dumps(tools), max_tokens)
        return response

    def get_usage_summary(self) -> str:
        """사용량 요약."""
        if not self._usage_log:
            return "LLM 사용 없음"

        total_cost = sum(u["cost"] for u in self._usage_log)
        by_provider: dict[str, int] = {}
        for u in self._usage_log:
            by_provider[u["provider"]] = by_provider.get(u["provider"], 0) + 1

        parts = [f"{name}: {count}회" for name, count in by_provider.items()]
        return f"총 {len(self._usage_log)}회 호출 ({', '.join(parts)}) — ${total_cost:.4f}"

    @staticmethod
    def check_available_providers() -> list[dict[str, str]]:
        """사용 가능한 provider 목록 반환."""
        available = []

        if shutil.which("claude"):
            available.append({"name": "claude-cli", "type": "subscription", "cost": "$0"})
        if shutil.which("gemini"):
            available.append({"name": "gemini-cli", "type": "subscription", "cost": "$0"})
        if shutil.which("codex"):
            available.append({"name": "codex-cli", "type": "subscription", "cost": "$0"})

        # Check API keys
        if os.environ.get("TOGETHER_API_KEY"):
            available.append({"name": "together-api", "type": "api", "cost": "$0.50/M"})
        if os.environ.get("ANTHROPIC_API_KEY"):
            available.append({"name": "anthropic-api", "type": "api", "cost": "$3/M"})
        if os.environ.get("GOOGLE_API_KEY"):
            available.append({"name": "google-api", "type": "api", "cost": "free tier"})
        if os.environ.get("OPENAI_API_KEY"):
            available.append({"name": "openai-api", "type": "api", "cost": "$0.15/M"})

        return available
