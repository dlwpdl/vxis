import asyncio
import json
import os
import sys
import urllib.request
from typing import Any

from vxis.agent.brain import AgentBrain, get_brain_decision_count, get_llm_call_count
from vxis.growth.strix_comparison import build_strix_comparison_scorecard
from vxis.pipeline.scan_pipeline_v2 import ScanPipeline

TARGET = os.environ.get("VXIS_BENCH_TARGET", "http://127.0.0.1:3000").strip()
REPORT_PATH = os.environ.get("VXIS_BENCH_REPORT", "reports/juiceshop_richer_smoke.html").strip()
SNAPSHOT_PATH = os.environ.get("VXIS_BENCH_SNAPSHOT_PATH", "/tmp/vxis-bench-control-plane.json").strip()
LOCAL_PROVIDERS = {"ollama", "llamacpp"}
REMOTE_PROVIDER_ENV_KEYS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "google": "GEMINI_API_KEY",
    "together": "TOGETHER_API_KEY",
}


def _provider_base_url(provider: str) -> str:
    if provider == "ollama":
        return os.environ.get("VXIS_OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    if provider == "llamacpp":
        return os.environ.get("VXIS_LLAMACPP_BASE_URL", "http://127.0.0.1:8090").rstrip("/")
    return ""


def _provider_healthcheck(provider: str, base_url: str) -> tuple[bool, str]:
    if provider == "ollama":
        url = f"{base_url}/api/tags"
    elif provider == "llamacpp":
        url = f"{base_url}/v1/models"
    else:
        return False, f"unsupported local provider: {provider}"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            status = getattr(resp, "status", 200)
            if 200 <= status < 500:
                return True, f"{provider} reachable at {base_url}"
            return False, f"{provider} returned HTTP {status}"
    except Exception as exc:
        return False, f"{provider} unreachable at {base_url}: {exc}"


def _require_llm_runtime() -> tuple[str, str, str]:
    provider = os.environ.get("UPSTREAM_LLM_PROVIDER", "").strip().lower()
    if provider == "google":
        provider = "gemini"
    model = os.environ.get("UPSTREAM_LLM_MODEL", "").strip()
    if not model:
        raise SystemExit(
            "benchmark harness requires UPSTREAM_LLM_MODEL to be set for the selected runtime."
        )
    if provider in LOCAL_PROVIDERS:
        base_url = _provider_base_url(provider)
        ok, message = _provider_healthcheck(provider, base_url)
        if not ok:
            raise SystemExit(f"local LLM runtime not ready: {message}")
        return provider, model, base_url
    env_key = REMOTE_PROVIDER_ENV_KEYS.get(provider)
    if not provider or not env_key:
        raise SystemExit(
            "benchmark harness requires a supported provider. "
            "Use ollama, llamacpp, openai, anthropic, gemini, or together."
        )
    if not os.environ.get(env_key, "").strip():
        raise SystemExit(
            f"benchmark harness requires {env_key} for provider '{provider}'."
        )
    return provider, model, ""


async def main() -> None:
    provider, model, base_url = _require_llm_runtime()
    latest_control_plane: dict[str, Any] = {}

    def _capture_event(event_type: str, data: dict[str, Any]) -> None:
        nonlocal latest_control_plane
        if event_type == "control_plane":
            latest_control_plane = dict(data or {})
            try:
                with open(SNAPSHOT_PATH, "w", encoding="utf-8") as fp:
                    json.dump(latest_control_plane, fp, ensure_ascii=False, indent=2)
            except Exception:
                pass

    brain = AgentBrain(
        provider=provider,
        model=model,
        max_steps=int(os.environ.get("VXIS_BENCH_MAX_STEPS", "120")),
        brain_mode=os.environ.get("VXIS_BENCH_BRAIN_MODE", "standard"),
    )
    pipe = ScanPipeline(
        brain=brain,
        auto_approve_injection=True,
        generate_report=True,
        report_output_path=REPORT_PATH,
        event_callback=_capture_event,
    )
    ctx = await pipe.run(target=TARGET)

    candidate_statuses = {
        item.get("id", ""): item.get("status", "")
        for item in (getattr(ctx, "vector_candidates", []) or [])
    }
    branch_statuses = {
        item.get("id", ""): item.get("status", "")
        for item in (getattr(ctx, "branches", []) or [])
    }

    out = {
        "target": TARGET,
        "provider": provider,
        "model": model,
        "base_url": base_url,
        "scan_id": ctx.scan_id,
        "completed": getattr(ctx, "scan_loop_completed", False),
        "findings_count": len(ctx.findings),
        "finding_types": [getattr(f, "finding_type", "") for f in ctx.findings],
        "attack_chains_count": len(getattr(ctx, "attack_chains", []) or []),
        "review_queue_count": len(getattr(ctx, "review_queue", []) or []),
        "review_history_count": len(getattr(ctx, "review_history", []) or []),
        "brain_decision_count": get_brain_decision_count(),
        "llm_call_count": get_llm_call_count(),
        "llm_usage": getattr(ctx, "llm_usage", {}) or {},
        "discipline_profile": str((latest_control_plane.get("telemetry") or {}).get("discipline_profile") or ""),
        "memory_compression": dict((latest_control_plane.get("telemetry") or {}).get("memory_compression") or {}),
        "candidate_statuses": candidate_statuses,
        "branch_statuses": branch_statuses,
        "focus_branch": latest_control_plane.get("focus_branch") or {},
        "blocking_branches": latest_control_plane.get("blocking_branches") or [],
        "memory_directives": latest_control_plane.get("memory_directives") or [],
        "chain_candidates": latest_control_plane.get("chain_candidates") or [],
        "strix_comparison": build_strix_comparison_scorecard(
            findings=[
                {
                    "finding_type": getattr(f, "finding_type", ""),
                    "severity": getattr(f, "severity", ""),
                    "title": getattr(f, "title", ""),
                    "affected_component": getattr(f, "affected_component", ""),
                    "description": getattr(f, "description", ""),
                    "impact": getattr(f, "impact", ""),
                    "technical_analysis": getattr(f, "technical_analysis", ""),
                    "poc_description": getattr(f, "poc_description", ""),
                    "poc_script_code": getattr(f, "poc_script_code", ""),
                    "evidence": "\n".join(str(x) for x in (getattr(f, "evidence", []) or [])[:2]),
                }
                for f in ctx.findings
            ],
            loop_result={
                "completed": getattr(ctx, "scan_loop_completed", False),
                "verdict_counts": getattr(ctx, "verdict_counts", {}) or {},
                "review_queue": getattr(ctx, "review_queue", []) or [],
                "review_history": getattr(ctx, "review_history", []) or [],
                "branches": getattr(ctx, "branches", []) or [],
            },
            attack_chains=list(getattr(ctx, "attack_chains", []) or []),
            llm_usage={
                **(getattr(ctx, "llm_usage", {}) or {}),
                "llm_calls": get_llm_call_count(),
                "brain_decisions": get_brain_decision_count(),
            },
            control_plane=latest_control_plane,
        ),
        "report_path": REPORT_PATH,
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except SystemExit as exc:
        print(str(exc), file=sys.stderr)
        raise
