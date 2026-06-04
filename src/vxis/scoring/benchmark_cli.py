"""Command-line entrypoint for executable Benchmark League manifests."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from vxis.scoring.benchmark import BenchmarkRunner
from vxis.scoring.benchmark_manifest import (
    BenchmarkManifestTarget,
    load_benchmark_manifest,
)


LLM_API_KEY_NAMES = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "TOGETHER_API_KEY",
    "DEEPSEEK_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
)


def has_llm_api_key(environ: dict[str, str] | None = None) -> bool:
    env = environ if environ is not None else os.environ
    return any(env.get(name) for name in LLM_API_KEY_NAMES)


def _write_result(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _skipped_payload(
    *,
    league_id: str,
    profile: str,
    reason: str,
    targets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "skipped": True,
        "reason": reason,
        "league_id": league_id,
        "profile": profile,
        "results": targets or [],
        "regression": False,
    }


async def run_benchmark_manifest(
    *,
    manifest_path: Path,
    baseline_path: Path,
    output_path: Path,
    target_type: str | None = None,
    target_id: str | None = None,
    profile: str | None = None,
) -> int:
    manifest = load_benchmark_manifest(manifest_path)
    run_profile = profile or manifest.profile

    selected = list(manifest.select(target_type=target_type, target_id=target_id))
    if not selected:
        _write_result(
            output_path,
            _skipped_payload(
                league_id=manifest.league_id,
                profile=run_profile,
                reason="no_matching_targets",
            ),
        )
        return 0

    if not has_llm_api_key():
        _write_result(
            output_path,
            _skipped_payload(
                league_id=manifest.league_id,
                profile=run_profile,
                reason="no_llm_api_key",
                targets=[target.to_dict() for target in selected],
            ),
        )
        return 0

    runner = BenchmarkRunner(str(baseline_path))
    results: list[dict[str, Any]] = []

    for target in selected:
        result = await _run_one_target(runner, target, run_profile)
        results.append(result)

    executed = [item for item in results if not item.get("skipped")]
    payload = {
        "skipped": not executed,
        "reason": "no_configured_targets" if not executed else "",
        "league_id": manifest.league_id,
        "profile": run_profile,
        "results": results,
        "regression": any(item.get("regression") for item in executed),
    }

    if len(executed) == 1:
        # Backward-compatible shape for the existing GitHub comment code.
        only = executed[0]
        payload["target_type"] = only["target_type"]
        payload["target_id"] = only["target_id"]
        payload["score"] = only["score"]
        payload["comparison"] = only["comparison"]
        payload["github_comment"] = only["github_comment"]

    _write_result(output_path, payload)
    return 1 if payload["regression"] else 0


async def _run_one_target(
    runner: BenchmarkRunner,
    target: BenchmarkManifestTarget,
    profile: str,
) -> dict[str, Any]:
    target_url = target.resolve_url()
    if not target_url:
        return {
            "skipped": True,
            "reason": "no_target_url",
            "target_id": target.target_id,
            "target_type": target.target_type,
            "required": target.required,
        }

    score = await runner.run_benchmark(
        target_type=target.target_type,
        target_url=target_url,
        profile=profile,
    )
    comparison = runner.compare_with_baseline(score)

    print(f"\n[{target.target_id}] {score.summary_text()}")

    return {
        "skipped": False,
        "target_id": target.target_id,
        "target_type": target.target_type,
        "target_url": target_url,
        "score": score.to_dict(),
        "comparison": comparison.to_dict(),
        "github_comment": runner.generate_report(comparison, format="github"),
        "regression": comparison.regression,
    }


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a VXIS benchmark manifest")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--baseline", default=Path("tools/benchmark/baseline.json"), type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--target-type", default=None)
    parser.add_argument("--target-id", default=None)
    parser.add_argument("--profile", default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv or sys.argv[1:])
    return asyncio.run(
        run_benchmark_manifest(
            manifest_path=args.manifest,
            baseline_path=args.baseline,
            output_path=args.output,
            target_type=args.target_type,
            target_id=args.target_id,
            profile=args.profile,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
