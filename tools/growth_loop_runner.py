#!/usr/bin/env python3
"""VXIS Growth Loop Runner — 독립 CLI 벤치마크 측정 도구.

GHA(평일)와 Claude Code(주말) 모두에서 사용하는 공통 측정 엔진.

Usage:
    # 자동 감지 (claude CLI 있으면 구독, 없으면 Together AI)
    python tools/growth_loop_runner.py

    # Together AI 강제 (GHA 평일용)
    python tools/growth_loop_runner.py --provider together

    # Claude CLI 강제 (주말 Claude Code용)
    python tools/growth_loop_runner.py --provider claude-cli

    # 반복 횟수 지정
    python tools/growth_loop_runner.py --iterations 3

    # 시간 제한 (KST 06:00까지)
    python tools/growth_loop_runner.py --until 06:00

    # 특정 타겟만
    python tools/growth_loop_runner.py --targets dvwa
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

# VXIS 소스 경로 추가
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# ── 상수 ──────────────────────────────────────────────────────────

HISTORY_FILE = Path("tools/benchmark/score_history.json")
BASELINE_FILE = Path("tools/benchmark/baseline.json")
ITERATION_LOG = Path("tools/benchmark/iteration_log.json")
RESULTS_FILE = Path("tools/benchmark/latest_results.json")
REPORT_FILE = Path("tools/benchmark/growth_report.md")

KST = timezone(timedelta(hours=9))

TARGETS: dict[str, dict[str, str]] = {
    "dvwa":       {"url": "http://localhost:8081", "image": "vulnerables/web-dvwa",         "port": "8081:80"},
    "juice-shop": {"url": "http://localhost:3000", "image": "bkimminich/juice-shop",        "port": "3000:3000"},
    "webgoat":    {"url": "http://localhost:8888/WebGoat", "image": "webgoat/webgoat",        "port": "8888:8080"},
    "nodegoat":   {"url": "http://localhost:4000", "image": "1njected/nodegoat",            "port": "4000:4000"},
}

DIM_NAMES_KO: dict[str, str] = {
    "vector_coverage": "벡터 커버리지",
    "exploitation_reach": "공격 깊이",
    "chain_intelligence": "체인 지능",
    "finding_precision": "발견 정확도",
    "completeness": "완전성",
}

DIM_MAX: dict[str, int] = {
    "vector_coverage": 250,
    "exploitation_reach": 300,
    "chain_intelligence": 150,
    "finding_precision": 200,
    "completeness": 100,
}

# 판정 임계값
IMPROVED_THRESHOLD = 5.0   # +5점 이상 → 자동 반영
REGRESSED_THRESHOLD = -5.0  # -5점 이상 → 롤백 + 경고


# ── Docker 관리 ───────────────────────────────────────────────────

def ensure_docker_targets(target_names: list[str]) -> list[tuple[str, str]]:
    """Docker 컨테이너를 기동하고 준비될 때까지 대기."""
    active: list[tuple[str, str]] = []

    for name in target_names:
        if name not in TARGETS:
            print(f"  [SKIP] Unknown target: {name}")
            continue

        cfg = TARGETS[name]
        url = cfg["url"]

        # 이미 접속 가능한지 확인
        if _check_health(url):
            print(f"  [READY] {name} — already running at {url}")
            active.append((name, url))
            continue

        # Docker 기동 시도
        print(f"  [START] {name} — docker run {cfg['image']}...")
        try:
            subprocess.run(
                ["docker", "run", "-d", "--name", f"vxis-{name}",
                 "-p", cfg["port"], cfg["image"]],
                capture_output=True, text=True, timeout=60,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            print(f"  [WARN] Docker start failed for {name}: {exc}")

        # 준비 대기 (최대 30초)
        if _wait_for_health(name, url, timeout=30):
            active.append((name, url))
        else:
            print(f"  [SKIP] {name} not ready after 30s")

    return active


def _check_health(url: str, timeout: int = 3) -> bool:
    """URL 접속 가능 여부."""
    try:
        urllib.request.urlopen(url, timeout=timeout)
        return True
    except Exception:
        return False


def _wait_for_health(name: str, url: str, timeout: int = 30) -> bool:
    """서비스가 준비될 때까지 대기."""
    for i in range(timeout // 2):
        if _check_health(url):
            print(f"  [READY] {name} — up after {(i + 1) * 2}s")
            return True
        time.sleep(2)
    return False


# ── 벤치마크 실행 ─────────────────────────────────────────────────

def run_single_benchmark(
    target_name: str,
    target_url: str,
    target_type: str = "web",
) -> dict:
    """단일 타겟 벤치마크 실행. LLM Brain이 스캔을 수행한다."""
    try:
        from vxis.scoring.benchmark import BenchmarkRunner

        runner = BenchmarkRunner(baseline_path=str(BASELINE_FILE))

        async def _run():
            score = await runner.run_benchmark(target_type, target_url)
            comparison = runner.compare_with_baseline(score)
            return score, comparison

        score, comparison = asyncio.run(_run())

        return {
            "target": target_name,
            "url": target_url,
            "total": score.total,
            "grade": score.grade,
            "dimensions": {
                "vector_coverage": score.vector_coverage.score,
                "exploitation_reach": score.exploitation_reach.score,
                "chain_intelligence": score.chain_intelligence.score,
                "finding_precision": score.finding_precision.score,
                "completeness": score.completeness.score,
            },
            "delta": comparison.total_delta if comparison else 0,
            "score_obj": score,
            "comparison": comparison,
            "runner": runner,
            "error": None,
        }
    except Exception as exc:
        return {
            "target": target_name,
            "url": target_url,
            "total": 0,
            "grade": "D",
            "error": str(exc)[:300],
        }


# ── 약점 분석 ─────────────────────────────────────────────────────

def find_weakest_dimension(result: dict) -> tuple[str | None, float]:
    """가장 약한 차원 찾기."""
    dims = result.get("dimensions")
    if not dims:
        return None, 0.0

    weakest: str | None = None
    weakest_pct = 1.0
    for dim, score in dims.items():
        pct = score / DIM_MAX[dim]
        if pct < weakest_pct:
            weakest_pct = pct
            weakest = dim
    return weakest, weakest_pct


def make_verdict(delta: float) -> str:
    """점수 변화에 대한 판정."""
    if delta >= IMPROVED_THRESHOLD:
        return "improved"
    elif delta <= REGRESSED_THRESHOLD:
        return "regressed"
    return "stable"


# ── 전략 조정 ─────────────────────────────────────────────────────

STRATEGIES: dict[str, dict[str, str]] = {
    "vector_coverage": {
        "action": "더 많은 벡터를 시도하도록 Brain 전략 조정|||Adjust Brain strategy for more vector coverage",
        "env_hint": "VXIS_STRATEGY=aggressive_coverage",
    },
    "exploitation_reach": {
        "action": "L2+ 도달을 위해 익스플로잇 체인 강화|||Strengthen exploit chains for L2+ reach",
        "env_hint": "VXIS_STRATEGY=deep_exploit",
    },
    "chain_intelligence": {
        "action": "발견 간 연결점 탐색 강화, 피벗 로직 활성화|||Enhance chain discovery and pivot logic",
        "env_hint": "VXIS_STRATEGY=chain_focus",
    },
    "finding_precision": {
        "action": "FP 필터 강화, 증거 수집 로직 활성화|||Strengthen FP filter and evidence collection",
        "env_hint": "VXIS_STRATEGY=precision_mode",
    },
    "completeness": {
        "action": "스킵된 Phase 재시도, 타임아웃 증가|||Retry skipped phases with increased timeout",
        "env_hint": "VXIS_STRATEGY=full_coverage",
    },
}


def apply_strategy(weakest_dim: str | None, iteration: int) -> str:
    """약점 차원에 맞는 전략 조정."""
    if weakest_dim and weakest_dim in STRATEGIES:
        strategy = STRATEGIES[weakest_dim]
        os.environ["VXIS_GROWTH_STRATEGY"] = strategy["env_hint"]
        action = strategy["action"].split("|||")[0]
        print(f"  [STRATEGY] {action}")
        return action
    return "no_strategy"


# ── 히스토리 & 리포트 ─────────────────────────────────────────────

def load_history() -> list[dict]:
    """점수 히스토리 로드."""
    if HISTORY_FILE.exists():
        try:
            return json.loads(HISTORY_FILE.read_text())
        except json.JSONDecodeError:
            pass
    return []


def save_history(history: list[dict]) -> None:
    """점수 히스토리 저장 (최대 365일)."""
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    if len(history) > 365:
        history[:] = history[-365:]
    HISTORY_FILE.write_text(json.dumps(history, indent=2, ensure_ascii=False))


def save_iteration_log(iterations: list[dict]) -> None:
    """반복 로그 저장."""
    now = datetime.now(timezone.utc)
    data = {
        "date": now.strftime("%Y-%m-%d"),
        "total_iterations": len(iterations),
        "start_score": iterations[0]["best_score"] if iterations else 0,
        "final_score": iterations[-1]["best_score"] if iterations else 0,
        "total_growth": round(
            (iterations[-1]["best_score"] - iterations[0]["best_score"])
            if len(iterations) >= 2 else 0,
            1,
        ),
        "iterations": iterations,
    }
    ITERATION_LOG.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def save_latest_results(iterations: list[dict], verdicts: list[dict]) -> None:
    """최신 결과 JSON — Claude Code가 읽을 수 있도록."""
    now = datetime.now(timezone.utc)
    data = {
        "date": now.isoformat(),
        "total_iterations": len(iterations),
        "start_score": iterations[0]["best_score"] if iterations else 0,
        "final_score": iterations[-1]["best_score"] if iterations else 0,
        "total_growth": round(
            (iterations[-1]["best_score"] - iterations[0]["best_score"])
            if len(iterations) >= 2 else 0,
            1,
        ),
        "verdicts": verdicts,
        "iterations": iterations,
    }
    RESULTS_FILE.write_text(json.dumps(data, indent=2, ensure_ascii=False))


def generate_report(iterations: list[dict], verdicts: list[dict]) -> str:
    """마크다운 풀 리포트 생성 — 판정 + 선택지 포함."""
    now = datetime.now(KST)
    lines: list[str] = []

    # 헤더
    lines.append(f"# VXIS Growth Loop Report — {now.strftime('%Y-%m-%d %H:%M')} KST")
    lines.append("")

    if not iterations:
        lines.append("**결과 없음** — 모든 타겟 실패")
        return "\n".join(lines)

    start_s = iterations[0]["best_score"]
    final_s = iterations[-1]["best_score"]
    growth = final_s - start_s

    # 요약
    lines.append("## 요약")
    lines.append(f"- **반복 횟수:** {len(iterations)}")
    lines.append(f"- **시작 점수:** {start_s:.1f}")
    lines.append(f"- **최종 점수:** {final_s:.1f}")
    lines.append(f"- **총 성장:** {growth:+.1f}점")
    lines.append("")

    # 판정
    lines.append("## 판정")
    lines.append("")
    for v in verdicts:
        icon = {"improved": "✅", "regressed": "❌", "stable": "➡️", "first_run": "🆕"}
        verdict_icon = icon.get(v["verdict"], "❓")
        lines.append(
            f"- {verdict_icon} **{v['target']}**: {v['today']:.1f}점 "
            f"(이전: {v['previous']:.1f}, 변화: {v['delta']:+.1f}) → **{v['verdict'].upper()}**"
        )
    lines.append("")

    # 선택지 (애매한 경우)
    stable_verdicts = [v for v in verdicts if v["verdict"] == "stable"]
    if stable_verdicts:
        lines.append("## 🤔 결정 필요 (Stable 판정)")
        lines.append("")
        lines.append("점수 변화가 ±5점 이내입니다. 선택해주세요:")
        lines.append("")
        lines.append("| 선택 | 설명 | 장점 | 단점 |")
        lines.append("|------|------|------|------|")
        lines.append("| **반영** | 코드 변경을 유지 | 미세한 개선도 축적됨 | 노이즈 커밋 가능 |")
        lines.append("| **보류** | 변경을 unstage | 깨끗한 히스토리 | 개선분 손실 |")
        lines.append("| **롤백** | 이전 상태로 복원 | 안전 | 작업 시간 손실 |")
        lines.append("")

    # 반복별 상세
    lines.append("## Step-by-Step")
    lines.append("")
    lines.append("| # | 점수 | 변화 | 약점 | 약점% | 전략 |")
    lines.append("|---|------|------|------|-------|------|")

    for it in iterations:
        weak_ko = DIM_NAMES_KO.get(it.get("weakest_dimension", ""), "?")
        wpct = it.get("weakest_pct", 0)
        imp = it.get("improvement", 0)
        imp_icon = "📈" if imp > 0 else ("📉" if imp < 0 else "➡️")
        action = it.get("action", "")[:40]
        lines.append(
            f"| {it['iteration']} | {it['best_score']:.1f} "
            f"| {imp_icon} {imp:+.1f} | {weak_ko} | {wpct:.0%} | {action} |"
        )
    lines.append("")

    # 차원별 상세 (마지막 반복)
    last = iterations[-1]
    dims = last.get("all_dimensions", {})
    if dims:
        lines.append("## 최종 차원별 점수")
        lines.append("")
        lines.append("| 차원 | 점수 | 최대 | % | 상태 |")
        lines.append("|------|------|------|---|------|")
        for dk, dv in dims.items():
            dmax = DIM_MAX.get(dk, 100)
            pct = dv / dmax if dmax else 0
            bar = "🟢" if pct >= 0.7 else ("🟡" if pct >= 0.4 else "🔴")
            lines.append(f"| {DIM_NAMES_KO.get(dk, dk)} | {dv:.1f} | {dmax} | {pct:.0%} | {bar} |")
        lines.append("")

    return "\n".join(lines)


def send_telegram_report(report_text: str, verdicts: list[dict]) -> None:
    """텔레그램으로 요약 리포트 전송."""
    token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        return

    # 텔레그램용 요약 (마크다운 전체를 보내면 너무 김)
    improved = [v for v in verdicts if v["verdict"] == "improved"]
    regressed = [v for v in verdicts if v["verdict"] == "regressed"]
    stable = [v for v in verdicts if v["verdict"] == "stable"]

    if regressed:
        icon = "🚨"
        status = "REGRESSION 감지"
    elif improved:
        icon = "📈"
        status = "성장"
    else:
        icon = "➡️"
        status = "변화없음"

    details = "\n".join(
        f"  {'✅' if v['verdict'] == 'improved' else '❌' if v['verdict'] == 'regressed' else '➡️'} "
        f"{v['target']}: {v['today']:.0f}점 ({v['delta']:+.1f})"
        for v in verdicts
    )

    need_decision = ""
    if stable:
        need_decision = "\n\n💡 <i>Stable 판정 — 반영/보류/롤백 결정 필요</i>"

    msg = (
        f"{icon} <b>VXIS Growth Loop — {status}</b>\n"
        f"\n{details}"
        f"{need_decision}"
    )

    payload = json.dumps({
        "chat_id": chat_id,
        "text": msg,
        "parse_mode": "HTML",
    }).encode("utf-8")

    req = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=15)
        print("  [TELEGRAM] Report sent")
    except Exception as exc:
        print(f"  [TELEGRAM] Failed: {exc}")


# ── 메인 루프 ─────────────────────────────────────────────────────

def should_continue(
    iteration: int,
    max_iterations: int | None,
    until_hour_kst: int | None,
) -> bool:
    """계속 돌릴지 판단."""
    if max_iterations is not None:
        return iteration < max_iterations

    if until_hour_kst is not None:
        now_kst = datetime.now(KST)
        return now_kst.hour < until_hour_kst

    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="VXIS Growth Loop Runner")
    parser.add_argument(
        "--provider", default=None,
        help="LLM provider: together, claude-cli, anthropic, auto (default: auto)",
    )
    parser.add_argument(
        "--brain", default="api",
        choices=["api", "claude-code"],
        help="Brain mode: api (LLM API call) or claude-code (file protocol for Claude Code). Default: api",
    )
    parser.add_argument(
        "--targets", default="dvwa,juice-shop,webgoat,nodegoat",
        help="Comma-separated target names (default: dvwa,juice-shop,webgoat,nodegoat)",
    )
    parser.add_argument(
        "--iterations", type=int, default=None,
        help="Max iterations (default: None = use --until)",
    )
    parser.add_argument(
        "--until", default=None,
        help="Run until this KST hour, e.g. '06:00' (default: 5 iterations)",
    )
    parser.add_argument(
        "--target-type", default="web",
        help="Target type: web, game, mobile (default: web)",
    )

    args = parser.parse_args()

    # LLM Provider 설정
    if args.provider:
        if args.provider == "claude-cli":
            os.environ["VXIS_LLM_PROVIDER"] = "claude-cli"
        elif args.provider == "together":
            os.environ["VXIS_LLM_PROVIDER"] = "api"
            os.environ.setdefault("UPSTREAM_LLM_PROVIDER", "together")
        elif args.provider == "anthropic":
            os.environ.setdefault("UPSTREAM_LLM_PROVIDER", "anthropic")

    # Brain 모드 설정
    if args.brain == "claude-code":
        os.environ["VXIS_BRAIN_MODE"] = "claude-code"
    else:
        os.environ["VXIS_BRAIN_MODE"] = "api"

    # 종료 조건 결정
    max_iterations: int | None = args.iterations
    until_hour_kst: int | None = None

    if args.until:
        until_hour_kst = int(args.until.split(":")[0])
        max_iterations = None  # 시간 기반
    elif max_iterations is None:
        max_iterations = 5  # 기본 5회

    # 타겟 준비
    target_names = [t.strip() for t in args.targets.split(",")]
    print(f"\n{'#' * 60}")
    print(f"  VXIS Growth Loop Runner")
    print(f"  Time: {datetime.now(KST).strftime('%Y-%m-%d %H:%M')} KST")
    print(f"  Targets: {', '.join(target_names)}")
    print(f"  Provider: {args.provider or 'auto'}")
    print(f"  Brain: {args.brain}")
    if until_hour_kst is not None:
        print(f"  Until: {until_hour_kst:02d}:00 KST")
    else:
        print(f"  Iterations: {max_iterations}")
    print(f"{'#' * 60}\n")

    active_targets = ensure_docker_targets(target_names)
    if not active_targets:
        print("\n  [FAIL] No targets available — exiting")
        sys.exit(1)

    # 히스토리 로드
    history = load_history()
    iterations: list[dict] = []
    prev_best = 0.0
    iteration = 0

    # ── 메인 루프 ──
    while should_continue(iteration, max_iterations, until_hour_kst):
        iteration += 1
        now_kst = datetime.now(KST)

        time_info = ""
        if until_hour_kst is not None:
            mins_left = (until_hour_kst - now_kst.hour) * 60 - now_kst.minute
            time_info = f" | 남은시간 ~{mins_left}분"
        iter_label = f"{iteration}" if max_iterations is None else f"{iteration}/{max_iterations}"

        print(f"\n{'=' * 60}")
        print(f"  ITERATION {iter_label}{time_info}")
        print(f"{'=' * 60}")

        iter_results: list[dict] = []

        for target_name, target_url in active_targets:
            print(f"\n  --- {target_name} ---")
            result = run_single_benchmark(target_name, target_url, args.target_type)
            iter_results.append(result)

            if result["error"] is None:
                print(f"  Score: {result['total']:.1f} [{result['grade']}] (delta: {result.get('delta', 0):+.1f})")

                # 히스토리 기록
                history.append({
                    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                    "iteration": iteration,
                    "target_name": target_name,
                    "target_type": args.target_type,
                    "total": result["total"],
                    "grade": result["grade"],
                    "dimensions": result["dimensions"],
                    "delta": result.get("delta", 0),
                })

                # baseline 업데이트 (점수 오르면)
                comp = result.get("comparison")
                if comp and comp.total_delta > 0:
                    result["runner"].save_baseline(result["score_obj"])
                    print(f"  ✅ Baseline updated!")
            else:
                print(f"  ❌ ERROR: {result['error']}")

        # 유효 결과 확인
        valid_results = [r for r in iter_results if r.get("error") is None]
        if not valid_results:
            print("\n  [STOP] 모든 타겟 실패 — 루프 중단")
            break

        current_best = max(r["total"] for r in valid_results)
        best_result = max(valid_results, key=lambda r: r["total"])

        # 약점 분석
        weakest_dim, weakest_pct = find_weakest_dimension(best_result)

        print(f"\n  Best: {current_best:.1f} | "
              f"Weakest: {DIM_NAMES_KO.get(weakest_dim or '', '?')} ({weakest_pct:.0%})")

        # iteration 로그
        improvement = current_best - prev_best if iteration > 1 else 0.0
        iter_log: dict = {
            "iteration": iteration,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "best_score": current_best,
            "weakest_dimension": weakest_dim,
            "weakest_pct": round(weakest_pct, 2),
            "all_dimensions": best_result.get("dimensions", {}),
            "improvement": round(improvement, 1),
            "results_per_target": [
                {
                    "target": r.get("target", "?"),
                    "score": r.get("total", 0),
                    "grade": r.get("grade", "?"),
                    "dimensions": r.get("dimensions", {}),
                    "error": r.get("error", ""),
                }
                for r in iter_results
            ],
        }

        if improvement > 0 and iteration > 1:
            print(f"  📈 +{improvement:.1f}점 성장!")
        elif iteration > 1:
            print(f"  ➡️ 개선 없음 — 계속 시도")

        # 전략 조정
        action = apply_strategy(weakest_dim, iteration)
        iter_log["action"] = action
        iterations.append(iter_log)
        prev_best = current_best

        # 다음 반복 전 대기
        if should_continue(iteration, max_iterations, until_hour_kst):
            print(f"\n  [WAIT] 30초 후 다음 반복...")
            time.sleep(30)

    # ── 최종 판정 ──
    print(f"\n{'#' * 60}")
    print(f"  Growth Loop 완료 — 판정 중...")
    print(f"{'#' * 60}")

    # 판정 생성
    verdicts: list[dict] = []
    if iterations:
        last_iter = iterations[-1]
        for tr in last_iter.get("results_per_target", []):
            if tr.get("error"):
                continue

            target_name = tr["target"]
            today_score = tr["score"]

            # 이전 점수 찾기
            prev_entries = [
                e for e in history[:-len(iterations)]
                if e.get("target_name") == target_name and not e.get("error")
            ]
            prev_score = prev_entries[-1]["total"] if prev_entries else 0
            delta = today_score - prev_score

            verdicts.append({
                "target": target_name,
                "today": today_score,
                "previous": prev_score,
                "delta": round(delta, 1),
                "verdict": make_verdict(delta) if prev_score > 0 else "first_run",
            })

    # 결과 출력
    for v in verdicts:
        icon = {"improved": "✅", "regressed": "❌", "stable": "➡️", "first_run": "🆕"}
        print(f"  {icon.get(v['verdict'], '?')} {v['target']}: "
              f"{v['today']:.1f} (delta: {v['delta']:+.1f}) → {v['verdict'].upper()}")

    # 저장
    save_history(history)
    save_iteration_log(iterations)
    save_latest_results(iterations, verdicts)

    # 리포트 생성
    report = generate_report(iterations, verdicts)
    REPORT_FILE.write_text(report, encoding="utf-8")
    print(f"\n  📄 Report: {REPORT_FILE}")

    # 텔레그램 전송
    send_telegram_report(report, verdicts)

    # 최종 요약 JSON (stdout) — CI/Claude Code에서 파싱 가능
    summary = {
        "total_iterations": len(iterations),
        "start_score": iterations[0]["best_score"] if iterations else 0,
        "final_score": iterations[-1]["best_score"] if iterations else 0,
        "growth": round(
            (iterations[-1]["best_score"] - iterations[0]["best_score"])
            if len(iterations) >= 2 else 0,
            1,
        ),
        "verdicts": verdicts,
        "has_regression": any(v["verdict"] == "regressed" for v in verdicts),
        "needs_decision": any(v["verdict"] == "stable" for v in verdicts),
    }
    print(f"\n::RESULTS::{json.dumps(summary)}::END::")


if __name__ == "__main__":
    main()
