#!/usr/bin/env python3
"""VXIS Brain TUI — Claude Code가 Brain으로 동작할 때 터미널 대시보드.

Usage:
    # 1. 백그라운드에서 파이프라인 시작
    PYTHONPATH=src python tools/growth_loop_runner.py --brain claude-code --targets dvwa &

    # 2. Brain TUI 시작 (포그라운드)
    python tools/brain_tui.py

    # 또는 한 줄로:
    python tools/brain_tui.py --launch --targets dvwa
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Rich imports
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.progress import Progress, BarColumn, TextColumn, SpinnerColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

BRAIN_DIR = Path("tools/benchmark/.brain")
STATUS = BRAIN_DIR / "status.json"
OBS = BRAIN_DIR / "observation.json"
DEC = BRAIN_DIR / "decision.json"
RESULT = BRAIN_DIR / "result.json"

console = Console()

# ── DVWA 공격 페이로드 DB ──────────────────────────────────────

DVWA_PAYLOADS: dict[str, list[dict]] = {
    "WEB-SQLI": [
        {"endpoint": "/vulnerabilities/sqli/", "method": "GET", "param": "id",
         "payloads": ["1' OR '1'='1", "1' UNION SELECT user,password FROM users--",
                      "1' AND 1=1--", "1 OR 1=1"]},
        {"endpoint": "/login.php", "method": "POST", "param": "username",
         "payloads": ["admin' OR '1'='1'--", "' OR 1=1--"]},
    ],
    "WEB-XSS": [
        {"endpoint": "/vulnerabilities/xss_r/", "method": "GET", "param": "name",
         "payloads": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                      "<svg/onload=alert(1)>", "'\"><details open ontoggle=alert(1)>"]},
        {"endpoint": "/vulnerabilities/xss_s/", "method": "POST", "param": "mtxMessage",
         "payloads": ["<script>alert(document.cookie)</script>"]},
    ],
    "WEB-CMDI": [
        {"endpoint": "/vulnerabilities/exec/", "method": "POST", "param": "ip",
         "payloads": ["127.0.0.1; cat /etc/passwd", "127.0.0.1 | id", "127.0.0.1 && whoami"]},
    ],
    "WEB-UPLOAD": [
        {"endpoint": "/vulnerabilities/upload/", "method": "POST", "param": "uploaded",
         "payloads": ["test.php"]},
    ],
    "WEB-CSRF": [
        {"endpoint": "/vulnerabilities/csrf/", "method": "GET", "param": "password_new",
         "payloads": ["hacked123"]},
    ],
    "WEB-AUTH": [
        {"endpoint": "/login.php", "method": "POST", "param": "username",
         "payloads": ["admin"]},
        {"endpoint": "/vulnerabilities/brute/", "method": "GET", "param": "username",
         "payloads": ["admin"]},
    ],
    "WEB-SSRF": [
        {"endpoint": "/vulnerabilities/fi/", "method": "GET", "param": "page",
         "payloads": ["http://169.254.169.254/", "file:///etc/passwd", "/etc/passwd"]},
    ],
    "WEB-MISCONF": [
        {"endpoint": "/", "method": "GET", "param": "", "payloads": [""]},
        {"endpoint": "/.git/config", "method": "GET", "param": "", "payloads": [""]},
        {"endpoint": "/phpinfo.php", "method": "GET", "param": "", "payloads": [""]},
    ],
}


def atomic_write(path: str, data: dict) -> None:
    """Atomic JSON write."""
    import tempfile
    dir_path = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def get_payloads_for_vector(vector_id: str) -> list[dict]:
    """벡터 ID에 맞는 페이로드 반환."""
    prefix = "-".join(vector_id.split("-")[:2])
    return DVWA_PAYLOADS.get(prefix, [
        {"endpoint": "/", "method": "GET", "param": "", "payloads": [""]}
    ])


def build_dashboard(
    state: str,
    step: int,
    total: int,
    current_vector: str,
    current_phase: str,
    findings: int,
    decisions_log: list[dict],
    elapsed: float,
) -> Layout:
    """터미널 대시보드 레이아웃 생성."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="progress", ratio=2),
        Layout(name="log", ratio=3),
    )

    # Header
    state_colors = {
        "initializing": "yellow",
        "waiting_for_brain": "cyan",
        "executing": "green",
        "done": "bold green",
        "error": "bold red",
    }
    state_color = state_colors.get(state, "white")
    header_text = Text()
    header_text.append("  VXIS Brain TUI", style="bold magenta")
    header_text.append("  |  State: ")
    header_text.append(state.upper(), style=state_color)
    header_text.append(f"  |  Elapsed: {elapsed:.0f}s")
    layout["header"].update(Panel(header_text, style="blue"))

    # Progress panel
    progress_table = Table(show_header=False, box=None, padding=(0, 1))
    progress_table.add_column("label", style="bold", width=14)
    progress_table.add_column("value")

    pct = (step / total * 100) if total > 0 else 0
    bar_filled = int(pct / 5)
    bar = "[green]" + "█" * bar_filled + "[/green]" + "░" * (20 - bar_filled)

    progress_table.add_row("Vectors", f"{step}/{total}  {bar}  {pct:.0f}%")
    progress_table.add_row("Findings", f"[{'green' if findings > 0 else 'red'}]{findings}[/]")
    progress_table.add_row("Current", f"[cyan]{current_vector}[/]")
    progress_table.add_row("Phase", current_phase[:40])

    layout["progress"].update(Panel(progress_table, title="Progress", border_style="green"))

    # Log panel
    log_table = Table(show_header=True, header_style="bold", box=None, padding=(0, 1))
    log_table.add_column("#", width=4, justify="right")
    log_table.add_column("Vector", width=18)
    log_table.add_column("Payloads", width=4, justify="right")
    log_table.add_column("Status", width=8)

    for entry in decisions_log[-15:]:  # last 15
        status_style = "green" if entry.get("hit") else "dim"
        status_text = "HIT!" if entry.get("hit") else "sent"
        log_table.add_row(
            str(entry.get("step", "")),
            entry.get("vector", ""),
            str(entry.get("payloads", 0)),
            Text(status_text, style=status_style),
        )

    layout["log"].update(Panel(log_table, title="Decision Log", border_style="cyan"))

    # Footer
    footer = Text()
    footer.append("  Brain: Claude Code (FileBasedBrain)", style="dim")
    footer.append("  |  Press Ctrl+C to stop", style="dim")
    layout["footer"].update(Panel(footer, style="dim"))

    return layout


def run_brain_tui(launch: bool = False, targets: str = "dvwa", iterations: str = "1") -> None:
    """Brain TUI 메인 루프."""
    BRAIN_DIR.mkdir(parents=True, exist_ok=True)

    # 파이프라인 자동 시작
    if launch:
        # 이전 파일 정리
        for f in BRAIN_DIR.iterdir():
            f.unlink()

        console.print("[bold magenta]Starting pipeline in background...[/]")
        env = os.environ.copy()
        env["PYTHONPATH"] = "src"
        subprocess.Popen(
            [sys.executable, "tools/growth_loop_runner.py",
             "--brain", "claude-code", "--iterations", iterations, "--targets", targets],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(2)

    decisions_log: list[dict] = []
    total_vectors = 67  # WEB_VECTORS count
    start_time = time.monotonic()

    with Live(console=console, refresh_per_second=4, screen=True) as live:
        while True:
            elapsed = time.monotonic() - start_time

            # Read status
            state = "initializing"
            step = 0
            findings = 0
            current_vector = ""
            current_phase = ""

            if STATUS.exists():
                try:
                    status = json.loads(STATUS.read_text())
                    state = status.get("state", "initializing")
                    step = status.get("vector_index", status.get("step", 0))
                    findings = status.get("findings_so_far", status.get("total_findings", 0))
                except (json.JSONDecodeError, OSError):
                    pass

            if state == "done":
                total = status.get("total_vectors", total_vectors)
                findings = status.get("total_findings", 0)
                live.update(build_dashboard(
                    state, total, total, "COMPLETE", "All phases done",
                    findings, decisions_log, elapsed,
                ))
                time.sleep(2)
                break

            if state == "error":
                live.update(build_dashboard(
                    state, step, total_vectors, "ERROR", "",
                    findings, decisions_log, elapsed,
                ))
                time.sleep(2)
                break

            # Brain 판단 로직
            if state == "waiting_for_brain" and not DEC.exists() and OBS.exists():
                try:
                    obs = json.loads(OBS.read_text())
                    vector_id = obs.get("vector_id", "unknown")
                    current_vector = vector_id
                    current_phase = obs.get("phase", "")
                    cum_findings = obs.get("cumulative_findings", [])

                    targets = get_payloads_for_vector(vector_id)
                    n_payloads = sum(len(t.get("payloads", [])) for t in targets)

                    chain = ""
                    if cum_findings:
                        chain = f"Chain: {len(cum_findings)} findings"

                    decision = {
                        "vector_id": vector_id,
                        "attempt": True,
                        "reasoning": f"DVWA: {vector_id} with {n_payloads} payloads. {chain}",
                        "targets": targets,
                        "chain_hint": chain,
                    }

                    atomic_write(str(DEC), decision)

                    decisions_log.append({
                        "step": step,
                        "vector": vector_id,
                        "payloads": n_payloads,
                        "hit": False,
                    })

                except (json.JSONDecodeError, OSError):
                    pass

            # Result 체크 (hit 감지)
            if RESULT.exists():
                try:
                    result = json.loads(RESULT.read_text())
                    if result.get("findings"):
                        if decisions_log:
                            decisions_log[-1]["hit"] = True
                        findings += len(result["findings"])
                except (json.JSONDecodeError, OSError):
                    pass

            live.update(build_dashboard(
                state, step, total_vectors, current_vector, current_phase,
                findings, decisions_log, elapsed,
            ))

            time.sleep(0.25)

    # 최종 리포트 출력
    console.print()
    report_path = Path("tools/benchmark/growth_report.md")
    if report_path.exists():
        console.print(Panel(report_path.read_text(), title="Growth Report", border_style="green"))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="VXIS Brain TUI")
    parser.add_argument("--launch", action="store_true",
                        help="Auto-launch pipeline in background")
    parser.add_argument("--targets", default="dvwa",
                        help="Comma-separated targets (default: dvwa)")
    parser.add_argument("--iterations", default="1",
                        help="Max iterations (default: 1)")
    args = parser.parse_args()
    try:
        run_brain_tui(launch=args.launch, targets=args.targets, iterations=args.iterations)
    except KeyboardInterrupt:
        console.print("\n[yellow]Brain TUI stopped.[/]")
