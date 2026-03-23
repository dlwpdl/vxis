"""Track repository activity trends — commit velocity, stars, forks."""

from __future__ import annotations

import json
import subprocess
from dataclasses import asdict, dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

METRICS_HISTORY_FILE = Path("tools/upstream_watch/.metrics_history.json")
MAX_HISTORY_DAYS = 90


@dataclass
class RepoMetrics:
    """Snapshot of a repository's activity at a point in time."""

    repo: str              # "owner/repo"
    stars: int
    forks: int
    open_issues: int
    commit_count_today: int
    fetched_at: str        # ISO date string, e.g. "2026-03-23"


def _run_gh_json(args: list[str], timeout: int = 30) -> dict | list:
    """Run gh CLI and return parsed JSON. Returns empty dict on any failure."""
    try:
        result = subprocess.run(
            ["gh", "api", *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return {}
        text = result.stdout.strip()
        if not text:
            return {}
        return json.loads(text)
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return {}


def fetch_repo_metrics(owner: str, repo: str) -> RepoMetrics:
    """
    Fetch current stars, forks, open_issues, and today's commit count
    for a repository using the gh CLI.

    Returns a zeroed RepoMetrics if gh is unavailable or the request fails.
    """
    full_name = f"{owner}/{repo}"
    today = date.today().isoformat()

    # Fetch repo metadata (stars, forks, open issues)
    repo_data = _run_gh_json([f"/repos/{owner}/{repo}"])
    stars = int(repo_data.get("stargazers_count", 0)) if isinstance(repo_data, dict) else 0
    forks = int(repo_data.get("forks_count", 0)) if isinstance(repo_data, dict) else 0
    open_issues = int(repo_data.get("open_issues_count", 0)) if isinstance(repo_data, dict) else 0

    # Count commits pushed today (UTC)
    today_start = f"{today}T00:00:00Z"
    commits_data = _run_gh_json([
        f"/repos/{owner}/{repo}/commits",
        "-f", f"since={today_start}",
        "-f", "per_page=100",
    ], timeout=60)
    commit_count = len(commits_data) if isinstance(commits_data, list) else 0

    return RepoMetrics(
        repo=full_name,
        stars=stars,
        forks=forks,
        open_issues=open_issues,
        commit_count_today=commit_count,
        fetched_at=today,
    )


class TrendTracker:
    """
    Maintains a rolling 90-day history of RepoMetrics per repository and
    exposes spike detection and trending summaries.
    """

    def __init__(self) -> None:
        self._history: dict[str, list[dict]] = self._load()

    # ── Persistence ──────────────────────────────────────────────

    def _load(self) -> dict[str, list[dict]]:
        if not METRICS_HISTORY_FILE.exists():
            return {}
        try:
            raw = json.loads(METRICS_HISTORY_FILE.read_text())
            if isinstance(raw, dict):
                return raw
        except (json.JSONDecodeError, OSError):
            pass
        return {}

    def _save(self) -> None:
        METRICS_HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
        METRICS_HISTORY_FILE.write_text(
            json.dumps(self._history, indent=2, ensure_ascii=False)
        )

    # ── Public API ───────────────────────────────────────────────

    def record_metrics(self, metrics: RepoMetrics) -> None:
        """Append a RepoMetrics snapshot to history and prune beyond 90 days."""
        if metrics.repo not in self._history:
            self._history[metrics.repo] = []

        entry = asdict(metrics)
        self._history[metrics.repo].append(entry)

        # Prune old entries
        cutoff = (date.today() - timedelta(days=MAX_HISTORY_DAYS)).isoformat()
        self._history[metrics.repo] = [
            e for e in self._history[metrics.repo]
            if e.get("fetched_at", "") >= cutoff
        ]
        self._save()

    def detect_spikes(self, repo: str, window_days: int = 7) -> list[str]:
        """
        Compare the most recent day's metrics against a rolling window average.

        Returns a list of spike labels (may be empty):
          - "commit_spike"  — today's commits > 2× 7-day average
          - "star_spike"    — stars gained today > 3× daily average gain
        """
        entries = self._history.get(repo, [])
        if len(entries) < 2:
            return []

        # Sort by date ascending
        sorted_entries = sorted(entries, key=lambda e: e.get("fetched_at", ""))
        latest = sorted_entries[-1]
        window = sorted_entries[-(window_days + 1):-1]  # up to window_days prior entries

        if not window:
            return []

        spikes: list[str] = []

        # Commit spike: today vs window average
        avg_commits = sum(e.get("commit_count_today", 0) for e in window) / len(window)
        today_commits = latest.get("commit_count_today", 0)
        if avg_commits > 0 and today_commits > 2 * avg_commits:
            spikes.append("commit_spike")

        # Star spike: stars gained today vs average daily gain over window
        if len(window) >= 2:
            oldest_stars = window[0].get("stars", 0)
            newest_stars = window[-1].get("stars", 0)
            days_in_window = len(window)
            avg_daily_star_gain = (newest_stars - oldest_stars) / max(days_in_window, 1)
            today_star_gain = latest.get("stars", 0) - window[-1].get("stars", 0)
            if avg_daily_star_gain > 0 and today_star_gain > 3 * avg_daily_star_gain:
                spikes.append("star_spike")

        return spikes

    def get_trending_summary(self) -> str:
        """Return a markdown summary of all tracked repos with trend indicators."""
        if not self._history:
            return "_No trending data collected yet._"

        lines = ["## Trending Summary", ""]
        for repo in sorted(self._history):
            entries = sorted(
                self._history[repo], key=lambda e: e.get("fetched_at", "")
            )
            if not entries:
                continue

            latest = entries[-1]
            spikes = self.detect_spikes(repo)

            spike_labels = ""
            if spikes:
                spike_labels = "  **[" + ", ".join(s.upper() for s in spikes) + "]**"

            lines.append(
                f"- **{repo}** — "
                f"stars: {latest.get('stars', 0):,} | "
                f"forks: {latest.get('forks', 0):,} | "
                f"commits today: {latest.get('commit_count_today', 0)}"
                f"{spike_labels}"
            )

        return "\n".join(lines)


def format_trending_report(tracker: TrendTracker) -> str:
    """
    Generate a full markdown trending report showing:
      - Stars velocity (gained this week)
      - Commit velocity (this week vs last week)
      - Spike alerts
    """
    lines = [
        "# Upstream Trending Report",
        f"_Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_",
        "",
    ]

    if not tracker._history:
        lines.append("_No metrics history available._")
        return "\n".join(lines)

    # ── Stars velocity table ──────────────────────────────────────
    lines.extend(["## Stars Velocity (this week)", ""])
    lines.extend([
        "| Repository | Stars (now) | +Stars this week | +Forks this week |",
        "|------------|-------------|------------------|------------------|",
    ])

    cutoff_week = (date.today() - timedelta(days=7)).isoformat()

    for repo in sorted(tracker._history):
        entries = sorted(
            tracker._history[repo], key=lambda e: e.get("fetched_at", "")
        )
        if not entries:
            continue

        latest = entries[-1]
        week_start = next(
            (e for e in entries if e.get("fetched_at", "") >= cutoff_week),
            entries[0],
        )

        star_delta = latest.get("stars", 0) - week_start.get("stars", 0)
        fork_delta = latest.get("forks", 0) - week_start.get("forks", 0)
        star_delta_str = f"+{star_delta}" if star_delta >= 0 else str(star_delta)
        fork_delta_str = f"+{fork_delta}" if fork_delta >= 0 else str(fork_delta)

        lines.append(
            f"| {repo} | {latest.get('stars', 0):,} | "
            f"{star_delta_str} | {fork_delta_str} |"
        )

    lines.append("")

    # ── Commit velocity table ────────────────────────────────────
    lines.extend(["## Commit Velocity", ""])
    lines.extend([
        "| Repository | Commits (today) | Avg/day (7d) | vs last 7d |",
        "|------------|-----------------|--------------|------------|",
    ])

    cutoff_14 = (date.today() - timedelta(days=14)).isoformat()

    for repo in sorted(tracker._history):
        entries = sorted(
            tracker._history[repo], key=lambda e: e.get("fetched_at", "")
        )
        if not entries:
            continue

        latest = entries[-1]
        this_week = [
            e for e in entries
            if e.get("fetched_at", "") >= cutoff_week
        ]
        prev_week = [
            e for e in entries
            if cutoff_14 <= e.get("fetched_at", "") < cutoff_week
        ]

        avg_this = (
            sum(e.get("commit_count_today", 0) for e in this_week) / len(this_week)
            if this_week else 0.0
        )
        avg_prev = (
            sum(e.get("commit_count_today", 0) for e in prev_week) / len(prev_week)
            if prev_week else 0.0
        )

        if avg_prev > 0:
            change_pct = ((avg_this - avg_prev) / avg_prev) * 100
            change_str = f"{change_pct:+.0f}%"
        elif avg_this > 0:
            change_str = "new activity"
        else:
            change_str = "—"

        lines.append(
            f"| {repo} | {latest.get('commit_count_today', 0)} | "
            f"{avg_this:.1f} | {change_str} |"
        )

    lines.append("")

    # ── Spike alerts ─────────────────────────────────────────────
    spike_alerts: list[str] = []
    for repo in tracker._history:
        spikes = tracker.detect_spikes(repo)
        for spike in spikes:
            label = "Commit spike" if spike == "commit_spike" else "Star spike"
            spike_alerts.append(f"- **[ALERT] {label}** detected in `{repo}`")

    if spike_alerts:
        lines.extend(["## Spike Alerts", ""])
        lines.extend(spike_alerts)
        lines.append("")
    else:
        lines.extend(["## Spike Alerts", "", "_No anomalies detected._", ""])

    return "\n".join(lines)
