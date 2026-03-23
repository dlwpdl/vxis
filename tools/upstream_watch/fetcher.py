"""
Upstream Watch — GitHub change fetcher.

Uses GitHub REST API (via gh CLI or httpx) to detect new commits
and releases since last check.  Related commits are grouped into
CommitCluster objects before being forwarded to the analyzer.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .config import STATE_FILE, WatchTarget


@dataclass
class CommitInfo:
    sha: str
    message: str
    author: str
    date: str
    url: str
    files_changed: list[str] = field(default_factory=list)


@dataclass
class ReleaseInfo:
    tag: str
    name: str
    body: str
    date: str
    url: str


@dataclass
class CommitCluster:
    """A group of related commits that share temporal and file-path proximity."""

    commits: list[CommitInfo]
    summary: str  # Combined commit messages, newline-separated
    files_changed: list[str]  # Union of all files across the cluster
    time_span: str  # Human-readable duration, e.g. "2h30m"


@dataclass
class RepoChanges:
    target: WatchTarget
    commits: list[CommitInfo] = field(default_factory=list)
    releases: list[ReleaseInfo] = field(default_factory=list)
    diff_summary: str = ""  # Combined diff stat for all new commits
    clusters: list[CommitCluster] = field(default_factory=list)
    error: str = ""

    @property
    def has_changes(self) -> bool:
        return bool(self.commits or self.releases)


def _run_gh(args: list[str], timeout: int = 30) -> dict | list | str:
    """Run gh CLI command and return parsed JSON output."""
    cmd = ["gh", "api", *args]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh api failed: {result.stderr.strip()}")
    if not result.stdout.strip():
        return {}
    return json.loads(result.stdout)


def _load_state() -> dict:
    """Load last-checked state from JSON file."""
    path = Path(STATE_FILE)
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def _save_state(state: dict) -> None:
    """Persist state to JSON file."""
    path = Path(STATE_FILE)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2))


def _state_key(target: WatchTarget) -> str:
    return f"{target.owner}/{target.repo}"


def _filter_files(files: list[str], target: WatchTarget) -> list[str]:
    """Filter file paths based on include/exclude rules."""
    result = []
    for f in files:
        # Exclude check
        if any(f.startswith(ex) or f == ex for ex in target.exclude_paths):
            continue
        # Include check (empty = include all)
        if target.include_paths:
            if not any(f.startswith(inc) for inc in target.include_paths):
                continue
        result.append(f)
    return result


def fetch_commits(
    target: WatchTarget, since: str | None = None, max_commits: int = 50
) -> list[CommitInfo]:
    """Fetch commits since a given ISO timestamp."""
    commits = []
    for branch in target.branches:
        endpoint = f"/repos/{target.owner}/{target.repo}/commits"
        params = [endpoint, "--jq", ".", "-q", "per_page=50"]
        if since:
            params.extend(["-f", f"since={since}"])
        params.extend(["-f", f"sha={branch}"])

        try:
            raw = _run_gh(params, timeout=60)
        except (RuntimeError, subprocess.TimeoutExpired):
            continue

        if not isinstance(raw, list):
            continue

        for item in raw[:max_commits]:
            sha = item.get("sha", "")
            commit_data = item.get("commit", {})
            author_data = commit_data.get("author", {})

            # Fetch files changed for this commit
            try:
                detail = _run_gh(
                    [f"/repos/{target.owner}/{target.repo}/commits/{sha}"],
                    timeout=30,
                )
                files = [f.get("filename", "") for f in detail.get("files", [])]
            except (RuntimeError, subprocess.TimeoutExpired):
                files = []

            # Filter by path rules
            relevant_files = _filter_files(files, target)
            if target.include_paths and not relevant_files:
                continue  # Skip commits with no relevant file changes

            commits.append(
                CommitInfo(
                    sha=sha[:12],
                    message=commit_data.get("message", "").split("\n")[0],
                    author=author_data.get("name", "unknown"),
                    date=author_data.get("date", ""),
                    url=item.get("html_url", ""),
                    files_changed=relevant_files,
                )
            )

    # Deduplicate by sha (same commit on multiple branches)
    seen = set()
    unique = []
    for c in commits:
        if c.sha not in seen:
            seen.add(c.sha)
            unique.append(c)
    return unique


def fetch_releases(
    target: WatchTarget, since: str | None = None
) -> list[ReleaseInfo]:
    """Fetch releases since a given ISO timestamp."""
    try:
        raw = _run_gh(
            [f"/repos/{target.owner}/{target.repo}/releases", "-q", ".", "--jq", "."],
            timeout=30,
        )
    except (RuntimeError, subprocess.TimeoutExpired):
        return []

    if not isinstance(raw, list):
        return []

    releases = []
    for item in raw[:10]:
        published = item.get("published_at", "")
        if since and published and published <= since:
            continue
        releases.append(
            ReleaseInfo(
                tag=item.get("tag_name", ""),
                name=item.get("name", ""),
                body=(item.get("body", "") or "")[:3000],  # Truncate large bodies
                date=published,
                url=item.get("html_url", ""),
            )
        )
    return releases


def fetch_diff_stat(target: WatchTarget, base_sha: str, head_sha: str) -> str:
    """Fetch a compact diff stat between two commits."""
    try:
        raw = _run_gh(
            [f"/repos/{target.owner}/{target.repo}/compare/{base_sha}...{head_sha}"],
            timeout=60,
        )
        if not isinstance(raw, dict):
            return ""

        files = raw.get("files", [])
        stats = []
        for f in files[:30]:  # Limit to 30 files
            fname = f.get("filename", "")
            additions = f.get("additions", 0)
            deletions = f.get("deletions", 0)
            status = f.get("status", "modified")
            stats.append(f"  {status}: {fname} (+{additions}/-{deletions})")

        total = raw.get("total_commits", 0)
        ahead = raw.get("ahead_by", 0)
        return f"{ahead} commits, {len(files)} files changed:\n" + "\n".join(stats)
    except (RuntimeError, subprocess.TimeoutExpired):
        return ""


def _parse_commit_datetime(date_str: str) -> datetime | None:
    """Parse ISO 8601 commit date into an aware UTC datetime, or None on failure."""
    if not date_str:
        return None
    try:
        # GitHub returns e.g. "2024-01-15T12:34:56Z"
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        return None


def _format_timedelta(delta: timedelta) -> str:
    """Format a timedelta as a compact human-readable string like '2h30m'."""
    total_seconds = int(abs(delta.total_seconds()))
    hours, remainder = divmod(total_seconds, 3600)
    minutes = remainder // 60
    if hours and minutes:
        return f"{hours}h{minutes}m"
    if hours:
        return f"{hours}h"
    if minutes:
        return f"{minutes}m"
    return f"{total_seconds}s"


def _file_overlap_ratio(files_a: list[str], files_b: list[str]) -> float:
    """
    Compute Jaccard-like overlap ratio between two file path sets.

    Returns 0.0 when both sets are empty (no evidence of relatedness).
    """
    set_a = set(files_a)
    set_b = set(files_b)
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


def cluster_commits(commits: list[CommitInfo]) -> list[CommitCluster]:
    """
    Group related commits into CommitCluster objects.

    Two commits are merged into the same cluster when they satisfy ANY of:
    1. Both are within a 4-hour time window AND share >30 % of modified files
       (path overlap by Jaccard ratio).
    2. They share the same author AND are within a 2-hour time window.

    The algorithm is a single-pass greedy merge: each commit is tested
    against every existing cluster's representative window and file set.
    This is O(n * k) where k is the number of clusters — acceptable for
    the typical upstream watch batch size of ≤200 commits.

    Returns a list of CommitCluster objects.  Commits with unparseable
    dates are placed in singleton clusters.
    """
    if not commits:
        return []

    # Pre-parse dates once
    dated: list[tuple[CommitInfo, datetime | None]] = [
        (c, _parse_commit_datetime(c.date)) for c in commits
    ]

    _4h = timedelta(hours=4)
    _2h = timedelta(hours=2)
    FILE_OVERLAP_THRESHOLD = 0.30

    # Each open cluster is represented as a mutable dict for accumulation
    open_clusters: list[dict] = []

    for commit, dt in dated:
        merged = False
        for clust in open_clusters:
            clust_dt: datetime | None = clust["representative_dt"]

            # Condition 1: time window + file overlap
            time_close_4h = (
                dt is not None
                and clust_dt is not None
                and abs(dt - clust_dt) <= _4h
            )
            file_overlap = _file_overlap_ratio(commit.files_changed, clust["files"])
            cond1 = time_close_4h and file_overlap > FILE_OVERLAP_THRESHOLD

            # Condition 2: same author + 2-hour window
            time_close_2h = (
                dt is not None
                and clust_dt is not None
                and abs(dt - clust_dt) <= _2h
            )
            cond2 = time_close_2h and commit.author == clust["author"]

            if cond1 or cond2:
                # Absorb commit into this cluster
                clust["commits"].append(commit)
                clust["files"] = list(set(clust["files"]) | set(commit.files_changed))
                clust["messages"].append(commit.message)
                # Extend the representative timestamp toward the newest commit
                if dt is not None and (
                    clust_dt is None or dt > clust_dt
                ):
                    clust["representative_dt"] = dt
                # Track earliest/latest for time_span calculation
                if dt is not None:
                    if clust["earliest_dt"] is None or dt < clust["earliest_dt"]:
                        clust["earliest_dt"] = dt
                    if clust["latest_dt"] is None or dt > clust["latest_dt"]:
                        clust["latest_dt"] = dt
                merged = True
                break

        if not merged:
            open_clusters.append({
                "commits": [commit],
                "files": list(commit.files_changed),
                "messages": [commit.message],
                "author": commit.author,
                "representative_dt": dt,
                "earliest_dt": dt,
                "latest_dt": dt,
            })

    # Convert raw dicts to CommitCluster dataclasses
    result: list[CommitCluster] = []
    for clust in open_clusters:
        earliest: datetime | None = clust["earliest_dt"]
        latest: datetime | None = clust["latest_dt"]
        if earliest is not None and latest is not None and earliest != latest:
            span = _format_timedelta(latest - earliest)
        elif len(clust["commits"]) == 1:
            span = "0m"
        else:
            span = "unknown"

        result.append(
            CommitCluster(
                commits=clust["commits"],
                summary="\n".join(clust["messages"]),
                files_changed=sorted(set(clust["files"])),
                time_span=span,
            )
        )

    return result


def fetch_all(targets: list[WatchTarget]) -> list[RepoChanges]:
    """Fetch changes for all targets since last check."""
    state = _load_state()
    now = datetime.now(timezone.utc).isoformat()
    results = []

    for target in targets:
        key = _state_key(target)
        since = state.get(key, {}).get("last_checked")
        last_sha = state.get(key, {}).get("last_sha")

        changes = RepoChanges(target=target)

        try:
            if target.watch_commits:
                changes.commits = fetch_commits(target, since=since)

                # Get diff stat if we have a previous SHA
                if last_sha and changes.commits:
                    changes.diff_summary = fetch_diff_stat(
                        target, last_sha, changes.commits[0].sha
                    )

                # Cluster related commits for downstream analysis
                if changes.commits:
                    changes.clusters = cluster_commits(changes.commits)

            if target.watch_releases:
                changes.releases = fetch_releases(target, since=since)

        except Exception as e:
            changes.error = str(e)

        # Update state
        state[key] = {
            "last_checked": now,
            "last_sha": changes.commits[0].sha if changes.commits else last_sha,
            "last_release": (
                changes.releases[0].tag if changes.releases else
                state.get(key, {}).get("last_release")
            ),
        }

        results.append(changes)

    _save_state(state)
    return results
