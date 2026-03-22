"""
Upstream Watch — GitHub change fetcher.

Uses GitHub REST API (via gh CLI or httpx) to detect new commits
and releases since last check.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
class RepoChanges:
    target: WatchTarget
    commits: list[CommitInfo] = field(default_factory=list)
    releases: list[ReleaseInfo] = field(default_factory=list)
    diff_summary: str = ""  # Combined diff stat for all new commits
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
