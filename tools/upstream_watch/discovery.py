"""Discover new AI pentesting tools via GitHub Search API."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path


@dataclass
class DiscoveredRepo:
    """A newly discovered repository that may be relevant to VXIS."""

    owner: str
    repo: str
    description: str
    stars: int
    language: str
    created_at: str
    url: str
    relevance_reason: str


def _run_gh_search(query: str, timeout: int = 30) -> list[dict]:
    """
    Execute a GitHub repository search via gh CLI and return raw item list.
    Returns an empty list if gh is unavailable or the query fails.
    """
    try:
        result = subprocess.run(
            [
                "gh", "api",
                "-X", "GET",
                "search/repositories",
                "-f", f"q={query}",
                "-f", "sort=stars",
                "-f", "order=desc",
                "-f", "per_page=30",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            return []
        text = result.stdout.strip()
        if not text:
            return []
        data = json.loads(text)
        if isinstance(data, dict):
            return data.get("items", [])
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return []


def _load_watch_targets() -> set[str]:
    """
    Return the set of full_names ("owner/repo") currently being watched.
    Reads both the TOML registry and hardcoded config defaults.
    """
    known: set[str] = set()

    # Registry (TOML)
    registry_path = Path("tools/upstream_watch/watch_targets.toml")
    if registry_path.exists():
        try:
            import tomllib
            with open(registry_path, "rb") as f:
                data = tomllib.load(f)
            for cfg in data.get("targets", {}).values():
                owner = cfg.get("owner", "")
                repo = cfg.get("repo", "")
                if owner and repo:
                    known.add(f"{owner}/{repo}")
        except Exception:
            pass

    # Hardcoded defaults
    try:
        from .config import TARGETS
        for t in TARGETS:
            known.add(f"{t.owner}/{t.repo}")
    except Exception:
        pass

    return known


def search_new_tools() -> list[DiscoveredRepo]:
    """
    Search GitHub for recently created AI/LLM pentesting tools.

    Runs four targeted queries with different keywords and star thresholds,
    deduplicates results, filters out already-watched repos, and returns
    a list sorted by stars descending.
    """
    since_date = (date.today() - timedelta(days=30)).isoformat()

    queries: list[tuple[str, str]] = [
        (
            f"AI pentesting language:python stars:>50 created:>{since_date}",
            "AI pentesting tool (Python, >50 stars)",
        ),
        (
            f"LLM security tool language:python stars:>30 created:>{since_date}",
            "LLM-powered security tool (Python, >30 stars)",
        ),
        (
            f"automated pentest language:python stars:>100 created:>{since_date}",
            "Automated pentest framework (Python, >100 stars)",
        ),
        (
            f"vulnerability scanner AI stars:>50 created:>{since_date}",
            "AI vulnerability scanner (any language, >50 stars)",
        ),
    ]

    known_targets = _load_watch_targets()

    seen: dict[str, DiscoveredRepo] = {}

    for query, reason in queries:
        items = _run_gh_search(query)
        for item in items:
            if not isinstance(item, dict):
                continue

            owner_data = item.get("owner", {}) or {}
            owner = owner_data.get("login", "")
            repo_name = item.get("name", "")
            if not owner or not repo_name:
                continue

            full_name = f"{owner}/{repo_name}"

            # Skip already-watched repos
            if full_name in known_targets:
                continue

            # Deduplicate — keep first occurrence (highest stars, since sorted desc)
            if full_name in seen:
                continue

            seen[full_name] = DiscoveredRepo(
                owner=owner,
                repo=repo_name,
                description=(item.get("description") or "").strip(),
                stars=int(item.get("stargazers_count", 0)),
                language=(item.get("language") or "").strip(),
                created_at=(item.get("created_at") or "")[:10],  # date only
                url=item.get("html_url", f"https://github.com/{full_name}"),
                relevance_reason=reason,
            )

    # Sort by stars descending
    return sorted(seen.values(), key=lambda r: r.stars, reverse=True)


def format_discovery_report(repos: list[DiscoveredRepo]) -> str:
    """
    Render a markdown report of newly discovered repositories.
    """
    if not repos:
        return "## New Tool Discovery\n\n_No new AI pentesting tools discovered this run._\n"

    lines = [
        "## New Tool Discovery",
        f"_{len(repos)} newly discovered repositories_",
        "",
        "| Repository | Stars | Language | Created | Reason |",
        "|------------|-------|----------|---------|--------|",
    ]

    for r in repos:
        link = f"[{r.owner}/{r.repo}]({r.url})"
        lines.append(
            f"| {link} | {r.stars:,} | {r.language or '—'} | "
            f"{r.created_at} | {r.relevance_reason} |"
        )

    lines.append("")

    # Detailed entries for high-value discoveries
    notable = [r for r in repos if r.stars >= 100]
    if notable:
        lines.extend(["### Notable Discoveries", ""])
        for r in notable:
            lines.extend([
                f"#### [{r.owner}/{r.repo}]({r.url}) — {r.stars:,} stars",
                f"**Language:** {r.language or 'unknown'}  |  "
                f"**Created:** {r.created_at}",
                "",
                r.description or "_No description provided._",
                "",
                f"**Why relevant:** {r.relevance_reason}",
                "",
            ])

    return "\n".join(lines)
