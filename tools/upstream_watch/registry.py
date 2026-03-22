"""
Upstream Watch — Dynamic watch target registry.

Manages watched repositories via TOML file, supporting add/remove/list
operations through CLI. Replaces hardcoded TARGETS list.
"""

from __future__ import annotations

import tomllib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

REGISTRY_FILE = Path("tools/upstream_watch/watch_targets.toml")


@dataclass
class WatchTarget:
    """A GitHub repository to monitor for changes relevant to VXIS."""

    owner: str
    repo: str
    reason: str
    watch_releases: bool = True
    watch_commits: bool = True
    branches: list[str] = field(default_factory=lambda: ["main", "master"])
    include_paths: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(
        default_factory=lambda: [
            "docs/", ".github/", "README.md", "CHANGELOG.md", "LICENSE", ".gitignore"
        ]
    )
    relevance_tags: list[str] = field(default_factory=list)
    # Management metadata
    added_at: str = ""
    enabled: bool = True
    notes: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def toml_key(self) -> str:
        """TOML-safe key: owner--repo"""
        return f"{self.owner}--{self.repo}"


def _serialize_target(t: WatchTarget) -> dict:
    """Convert target to TOML-safe dict."""
    d = asdict(t)
    # Remove empty strings for cleaner TOML
    return {k: v for k, v in d.items() if v != "" and v != []}


def _write_toml(targets: dict[str, WatchTarget]) -> None:
    """Write targets to TOML file."""
    lines = [
        "# VXIS Upstream Watch — Watched Repositories",
        "# Managed via: python -m tools.upstream_watch target <add|remove|list>",
        "#",
        f"# Last updated: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]

    for key, t in sorted(targets.items()):
        lines.append(f'[targets."{key}"]')
        lines.append(f'owner = "{t.owner}"')
        lines.append(f'repo = "{t.repo}"')
        lines.append(f'reason = "{t.reason}"')
        lines.append(f"enabled = {str(t.enabled).lower()}")
        lines.append(f"watch_releases = {str(t.watch_releases).lower()}")
        lines.append(f"watch_commits = {str(t.watch_commits).lower()}")
        lines.append(f'branches = {_format_list(t.branches)}')
        if t.include_paths:
            lines.append(f'include_paths = {_format_list(t.include_paths)}')
        if t.exclude_paths:
            lines.append(f'exclude_paths = {_format_list(t.exclude_paths)}')
        if t.relevance_tags:
            lines.append(f'relevance_tags = {_format_list(t.relevance_tags)}')
        if t.added_at:
            lines.append(f'added_at = "{t.added_at}"')
        if t.notes:
            lines.append(f'notes = "{t.notes}"')
        lines.append("")

    REGISTRY_FILE.parent.mkdir(parents=True, exist_ok=True)
    REGISTRY_FILE.write_text("\n".join(lines))


def _format_list(items: list[str]) -> str:
    """Format a list for TOML output."""
    if len(items) <= 3:
        return "[" + ", ".join(f'"{i}"' for i in items) + "]"
    inner = ",\n    ".join(f'"{i}"' for i in items)
    return f"[\n    {inner},\n]"


def load_targets() -> dict[str, WatchTarget]:
    """Load targets from TOML registry."""
    if not REGISTRY_FILE.exists():
        return {}

    with open(REGISTRY_FILE, "rb") as f:
        data = tomllib.load(f)

    targets = {}
    for key, cfg in data.get("targets", {}).items():
        targets[key] = WatchTarget(
            owner=cfg["owner"],
            repo=cfg["repo"],
            reason=cfg.get("reason", ""),
            watch_releases=cfg.get("watch_releases", True),
            watch_commits=cfg.get("watch_commits", True),
            branches=cfg.get("branches", ["main", "master"]),
            include_paths=cfg.get("include_paths", []),
            exclude_paths=cfg.get("exclude_paths", [
                "docs/", ".github/", "README.md", "CHANGELOG.md", "LICENSE", ".gitignore"
            ]),
            relevance_tags=cfg.get("relevance_tags", []),
            added_at=cfg.get("added_at", ""),
            enabled=cfg.get("enabled", True),
            notes=cfg.get("notes", ""),
        )
    return targets


def get_active_targets() -> list[WatchTarget]:
    """Get only enabled targets."""
    targets = load_targets()
    return [t for t in targets.values() if t.enabled]


def add_target(
    owner: str,
    repo: str,
    reason: str = "",
    watch_commits: bool = True,
    watch_releases: bool = True,
    include_paths: list[str] | None = None,
    relevance_tags: list[str] | None = None,
    notes: str = "",
) -> WatchTarget:
    """Add a new watch target."""
    targets = load_targets()
    t = WatchTarget(
        owner=owner,
        repo=repo,
        reason=reason,
        watch_commits=watch_commits,
        watch_releases=watch_releases,
        include_paths=include_paths or [],
        relevance_tags=relevance_tags or [],
        added_at=datetime.now(timezone.utc).isoformat(),
        notes=notes,
    )

    key = t.toml_key
    if key in targets:
        raise ValueError(f"Target already exists: {t.full_name}")

    targets[key] = t
    _write_toml(targets)
    return t


def remove_target(owner: str, repo: str) -> bool:
    """Remove a watch target."""
    targets = load_targets()
    key = f"{owner}--{repo}"
    if key not in targets:
        return False
    del targets[key]
    _write_toml(targets)
    return True


def toggle_target(owner: str, repo: str, enabled: bool) -> bool:
    """Enable or disable a watch target."""
    targets = load_targets()
    key = f"{owner}--{repo}"
    if key not in targets:
        return False
    targets[key].enabled = enabled
    _write_toml(targets)
    return True


def init_defaults() -> int:
    """Initialize registry with default targets. Returns count added."""
    from .config import TARGETS as DEFAULT_TARGETS

    targets = load_targets()
    added = 0

    for dt in DEFAULT_TARGETS:
        key = f"{dt.owner}--{dt.repo}"
        if key not in targets:
            targets[key] = WatchTarget(
                owner=dt.owner,
                repo=dt.repo,
                reason=dt.reason,
                watch_releases=dt.watch_releases,
                watch_commits=dt.watch_commits,
                branches=list(dt.branches),
                include_paths=list(dt.include_paths),
                exclude_paths=list(dt.exclude_paths),
                relevance_tags=list(dt.relevance_tags),
                added_at=datetime.now(timezone.utc).isoformat(),
            )
            added += 1

    _write_toml(targets)
    return added
