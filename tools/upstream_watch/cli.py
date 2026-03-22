"""
Upstream Watch — CLI interface.

Provides commands for managing watched repos, reviewing proposals,
and making adoption decisions.

Usage:
    # Target management
    python -m tools.upstream_watch.cli target list
    python -m tools.upstream_watch.cli target add usestrix/strix --reason "AI agent patterns"
    python -m tools.upstream_watch.cli target remove usestrix/strix
    python -m tools.upstream_watch.cli target enable usestrix/strix
    python -m tools.upstream_watch.cli target disable usestrix/strix
    python -m tools.upstream_watch.cli target init  # Load default targets

    # Review & decide
    python -m tools.upstream_watch.cli review         # Show pending proposals
    python -m tools.upstream_watch.cli decide <id> approved "Good idea"
    python -m tools.upstream_watch.cli decide <id> rejected "Already covered"
    python -m tools.upstream_watch.cli decide <id> deferred "Phase 2"

    # Status
    python -m tools.upstream_watch.cli stats           # Adoption statistics
    python -m tools.upstream_watch.cli approved         # List approved items
"""

from __future__ import annotations

import argparse
import sys

from .adoption import (
    DecisionStatus,
    format_pending_review,
    get_adoption_stats,
    get_approved_proposals,
    record_decision,
)
from .registry import (
    add_target,
    get_active_targets,
    init_defaults,
    load_targets,
    remove_target,
    toggle_target,
)


def cmd_target_list(args: argparse.Namespace) -> int:
    targets = load_targets()
    if not targets:
        print("No watched targets. Run: cli target init")
        return 0

    print(f"{'Status':<10} {'Repository':<35} {'Reason'}")
    print("-" * 90)
    for key, t in sorted(targets.items()):
        status = "ACTIVE" if t.enabled else "PAUSED"
        print(f"{status:<10} {t.full_name:<35} {t.reason[:45]}")
        if t.relevance_tags:
            print(f"{'':>10} tags: {', '.join(t.relevance_tags[:5])}")
    print(f"\nTotal: {len(targets)} targets ({sum(1 for t in targets.values() if t.enabled)} active)")
    return 0


def cmd_target_add(args: argparse.Namespace) -> int:
    parts = args.repo.split("/")
    if len(parts) != 2:
        print(f"ERROR: Invalid format. Use owner/repo (e.g., usestrix/strix)")
        return 1

    owner, repo = parts
    tags = args.tags.split(",") if args.tags else []
    paths = args.include_paths.split(",") if args.include_paths else []

    try:
        t = add_target(
            owner=owner,
            repo=repo,
            reason=args.reason or "",
            include_paths=paths,
            relevance_tags=tags,
            notes=args.notes or "",
        )
        print(f"Added: {t.full_name}")
        return 0
    except ValueError as e:
        print(f"ERROR: {e}")
        return 1


def cmd_target_remove(args: argparse.Namespace) -> int:
    parts = args.repo.split("/")
    if len(parts) != 2:
        print(f"ERROR: Invalid format. Use owner/repo")
        return 1

    if remove_target(parts[0], parts[1]):
        print(f"Removed: {args.repo}")
        return 0
    else:
        print(f"Not found: {args.repo}")
        return 1


def cmd_target_toggle(args: argparse.Namespace, enabled: bool) -> int:
    parts = args.repo.split("/")
    if len(parts) != 2:
        print(f"ERROR: Invalid format. Use owner/repo")
        return 1

    action = "Enabled" if enabled else "Disabled"
    if toggle_target(parts[0], parts[1], enabled):
        print(f"{action}: {args.repo}")
        return 0
    else:
        print(f"Not found: {args.repo}")
        return 1


def cmd_target_init(args: argparse.Namespace) -> int:
    count = init_defaults()
    print(f"Initialized {count} default targets.")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    print(format_pending_review())
    return 0


def cmd_decide(args: argparse.Namespace) -> int:
    try:
        status = DecisionStatus(args.status)
    except ValueError:
        print(f"ERROR: Invalid status. Use: approved, rejected, deferred, implemented")
        return 1

    try:
        record_decision(args.proposal_id, status, args.reason or "")
        print(f"Recorded: {args.proposal_id} -> {status.value}")
        if args.reason:
            print(f"Reason: {args.reason}")
        return 0
    except ValueError as e:
        print(f"ERROR: {e}")
        return 1


def cmd_stats(args: argparse.Namespace) -> int:
    stats = get_adoption_stats()
    print("Upstream Watch — Adoption Statistics")
    print("=" * 40)
    print(f"  Total proposals:   {stats['total']}")
    print(f"  Pending review:    {stats['pending']}")
    print(f"  Approved:          {stats['approved']}")
    print(f"  Rejected:          {stats['rejected']}")
    print(f"  Deferred:          {stats['deferred']}")
    print(f"  Implemented:       {stats['implemented']}")
    print(f"  Adoption rate:     {stats['adoption_rate']:.0%}")
    return 0


def cmd_approved(args: argparse.Namespace) -> int:
    approved = get_approved_proposals()
    if not approved:
        print("No approved proposals awaiting implementation.")
        return 0

    print("Approved Proposals (awaiting implementation):")
    print("-" * 60)
    for p in approved:
        print(f"  [{p.priority.upper():>6}] {p.id}")
        print(f"          {p.title}")
        print(f"          from {p.source_repo}")
        if p.vxis_files:
            print(f"          files: {', '.join(p.vxis_files[:3])}")
        print()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VXIS Upstream Watch CLI"
    )
    subparsers = parser.add_subparsers(dest="command")

    # ── target commands ──
    target_parser = subparsers.add_parser("target", help="Manage watched repos")
    target_sub = target_parser.add_subparsers(dest="target_action")

    target_sub.add_parser("list", help="List all watched targets")
    target_sub.add_parser("init", help="Initialize with default targets")

    add_p = target_sub.add_parser("add", help="Add a watch target")
    add_p.add_argument("repo", help="owner/repo (e.g., usestrix/strix)")
    add_p.add_argument("--reason", help="Why watch this repo")
    add_p.add_argument("--tags", help="Comma-separated relevance tags")
    add_p.add_argument("--include-paths", help="Comma-separated source paths to watch")
    add_p.add_argument("--notes", help="Additional notes")

    rm_p = target_sub.add_parser("remove", help="Remove a watch target")
    rm_p.add_argument("repo", help="owner/repo")

    en_p = target_sub.add_parser("enable", help="Enable a target")
    en_p.add_argument("repo", help="owner/repo")

    dis_p = target_sub.add_parser("disable", help="Disable a target")
    dis_p.add_argument("repo", help="owner/repo")

    # ── review commands ──
    subparsers.add_parser("review", help="Show pending proposals")
    subparsers.add_parser("stats", help="Show adoption statistics")
    subparsers.add_parser("approved", help="List approved proposals")

    decide_p = subparsers.add_parser("decide", help="Record decision on a proposal")
    decide_p.add_argument("proposal_id", help="Proposal ID")
    decide_p.add_argument(
        "status",
        choices=["approved", "rejected", "deferred", "implemented"],
    )
    decide_p.add_argument("reason", nargs="?", default="", help="Decision reason")

    args = parser.parse_args()

    if args.command == "target":
        if args.target_action == "list":
            return cmd_target_list(args)
        elif args.target_action == "add":
            return cmd_target_add(args)
        elif args.target_action == "remove":
            return cmd_target_remove(args)
        elif args.target_action == "enable":
            return cmd_target_toggle(args, enabled=True)
        elif args.target_action == "disable":
            return cmd_target_toggle(args, enabled=False)
        elif args.target_action == "init":
            return cmd_target_init(args)
        else:
            target_parser.print_help()
            return 0
    elif args.command == "review":
        return cmd_review(args)
    elif args.command == "decide":
        return cmd_decide(args)
    elif args.command == "stats":
        return cmd_stats(args)
    elif args.command == "approved":
        return cmd_approved(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
