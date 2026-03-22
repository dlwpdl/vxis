"""
Upstream Watch — Selective adoption workflow.

Manages the propose → review → approve → track lifecycle for
upstream-inspired changes. Generates proposals, tracks decisions,
and maintains an adoption log.
"""

from __future__ import annotations

import json
import tomllib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from .analyzer import ActionItem, AnalysisResult
from .overlap import OverlapResult


PROPOSALS_DIR = Path("tools/upstream_watch/proposals")
DECISIONS_FILE = Path("tools/upstream_watch/decisions.json")


class DecisionStatus(str, Enum):
    PROPOSED = "proposed"      # AI suggested, awaiting human review
    APPROVED = "approved"      # Human approved for implementation
    REJECTED = "rejected"      # Human rejected (with reason)
    DEFERRED = "deferred"      # Postponed for later
    IMPLEMENTED = "implemented"  # Code has been written


@dataclass
class Proposal:
    """A proposed change derived from upstream analysis."""

    id: str  # e.g., "2026-03-22-strix-llm-dedup"
    source_repo: str
    title: str
    category: str
    priority: str
    description: str
    source_ref: str
    vxis_files: list[str]
    overlap_verdict: str  # from OverlapResult
    overlap_score: float
    overlap_details: str
    status: str = DecisionStatus.PROPOSED.value
    decision_reason: str = ""
    decided_at: str = ""
    proposed_at: str = ""
    implemented_at: str = ""


@dataclass
class ProposalSet:
    """A batch of proposals from a single analysis run."""

    date: str
    proposals: list[Proposal]
    summary: str = ""


def _generate_id(repo: str, title: str, date: str) -> str:
    """Generate a unique proposal ID."""
    repo_short = repo.split("/")[-1][:10]
    title_slug = (
        title.lower()
        .replace(" ", "-")[:30]
        .strip("-")
    )
    return f"{date}-{repo_short}-{title_slug}"


def create_proposals(
    results: list[AnalysisResult],
    overlaps: list[OverlapResult],
) -> ProposalSet:
    """Create a proposal set from analysis results + overlap checks."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%Y-%m-%d")
    proposals = []

    # Build overlap lookup by item title
    overlap_map = {r.item.title: r for r in overlaps}

    for result in results:
        if result.relevance_score < 0.3:
            continue

        for item in result.actionable_items:
            overlap = overlap_map.get(item.title)

            # Skip items that clearly already exist
            if overlap and overlap.verdict == "already_exists" and overlap.overlap_score > 0.8:
                continue

            proposal = Proposal(
                id=_generate_id(result.repo, item.title, date_str),
                source_repo=result.repo,
                title=item.title,
                category=item.category,
                priority=item.priority,
                description=item.description,
                source_ref=item.source_ref,
                vxis_files=item.vxis_files,
                overlap_verdict=overlap.verdict if overlap else "unknown",
                overlap_score=overlap.overlap_score if overlap else 0.0,
                overlap_details=overlap.recommendation if overlap else "",
                proposed_at=now.isoformat(),
            )
            proposals.append(proposal)

    return ProposalSet(
        date=date_str,
        proposals=proposals,
        summary=f"{len(proposals)} proposals from {len(results)} repos",
    )


def save_proposals(proposal_set: ProposalSet) -> Path:
    """Save proposals as a reviewable markdown file."""
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    filepath = PROPOSALS_DIR / f"{proposal_set.date}.md"

    lines = [
        f"# Upstream Watch Proposals — {proposal_set.date}",
        f"_{proposal_set.summary}_",
        "",
        "Review each proposal and mark your decision.",
        "Edit the `Status` field: `approved` / `rejected` / `deferred`",
        "Add your reason in `Decision reason`.",
        "",
        "---",
        "",
    ]

    for i, p in enumerate(proposal_set.proposals, 1):
        priority_marker = {"high": "!!!", "medium": "!!", "low": "!"}.get(
            p.priority, ""
        )
        lines.extend([
            f"## [{i}] {p.title} {priority_marker}",
            "",
            f"- **ID:** `{p.id}`",
            f"- **Source:** {p.source_repo} ([link]({p.source_ref}))",
            f"- **Category:** {p.category}",
            f"- **Priority:** {p.priority}",
            f"- **Overlap:** {p.overlap_verdict} ({p.overlap_score:.0%})",
            "",
            f"### Description",
            p.description,
            "",
            f"### Overlap Analysis",
            p.overlap_details or "No overlap detected.",
            "",
            f"### Affected VXIS Files",
            ", ".join(f"`{f}`" for f in p.vxis_files) if p.vxis_files else "TBD",
            "",
            f"### Decision",
            f"- **Status:** `{p.status}`",
            f"- **Decision reason:** ",
            "",
            "---",
            "",
        ])

    filepath.write_text("\n".join(lines))
    return filepath


def save_proposals_json(proposal_set: ProposalSet) -> Path:
    """Save proposals as machine-readable JSON for programmatic processing."""
    PROPOSALS_DIR.mkdir(parents=True, exist_ok=True)
    filepath = PROPOSALS_DIR / f"{proposal_set.date}.json"

    data = {
        "date": proposal_set.date,
        "summary": proposal_set.summary,
        "proposals": [asdict(p) for p in proposal_set.proposals],
    }
    filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False))
    return filepath


def load_decisions() -> dict[str, Proposal]:
    """Load all past decisions."""
    if not DECISIONS_FILE.exists():
        return {}
    data = json.loads(DECISIONS_FILE.read_text())
    return {
        pid: Proposal(**pdata)
        for pid, pdata in data.items()
    }


def record_decision(
    proposal_id: str,
    status: DecisionStatus,
    reason: str = "",
) -> None:
    """Record a human decision on a proposal."""
    decisions = load_decisions()
    now = datetime.now(timezone.utc).isoformat()

    # Find proposal in recent proposal files
    proposal = None
    for json_file in sorted(PROPOSALS_DIR.glob("*.json"), reverse=True):
        data = json.loads(json_file.read_text())
        for p in data.get("proposals", []):
            if p["id"] == proposal_id:
                proposal = Proposal(**p)
                break
        if proposal:
            break

    if not proposal:
        # Check existing decisions
        if proposal_id in decisions:
            proposal = decisions[proposal_id]
        else:
            raise ValueError(f"Proposal not found: {proposal_id}")

    proposal.status = status.value
    proposal.decision_reason = reason
    proposal.decided_at = now
    if status == DecisionStatus.IMPLEMENTED:
        proposal.implemented_at = now

    decisions[proposal_id] = proposal

    DECISIONS_FILE.write_text(
        json.dumps(
            {pid: asdict(p) for pid, p in decisions.items()},
            indent=2,
            ensure_ascii=False,
        )
    )


def get_approved_proposals() -> list[Proposal]:
    """Get all approved (but not yet implemented) proposals."""
    decisions = load_decisions()
    return [
        p for p in decisions.values()
        if p.status == DecisionStatus.APPROVED.value
    ]


def get_adoption_stats() -> dict:
    """Get statistics on proposal adoption."""
    decisions = load_decisions()
    stats = {
        "total": len(decisions),
        "approved": sum(1 for p in decisions.values() if p.status == "approved"),
        "rejected": sum(1 for p in decisions.values() if p.status == "rejected"),
        "deferred": sum(1 for p in decisions.values() if p.status == "deferred"),
        "implemented": sum(1 for p in decisions.values() if p.status == "implemented"),
        "pending": sum(1 for p in decisions.values() if p.status == "proposed"),
    }
    stats["adoption_rate"] = (
        stats["implemented"] / max(stats["total"], 1)
    )
    return stats


def format_pending_review() -> str:
    """Format pending proposals for quick terminal review."""
    lines = ["# Pending Proposals", ""]

    for json_file in sorted(PROPOSALS_DIR.glob("*.json"), reverse=True)[:3]:
        data = json.loads(json_file.read_text())
        for p in data.get("proposals", []):
            if p.get("status") == "proposed":
                priority = p.get("priority", "?")
                lines.append(
                    f"  [{priority.upper():>6}] {p['id']}"
                )
                lines.append(f"          {p['title']}")
                lines.append(f"          from {p['source_repo']}")
                lines.append(f"          overlap: {p['overlap_verdict']}")
                lines.append("")

    if len(lines) == 2:
        lines.append("  No pending proposals.")

    return "\n".join(lines)
