"""
Upstream Watch — AI-powered diff analyzer.

Uses Claude API to evaluate whether upstream changes are relevant
to VXIS, scoring and summarizing actionable insights.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

import anthropic

from .config import VXIS_CONTEXT, WatchTarget
from .fetcher import CommitInfo, ReleaseInfo, RepoChanges


@dataclass
class AnalysisResult:
    """AI analysis of upstream changes for a single repo."""

    repo: str
    relevance_score: float  # 0.0 - 1.0
    summary: str  # 2-3 sentence summary
    actionable_items: list[ActionItem] = field(default_factory=list)
    raw_response: str = ""


@dataclass
class ActionItem:
    """A specific change that could be applied to VXIS."""

    title: str
    category: str  # architecture, plugin, report, pipeline, tool-integration, etc.
    priority: str  # high, medium, low
    description: str  # What to do in VXIS
    source_ref: str  # URL or commit SHA reference
    vxis_files: list[str] = field(default_factory=list)  # Files that would be affected


SYSTEM_PROMPT = """\
You are an expert security engineer and software architect reviewing upstream \
open-source project changes for relevance to the VXIS platform.

Your job:
1. Analyze the provided changes (commits and/or releases) from an upstream repo.
2. Determine if any changes are relevant to VXIS development.
3. Score overall relevance (0.0 = completely irrelevant, 1.0 = critical must-have).
4. For relevant changes, produce specific actionable items.

CRITICAL RULES:
- AGPL/GPL code must NEVER be copied. Describe CONCEPTS and APPROACHES only.
- Focus on architectural patterns, algorithms, and design ideas — not code.
- Be specific about which VXIS files/modules would be affected.
- Ignore: typo fixes, CI config changes, documentation-only changes, dependency bumps \
  (unless they indicate a significant feature).
- Prioritize: new attack techniques, tool integration patterns, architecture improvements, \
  report quality enhancements, performance optimizations.

Output valid JSON matching this schema:
{
  "relevance_score": 0.0-1.0,
  "summary": "2-3 sentence overview",
  "actionable_items": [
    {
      "title": "short title",
      "category": "architecture|plugin|report|pipeline|tool-integration|performance|security",
      "priority": "high|medium|low",
      "description": "What VXIS should do (concept only, no copied code)",
      "source_ref": "URL or commit ref",
      "vxis_files": ["src/vxis/path/to/affected.py"]
    }
  ]
}

If nothing is relevant, return relevance_score: 0.0 with empty actionable_items.\
"""


def _format_changes(changes: RepoChanges) -> str:
    """Format repo changes into a readable prompt section."""
    parts = [
        f"## Repository: {changes.target.owner}/{changes.target.repo}",
        f"Purpose: {changes.target.reason}",
        f"Relevance tags: {', '.join(changes.target.relevance_tags)}",
        "",
    ]

    if changes.releases:
        parts.append("### New Releases")
        for r in changes.releases[:3]:
            parts.extend([
                f"**{r.tag}** — {r.name} ({r.date})",
                f"URL: {r.url}",
                r.body[:2000] if r.body else "(no release notes)",
                "",
            ])

    if changes.commits:
        parts.append(f"### New Commits ({len(changes.commits)} total)")
        if changes.diff_summary:
            parts.extend(["Diff summary:", changes.diff_summary, ""])
        for c in changes.commits[:20]:
            files_str = ", ".join(c.files_changed[:10]) if c.files_changed else ""
            parts.append(
                f"- `{c.sha}` {c.message} [{c.author}] {files_str}"
            )
        if len(changes.commits) > 20:
            parts.append(f"  ... and {len(changes.commits) - 20} more commits")

    return "\n".join(parts)


def analyze_changes(changes: RepoChanges) -> AnalysisResult:
    """Use Claude API to analyze upstream changes for VXIS relevance."""
    if not changes.has_changes:
        return AnalysisResult(
            repo=f"{changes.target.owner}/{changes.target.repo}",
            relevance_score=0.0,
            summary="No new changes detected.",
        )

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        return AnalysisResult(
            repo=f"{changes.target.owner}/{changes.target.repo}",
            relevance_score=0.0,
            summary="ANTHROPIC_API_KEY not set — skipping AI analysis.",
        )

    client = anthropic.Anthropic(api_key=api_key)

    user_prompt = f"""\
{VXIS_CONTEXT}

---

Here are the latest changes from an upstream repository:

{_format_changes(changes)}

---

Analyze these changes and return JSON with relevance score and actionable items for VXIS.\
"""

    try:
        response = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )

        raw_text = response.content[0].text

        # Extract JSON from response (handle markdown code blocks)
        json_str = raw_text
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0]
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0]

        data = json.loads(json_str.strip())

        items = [
            ActionItem(
                title=item.get("title", ""),
                category=item.get("category", ""),
                priority=item.get("priority", "low"),
                description=item.get("description", ""),
                source_ref=item.get("source_ref", ""),
                vxis_files=item.get("vxis_files", []),
            )
            for item in data.get("actionable_items", [])
        ]

        return AnalysisResult(
            repo=f"{changes.target.owner}/{changes.target.repo}",
            relevance_score=data.get("relevance_score", 0.0),
            summary=data.get("summary", ""),
            actionable_items=items,
            raw_response=raw_text,
        )

    except (json.JSONDecodeError, KeyError, IndexError) as e:
        return AnalysisResult(
            repo=f"{changes.target.owner}/{changes.target.repo}",
            relevance_score=0.0,
            summary=f"AI analysis parse error: {e}",
            raw_response=raw_text if "raw_text" in dir() else "",
        )
    except anthropic.APIError as e:
        return AnalysisResult(
            repo=f"{changes.target.owner}/{changes.target.repo}",
            relevance_score=0.0,
            summary=f"Claude API error: {e}",
        )


def analyze_all(changes_list: list[RepoChanges]) -> list[AnalysisResult]:
    """Analyze all repo changes. Only calls AI for repos with actual changes."""
    results = []
    for changes in changes_list:
        if changes.has_changes:
            results.append(analyze_changes(changes))
        else:
            results.append(
                AnalysisResult(
                    repo=f"{changes.target.owner}/{changes.target.repo}",
                    relevance_score=0.0,
                    summary="No changes since last check.",
                )
            )
    return results
