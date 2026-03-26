"""
Upstream Watch — AI-powered diff analyzer.

Uses a configurable LLM provider (Kimi, GLM, DeepSeek, Claude, etc.) to
evaluate whether upstream changes are relevant to VXIS.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

import logging
import re

from .config import VXIS_CONTEXT, WatchTarget
from .fetcher import CommitCluster, CommitInfo, ReleaseInfo, RepoChanges
from .llm import chat as llm_chat, is_available as llm_is_available

logger = logging.getLogger(__name__)


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
You are an expert security engineer reviewing upstream open-source project \
changes for relevance to the VXIS security automation platform.

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
- ALL text fields (summary, title, description) MUST be written in Korean (한국어).

Output valid JSON matching this schema:
{
  "relevance_score": 0.0-1.0,
  "summary": "2~3문장 한국어 요약",
  "actionable_items": [
    {
      "title": "짧은 한국어 제목",
      "category": "architecture|plugin|report|pipeline|tool-integration|performance|security",
      "priority": "high|medium|low",
      "description": "VXIS에 적용할 방법 (컨셉만, 코드 복사 금지) — 한국어로 작성",
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

        if changes.clusters:
            # Clustered view — surfaces logical units of work rather than
            # individual commits, reducing noise in the LLM prompt.
            parts.append(
                f"(Grouped into {len(changes.clusters)} cluster(s) by author/time/files)"
            )
            for idx, cluster in enumerate(changes.clusters[:15], start=1):
                commit_count = len(cluster.commits)
                shas = ", ".join(f"`{c.sha}`" for c in cluster.commits[:5])
                if commit_count > 5:
                    shas += f" (+{commit_count - 5} more)"
                files_preview = ", ".join(cluster.files_changed[:8])
                if len(cluster.files_changed) > 8:
                    files_preview += f" (+{len(cluster.files_changed) - 8} more files)"
                parts.extend([
                    f"**Cluster {idx}** — {commit_count} commit(s) over {cluster.time_span}",
                    f"  Commits: {shas}",
                    f"  Files: {files_preview}" if files_preview else "  Files: (none recorded)",
                    f"  Messages:",
                ])
                for line in cluster.summary.splitlines()[:5]:
                    parts.append(f"    - {line}")
                if cluster.summary.count("\n") >= 5:
                    extra = cluster.summary.count("\n") - 4
                    parts.append(f"    - ... and {extra} more messages")
                parts.append("")
            if len(changes.clusters) > 15:
                parts.append(f"  ... and {len(changes.clusters) - 15} more clusters")
        else:
            # Fallback: flat commit list (no clustering data available)
            for c in changes.commits[:20]:
                files_str = ", ".join(c.files_changed[:10]) if c.files_changed else ""
                parts.append(
                    f"- `{c.sha}` {c.message} [{c.author}] {files_str}"
                )
            if len(changes.commits) > 20:
                parts.append(f"  ... and {len(changes.commits) - 20} more commits")

    return "\n".join(parts)


# ── LLM 호출 전 규칙 기반 필터 (비용 90% 절감) ──────────────────

# LLM 부를 필요 없는 노이즈 커밋 패턴
_NOISE_COMMIT_PATTERNS = re.compile(
    r"^("
    r"fix\s*(?:typo|spelling|whitespace|indent|format)|"
    r"update\s*(?:readme|changelog|license|contributing)|"
    r"bump\s*(?:version|deps?|depend)|"
    r"chore\s*[\(:]|"
    r"docs?\s*[\(:]|"
    r"ci\s*[\(:]|"
    r"style\s*[\(:]|"
    r"merge\s+(?:branch|pull|pr)|"
    r"release\s+v?\d|"
    r"update\s+\.\w+|"  # .gitignore, .eslintrc 등
    r"renovate|dependabot|snyk"
    r")",
    re.IGNORECASE,
)

# LLM 부를 필요 없는 파일 확장자 (코드가 아닌 것)
_NOISE_FILE_EXTENSIONS = {
    ".md", ".txt", ".rst", ".yml", ".yaml", ".toml",
    ".json", ".lock", ".sum", ".mod",
    ".png", ".jpg", ".svg", ".gif", ".ico",
    ".gitignore", ".dockerignore", ".editorconfig",
    ".eslintrc", ".prettierrc", ".flake8",
}


def _is_noise_only(changes: RepoChanges) -> tuple[bool, str]:
    """LLM 없이 노이즈인지 판단. (True, 이유) 반환."""
    # 릴리스가 있으면 항상 LLM 호출 (중요할 수 있음)
    if changes.releases:
        return False, ""

    if not changes.commits:
        return True, "No commits"

    # 모든 커밋 메시지가 노이즈 패턴이면 스킵
    all_noise_messages = all(
        _NOISE_COMMIT_PATTERNS.match(c.message.strip())
        for c in changes.commits
        if c.message.strip()
    )
    if all_noise_messages:
        return True, f"All {len(changes.commits)} commits are noise (typo/docs/ci/bump)"

    # 모든 변경 파일이 비코드 파일이면 스킵
    all_files: list[str] = []
    for c in changes.commits:
        all_files.extend(c.files_changed)

    if all_files:
        all_noise_files = all(
            any(f.endswith(ext) for ext in _NOISE_FILE_EXTENSIONS)
            for f in all_files
        )
        if all_noise_files:
            return True, f"All {len(all_files)} changed files are non-code ({', '.join(set(f.rsplit('.', 1)[-1] for f in all_files[:5]))})"

    # 커밋 1개 + 파일 1개 + 메시지가 짧으면 스킵
    if len(changes.commits) == 1 and len(all_files) <= 1:
        msg = changes.commits[0].message.strip()
        if len(msg) < 20 and not any(kw in msg.lower() for kw in ("feat", "fix", "security", "vuln", "exploit", "attack")):
            return True, f"Single trivial commit: '{msg}'"

    return False, ""


def analyze_changes(changes: RepoChanges) -> AnalysisResult:
    """Use the configured LLM to analyze upstream changes for VXIS relevance."""
    repo_name = f"{changes.target.owner}/{changes.target.repo}"

    if not changes.has_changes:
        return AnalysisResult(
            repo=repo_name, relevance_score=0.0,
            summary="No new changes detected.",
        )

    # ── 규칙 기반 노이즈 필터 (LLM 호출 전) ──
    is_noise, reason = _is_noise_only(changes)
    if is_noise:
        logger.info("[SKIP-LLM] %s — %s", repo_name, reason)
        return AnalysisResult(
            repo=repo_name, relevance_score=0.0,
            summary=f"Skipped (noise filter): {reason}",
        )

    if not llm_is_available():
        return AnalysisResult(
            repo=repo_name, relevance_score=0.0,
            summary="No LLM API key configured — skipping AI analysis.",
        )

    user_prompt = f"""\
{VXIS_CONTEXT}

---

Here are the latest changes from an upstream repository:

{_format_changes(changes)}

---

Analyze these changes and return JSON with relevance score and actionable items for VXIS.\
"""

    prompt_len = len(user_prompt)
    logger.info("Analyzing %s (%d chars prompt)", repo_name, prompt_len)

    response = llm_chat(
        system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt,
        max_tokens=2000,
    )

    if response is None:
        logger.error("All LLM providers failed for %s (prompt %d chars)", repo_name, prompt_len)
        return AnalysisResult(
            repo=repo_name, relevance_score=0.0,
            summary=f"LLM API call failed for {repo_name} — all providers exhausted (prompt {prompt_len} chars). Check TOGETHER_API_KEY or ANTHROPIC_API_KEY.",
        )

    raw_text = response.text

    try:
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
            repo=repo_name,
            relevance_score=data.get("relevance_score", 0.0),
            summary=data.get("summary", ""),
            actionable_items=items,
            raw_response=raw_text,
        )

    except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
        return AnalysisResult(
            repo=repo_name, relevance_score=0.0,
            summary=f"AI analysis parse error: {e}",
            raw_response=raw_text,
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
