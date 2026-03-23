"""Cross-repo trend detection and proposal dedup."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

from .analyzer import ActionItem, AnalysisResult


class TrendDetector:
    """
    Identifies industry-wide trends by looking for common keywords/categories
    surfacing across multiple upstream repositories in a single analysis run.
    """

    # Minimum number of repos that must share a theme to call it a trend
    _MIN_REPO_COUNT = 2

    def detect_cross_repo_trends(
        self, results: list[AnalysisResult]
    ) -> list[str]:
        """
        Scan all actionable items across repos and surface recurring
        category+keyword combinations that appear in 2+ distinct repos.

        Returns a list of human-readable trend description strings.
        """
        # Map (category, keyword) → set of repos that produced it
        signal: dict[tuple[str, str], set[str]] = defaultdict(set)

        for result in results:
            for item in result.actionable_items:
                keywords = self._extract_keywords(item.title + " " + item.description)
                for kw in keywords:
                    signal[(item.category, kw)].add(result.repo)

        trends: list[str] = []
        # Collect unique trends — avoid duplicates by tracking added combos
        seen: set[str] = set()

        for (category, keyword), repos in sorted(
            signal.items(), key=lambda x: -len(x[1])
        ):
            if len(repos) < self._MIN_REPO_COUNT:
                continue

            key = f"{category}:{keyword}"
            if key in seen:
                continue
            seen.add(key)

            repo_list = ", ".join(sorted(repos))
            trends.append(
                f"Industry trend — **{category}** / `{keyword}`: "
                f"seen in {len(repos)} repos ({repo_list})"
            )

        return trends

    @staticmethod
    def _extract_keywords(text: str) -> list[str]:
        """Extract normalised keywords from free text (2+ char alpha tokens)."""
        words = re.findall(r"[a-z][a-z0-9_-]+", text.lower())
        # Filter very common stop words
        stop = {
            "the", "and", "for", "with", "this", "that", "from", "into",
            "use", "add", "new", "via", "get", "set", "all", "can",
        }
        return [w for w in words if len(w) >= 3 and w not in stop]


class ProposalDeduplicator:
    """
    Prevents redundant proposals by checking new ActionItems against the
    historical decisions log (decisions.json).
    """

    def __init__(self, decisions_path: Path) -> None:
        self._decisions: list[dict] = []
        if decisions_path.exists():
            try:
                raw = json.loads(decisions_path.read_text())
                # decisions.json is a dict keyed by proposal id
                if isinstance(raw, dict):
                    self._decisions = list(raw.values())
            except (json.JSONDecodeError, OSError):
                pass

    def is_already_decided(
        self, item: ActionItem
    ) -> tuple[bool, str]:
        """
        Check whether a similar item was already approved, rejected, or deferred.

        Similarity criteria:
          - Same source_repo  AND  title (lowercase) is a substring of the
            existing decision title or vice-versa
          - OR titles share ≥3 significant keywords

        Returns (True, human-readable explanation) or (False, "").
        """
        item_title_lower = item.title.lower()
        item_words = set(re.findall(r"[a-z][a-z0-9_-]+", item_title_lower))

        for decision in self._decisions:
            status = decision.get("status", "proposed")
            if status == "proposed":
                # Not yet decided — don't treat as decided
                continue

            existing_title = (decision.get("title") or "").lower()
            existing_repo = decision.get("source_repo", "")
            decided_at = decision.get("decided_at", "")
            reason = (decision.get("decision_reason") or "").strip()

            # Match 1: same repo + title substring
            same_repo = existing_repo == item.source_repo if hasattr(item, "source_repo") else False
            title_match = (
                item_title_lower in existing_title
                or existing_title in item_title_lower
            )

            # Match 2: keyword overlap (≥3 shared significant words)
            existing_words = set(re.findall(r"[a-z][a-z0-9_-]+", existing_title))
            shared = item_words & existing_words
            keyword_match = len(shared) >= 3

            if (same_repo and title_match) or keyword_match:
                summary = f"{status} on {decided_at[:10] if decided_at else 'unknown date'}"
                if reason:
                    summary += f": {reason}"
                return True, summary

        return False, ""

    def filter_decided(self, items: list[ActionItem]) -> list[ActionItem]:
        """
        Return only those items that have NOT already been decided.
        Prints a brief notice for each filtered item.
        """
        undecided: list[ActionItem] = []
        for item in items:
            already, explanation = self.is_already_decided(item)
            if already:
                print(
                    f"    [DEDUP] Skipping '{item.title}' — "
                    f"already decided ({explanation})"
                )
            else:
                undecided.append(item)
        return undecided
