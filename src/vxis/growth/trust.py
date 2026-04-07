"""Source trust scoring|||소스 신뢰도 점수 관리."""

from __future__ import annotations

import json
from pathlib import Path

TRUST_SCORES_DEFAULT: dict[str, float] = {
    # Tier 1: official advisories & research labs
    "nvd": 1.0,
    "cisa_kev": 1.0,
    "mitre": 1.0,
    "google_project_zero": 0.95,
    "trail_of_bits": 0.95,
    "ncc_group": 0.95,
    # Tier 2: major security news
    "krebsonsecurity": 0.9,
    "bleepingcomputer": 0.9,
    "securityaffairs": 0.9,
    "thehackernews": 0.85,
    "darkreading": 0.85,
    "therecord": 0.85,
    "securityweek": 0.85,
    # Tier 3: vendor blogs
    "microsoft_security": 0.9,
    "aws_security": 0.85,
    "fortinet": 0.85,
    "crowdstrike": 0.85,
    # Tier 4: community
    "schneier": 0.8,
    "threatpost": 0.75,
    "github_advisory": 0.85,
    # Tier 5: aggregators
    "reddit_netsec": 0.5,
    "hackernews": 0.5,
    # unknown fallback
    "unknown": 0.3,
}


class TrustRegistry:
    """Persistent trust registry|||영속적 신뢰도 레지스트리."""

    def __init__(self, scores_path: Path | None = None) -> None:
        self.scores_path = scores_path or Path("configs/trust_scores.json")
        self.scores: dict[str, float] = self._load()

    def _load(self) -> dict[str, float]:
        if self.scores_path.exists():
            try:
                return json.loads(self.scores_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                return dict(TRUST_SCORES_DEFAULT)
        return dict(TRUST_SCORES_DEFAULT)

    def get(self, source_name: str) -> float:
        """Return trust score for source|||출처 신뢰도 반환."""
        return self.scores.get(source_name, TRUST_SCORES_DEFAULT["unknown"])

    def set(self, source_name: str, score: float) -> None:
        """Set and persist trust score|||신뢰도 저장."""
        self.scores[source_name] = max(0.0, min(1.0, score))
        self._save()

    def _save(self) -> None:
        self.scores_path.parent.mkdir(parents=True, exist_ok=True)
        self.scores_path.write_text(
            json.dumps(self.scores, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def adjust_by_effectiveness(
        self, source_name: str, was_effective: bool
    ) -> None:
        """Gradually raise/lower score|||유효성에 따라 점수 조정."""
        current = self.get(source_name)
        delta = 0.02 if was_effective else -0.05
        self.set(source_name, current + delta)
