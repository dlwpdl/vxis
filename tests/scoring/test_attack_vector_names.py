"""Tests for AttackVector name_en / name_ko field integrity.

Fix 4: 8 AttackVector entries had name_en like "English|||한국어", which caused
the report layer to render Korean + separator in the English field.
These tests assert that every AttackVector has a clean English-only name_en
and that Korean text (if present) lives in name_ko.
"""

from __future__ import annotations

import unicodedata

from vxis.scoring.vectors import WEB_VECTORS, GAME_VECTORS
from vxis.scoring.vectors import _ALL_VECTORS

ALL_VECTORS = tuple(_ALL_VECTORS.values())


def _contains_hangul(text: str) -> bool:
    """Return True if text contains any Hangul character."""
    return any(
        unicodedata.name(ch, "").startswith("HANGUL") for ch in text
    )


def _contains_separator(text: str) -> bool:
    return "|||" in text


class TestAttackVectorNameIntegrity:
    """Every AttackVector must have clean English-only name_en."""

    def test_no_name_en_contains_separator(self) -> None:
        bad = [v.id for v in ALL_VECTORS if _contains_separator(v.name_en)]
        assert not bad, (
            f"AttackVectors with '|||' in name_en: {bad!r}. "
            "Korean belongs in name_ko."
        )

    def test_no_name_en_contains_hangul(self) -> None:
        bad = [v.id for v in ALL_VECTORS if _contains_hangul(v.name_en)]
        assert not bad, (
            f"AttackVectors with Hangul in name_en: {bad!r}. "
            "Korean belongs in name_ko."
        )

    def test_all_vectors_have_name_ko(self) -> None:
        """Every vector must have a non-empty name_ko field."""
        missing = [v.id for v in ALL_VECTORS if not v.name_ko.strip()]
        assert not missing, (
            f"AttackVectors with empty name_ko: {missing!r}"
        )

    def test_specific_formerly_broken_vectors_are_clean(self) -> None:
        """The 8 originally broken vectors must now have clean English name_en."""
        broken_ids = {
            "WEB-INJECT-018",
            "WEB-INJECT-019",
            "WEB-INJECT-020",
            "WEB-INFRA-006",
            "WEB-INJECT-021",
            "WEB-AUTH-010",
            "WEB-SUPPLY-001",
            "WEB-SUPPLY-002",
        }
        vec_by_id = {v.id: v for v in ALL_VECTORS}
        for vid in broken_ids:
            v = vec_by_id.get(vid)
            assert v is not None, f"Missing vector {vid!r}"
            assert not _contains_separator(v.name_en), (
                f"{vid} name_en still contains '|||': {v.name_en!r}"
            )
            assert not _contains_hangul(v.name_en), (
                f"{vid} name_en still contains Hangul: {v.name_en!r}"
            )
            assert v.name_ko.strip(), f"{vid} name_ko is empty"
