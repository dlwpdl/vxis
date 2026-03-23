"""Vulnerability knowledge base for VXIS security automation platform.

Provides static lookup of remediation guidance, CWE/OWASP mappings, and
reference links for common vulnerability types.  Data is loaded from a
bundled JSON file at import time — no external API calls required.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class RemediationInfo(BaseModel):
    """Structured remediation guidance for a vulnerability type."""

    vuln_type: str = Field(description="Canonical vulnerability type key, e.g. 'sql_injection'")
    title: str = Field(description="Human-readable vulnerability name")
    description: str = Field(description="Brief description of the vulnerability class")
    remediation_steps: list[str] = Field(description="Ordered list of remediation actions")
    references: list[str] = Field(description="URLs to authoritative guidance")
    cwe_id: str = Field(description="Primary CWE identifier, e.g. 'CWE-89'")
    owasp_category: str = Field(
        description="OWASP Top 10 (2021) category, e.g. 'A03:2021 – Injection'"
    )


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------

_DATA_DIR = Path(__file__).resolve().parent / "data"
_DEFAULT_KB_PATH = _DATA_DIR / "vuln_kb.json"


class VulnKB:
    """Static vulnerability knowledge base backed by a local JSON file.

    Usage::

        kb = VulnKB()
        info = kb.get_remediation("sql_injection")
        results = kb.search("injection")
    """

    def __init__(self, path: Path | str | None = None) -> None:
        """Load the knowledge base from *path* (defaults to bundled JSON).

        Args:
            path: Optional filesystem path to a ``vuln_kb.json`` file.
                  When ``None``, the bundled dataset is used.
        """
        self._path = Path(path) if path else _DEFAULT_KB_PATH
        self._entries: dict[str, RemediationInfo] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_remediation(self, vuln_type: str) -> Optional[RemediationInfo]:
        """Look up remediation guidance by canonical vulnerability type key.

        The lookup is case-insensitive and treats hyphens/spaces as
        interchangeable with underscores so that callers don't need to
        know the exact key format.

        Args:
            vuln_type: Vulnerability type string (e.g. ``"sql_injection"``,
                       ``"SQL Injection"``, ``"sql-injection"``).

        Returns:
            ``RemediationInfo`` if found, otherwise ``None``.
        """
        normalised = self._normalise_key(vuln_type)
        return self._entries.get(normalised)

    def search(self, keyword: str) -> list[RemediationInfo]:
        """Search all entries for *keyword* (case-insensitive substring match).

        Matches against ``vuln_type``, ``title``, ``description``,
        ``cwe_id``, and ``owasp_category``.

        Args:
            keyword: Search term.

        Returns:
            List of matching ``RemediationInfo`` objects (may be empty).
        """
        keyword_lower = keyword.lower()
        results: list[RemediationInfo] = []
        for entry in self._entries.values():
            searchable = " ".join([
                entry.vuln_type,
                entry.title,
                entry.description,
                entry.cwe_id,
                entry.owasp_category,
            ]).lower()
            if keyword_lower in searchable:
                results.append(entry)
        return results

    @property
    def all_types(self) -> list[str]:
        """Return a sorted list of all known vulnerability type keys."""
        return sorted(self._entries.keys())

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, vuln_type: str) -> bool:
        return self._normalise_key(vuln_type) in self._entries

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Parse the JSON file and populate ``_entries``."""
        raw_text = self._path.read_text(encoding="utf-8")
        raw_list: list[dict] = json.loads(raw_text)
        for item in raw_list:
            info = RemediationInfo(**item)
            key = self._normalise_key(info.vuln_type)
            self._entries[key] = info

    @staticmethod
    def _normalise_key(value: str) -> str:
        """Normalise a vuln-type string to a canonical lookup key."""
        return value.lower().replace("-", "_").replace(" ", "_")


# ---------------------------------------------------------------------------
# Module-level convenience: singleton instance
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def get_vuln_kb() -> VulnKB:
    """Return a cached singleton ``VulnKB`` instance using the bundled data."""
    return VulnKB()
