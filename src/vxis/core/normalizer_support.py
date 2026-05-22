"""Support helpers for core finding normalization."""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from typing import Any

from vxis.models.finding import Finding, Severity


_NUCLEI_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "info": Severity.informational,
    "informational": Severity.informational,
    "unknown": Severity.informational,
}

_TESTSSL_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "low": Severity.low,
    "warn": Severity.low,
    "fatal": Severity.critical,
}

_TESTSSL_SKIP_SEVERITIES: set[str] = {"ok", "info", "not tested", "not offered"}

_TRUFFLEHOG_CLOUD_DETECTOR_PATTERNS: list[str] = [
    "aws",
    "gcp",
    "azure",
    "github",
    "gitlab",
    "slack",
    "stripe",
    "twilio",
    "sendgrid",
]


def _make_id() -> str:
    return str(uuid.uuid4())


def _extract_cve_ids(data: dict[str, Any]) -> list[str]:
    """Extract CVE IDs from nuclei info.classification or tags."""
    cve_ids: list[str] = []
    classification = data.get("info", {}).get("classification", {})
    raw_cves: list[str] = classification.get("cve-id", []) or []
    if isinstance(raw_cves, str):
        raw_cves = [raw_cves]
    for cve in raw_cves:
        normalized = cve.upper().strip()
        if re.match(r"CVE-\d{4}-\d+", normalized):
            cve_ids.append(normalized)

    # Also scan tags for CVE patterns
    tags: list[str] = data.get("info", {}).get("tags", []) or []
    if isinstance(tags, str):
        tags = [t.strip() for t in tags.split(",")]
    for tag in tags:
        match = re.search(r"(CVE-\d{4}-\d+)", tag, re.IGNORECASE)
        if match:
            cve_id = match.group(1).upper()
            if cve_id not in cve_ids:
                cve_ids.append(cve_id)

    return cve_ids

# ---------------------------------------------------------------------------
# FindingDeduplicator
# ---------------------------------------------------------------------------


class FindingDeduplicator:
    """Deduplication and grouping utilities for Finding lists."""

    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        """Group by dedup_hash and merge findings with the same hash.

        The first finding encountered for each hash becomes the canonical
        record. All subsequent findings with the same hash are merged into
        it via Finding.merge_with().

        Args:
            findings: Raw list of findings, potentially with duplicates.

        Returns:
            Deduplicated list preserving insertion order of first occurrence.
        """
        seen: dict[str, Finding] = {}

        for finding in findings:
            h = finding.dedup_hash
            if h not in seen:
                seen[h] = finding
            else:
                seen[h].merge_with(finding)

        return list(seen.values())

    def group_related(self, findings: list[Finding]) -> dict[str, list[Finding]]:
        """Group findings by fuzzy_hash for analyst review of near-duplicates.

        Findings that share the same target + finding_type + primary CVE will
        be clustered together even if they differ in port or affected_component.

        Args:
            findings: List of findings to group.

        Returns:
            Dict mapping fuzzy_hash → list of related findings.
        """
        groups: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            groups[finding.fuzzy_hash].append(finding)
        return dict(groups)
