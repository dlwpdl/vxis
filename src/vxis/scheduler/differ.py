"""Finding diff and regression detection|||발견 항목 diff 및 회귀 탐지."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable


def _key(finding: Any) -> tuple[str, str]:
    """Stable identity key for a finding by type + affected component."""
    ftype = (
        getattr(finding, "finding_type", None)
        or (finding.get("finding_type") if isinstance(finding, dict) else None)
        or "unknown"
    )
    comp = (
        getattr(finding, "affected_component", None)
        or (finding.get("affected_component") if isinstance(finding, dict) else None)
        or ""
    )
    return (str(ftype), str(comp))


@dataclass
class DiffResult:
    """Diff between two scan finding sets|||두 스캔 결과 간 diff."""

    new_findings: list = field(default_factory=list)
    resolved: list = field(default_factory=list)
    unchanged: list = field(default_factory=list)
    regressed: list = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"New: {len(self.new_findings)} | "
            f"Resolved: {len(self.resolved)} | "
            f"Unchanged: {len(self.unchanged)} | "
            f"Regressed: {len(self.regressed)}"
            "|||"
            f"신규: {len(self.new_findings)} | "
            f"해결: {len(self.resolved)} | "
            f"변동없음: {len(self.unchanged)} | "
            f"회귀: {len(self.regressed)}"
        )

    def has_regression(self) -> bool:
        return bool(self.regressed) or bool(self.new_findings)


def compare_scans(
    prev_findings: Iterable[Any],
    new_findings: Iterable[Any],
    historical_resolved: Iterable[Any] | None = None,
) -> DiffResult:
    """Compare previous and new scan findings.

    |||이전 스캔과 새 스캔의 발견을 비교.

    A finding is considered "regressed" if it appears in `new_findings`
    AND was previously resolved (present in `historical_resolved` set
    of keys that were resolved in earlier diffs).

    |||발견이 새 스캔에 다시 등장하고, 이전에 해결된 적 있으면 "회귀"로 분류.
    """
    prev_list = list(prev_findings)
    new_list = list(new_findings)

    prev_map = {_key(f): f for f in prev_list}
    new_map = {_key(f): f for f in new_list}

    new_keys = set(new_map.keys())
    prev_keys = set(prev_map.keys())

    only_new = new_keys - prev_keys
    only_prev = prev_keys - new_keys
    common = new_keys & prev_keys

    resolved_history: set[tuple[str, str]] = set()
    if historical_resolved:
        for f in historical_resolved:
            resolved_history.add(_key(f))

    regressed_keys = only_new & resolved_history
    fresh_new_keys = only_new - regressed_keys

    return DiffResult(
        new_findings=[new_map[k] for k in fresh_new_keys],
        resolved=[prev_map[k] for k in only_prev],
        unchanged=[new_map[k] for k in common],
        regressed=[new_map[k] for k in regressed_keys],
    )
