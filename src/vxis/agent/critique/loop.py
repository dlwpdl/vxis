"""Deterministic self-evaluation loop primitives.

The v3 plan eventually routes self-critique through a critique-class Brain
decision. This safe primitive deliberately avoids LLM calls and scan-loop
mutation: it evaluates gaps from structured summaries and returns a report a
coordinator can use.
"""

from __future__ import annotations

from collections.abc import Iterable
from statistics import mean
from typing import Any, Literal

from pydantic import BaseModel, Field


DecisionClass = Literal["recon", "triage", "strategy", "exploit", "verify", "critique"]


class ProposedHypothesis(BaseModel):
    claim: str
    decision_class: DecisionClass = "strategy"
    prior: float = Field(default=0.5, ge=0.0, le=1.0)
    rationale: str = ""
    source_gap: str | None = None


class CritiqueReport(BaseModel):
    coverage_pct: float = Field(ge=0.0, le=100.0)
    high_value_surface_coverage: float = Field(ge=0.0, le=100.0)
    untested_high_prior_hypotheses: list[str] = Field(default_factory=list)
    chain_depth_max: int = Field(ge=0)
    chain_depth_mean: float = Field(ge=0.0)
    gaps: list[str] = Field(default_factory=list)
    new_hypotheses_proposed: list[ProposedHypothesis] = Field(default_factory=list)
    finish_allowed: bool
    rationale: str


class SelfCritique:
    def __init__(
        self,
        *,
        coverage_threshold: float = 80.0,
        high_value_coverage_threshold: float = 80.0,
        high_prior_threshold: float = 0.7,
        max_new_hypotheses: int = 10,
    ) -> None:
        self.coverage_threshold = _normalize_pct(coverage_threshold)
        self.high_value_coverage_threshold = _normalize_pct(high_value_coverage_threshold)
        self.high_prior_threshold = max(0.0, min(1.0, high_prior_threshold))
        self.max_new_hypotheses = max(0, int(max_new_hypotheses))

    def run(
        self,
        dag: Any,
        matrix: Any,
        findings: list[Any] | tuple[Any, ...] | None = None,
        pti: Any | None = None,
    ) -> CritiqueReport:
        finding_items = list(findings or [])
        coverage_pct, high_value_surface_coverage = summarize_coverage(matrix)
        untested = find_untested_high_prior_hypotheses(
            dag, high_prior_threshold=self.high_prior_threshold
        )
        chain_depth_max, chain_depth_mean = compute_chain_depths(dag, finding_items)

        gaps = evaluate_coverage_gaps(
            coverage_pct=coverage_pct,
            high_value_surface_coverage=high_value_surface_coverage,
            coverage_threshold=self.coverage_threshold,
            high_value_coverage_threshold=self.high_value_coverage_threshold,
        )
        gaps.extend(_evaluate_hypothesis_gaps(untested))
        gaps.extend(_evaluate_finding_gaps(finding_items))
        gaps.extend(_evaluate_pti_gaps(pti))
        gaps = _dedupe_preserve_order(gaps)

        proposed = propose_hypotheses_for_gaps(
            gaps,
            untested_high_prior_hypotheses=untested,
            max_items=self.max_new_hypotheses,
        )
        finish_allowed = not gaps
        rationale = (
            "Finish allowed: deterministic critique found no coverage, hypothesis, "
            "finding, or PTI gaps."
            if finish_allowed
            else f"Finish blocked: deterministic critique found {len(gaps)} gap(s)."
        )

        return CritiqueReport(
            coverage_pct=coverage_pct,
            high_value_surface_coverage=high_value_surface_coverage,
            untested_high_prior_hypotheses=untested,
            chain_depth_max=chain_depth_max,
            chain_depth_mean=chain_depth_mean,
            gaps=gaps,
            new_hypotheses_proposed=proposed,
            finish_allowed=finish_allowed,
            rationale=rationale,
        )


def summarize_coverage(matrix: Any) -> tuple[float, float]:
    coverage_pct = _first_number(matrix, ("coverage_pct", "coverage_percent", "overall_pct"))
    high_value_pct = _first_number(
        matrix,
        (
            "high_value_surface_coverage",
            "high_value_coverage_pct",
            "high_value_pct",
        ),
    )

    items = _coverage_items(matrix)
    if coverage_pct is None:
        coverage_pct = _pct_from_items(items)
    if high_value_pct is None:
        high_value_items = [item for item in items if _is_high_value_surface(item)]
        high_value_pct = _pct_from_items(high_value_items) if high_value_items else coverage_pct

    return _normalize_pct(coverage_pct or 0.0), _normalize_pct(high_value_pct or 0.0)


def evaluate_coverage_gaps(
    *,
    coverage_pct: float,
    high_value_surface_coverage: float,
    coverage_threshold: float = 80.0,
    high_value_coverage_threshold: float = 80.0,
) -> list[str]:
    gaps: list[str] = []
    if coverage_pct < coverage_threshold:
        gaps.append(
            f"Overall coverage below threshold: {coverage_pct:.1f}% < {coverage_threshold:.1f}%."
        )
    if high_value_surface_coverage < high_value_coverage_threshold:
        gaps.append(
            "High-value surface coverage below threshold: "
            f"{high_value_surface_coverage:.1f}% < {high_value_coverage_threshold:.1f}%."
        )
    return gaps


def find_untested_high_prior_hypotheses(
    dag: Any, *, high_prior_threshold: float = 0.7
) -> list[str]:
    threshold = max(0.0, min(1.0, high_prior_threshold))
    untested: list[str] = []
    for node in _dag_nodes(dag):
        prior = _first_number(node, ("prior", "probability", "confidence"))
        if prior is None or prior < threshold:
            continue
        status = str(_first_value(node, ("status", "state"), default="pending")).lower()
        if status in {"confirmed", "refuted", "rejected", "closed", "tested", "done"}:
            continue
        claim = str(_first_value(node, ("claim", "title", "name"), default="")).strip()
        if claim:
            untested.append(claim)
    return _dedupe_preserve_order(untested)


def compute_chain_depths(
    dag: Any, findings: list[Any] | tuple[Any, ...] | None = None
) -> tuple[int, float]:
    explicit_max = _first_number(dag, ("chain_depth_max", "max_chain_depth"))
    explicit_mean = _first_number(dag, ("chain_depth_mean", "mean_chain_depth"))
    if explicit_max is not None and explicit_mean is not None:
        return int(max(0, explicit_max)), max(0.0, float(explicit_mean))

    finding_depths = [
        int(depth)
        for finding in findings or []
        if (depth := _first_number(finding, ("chain_depth", "depth"))) is not None
    ]
    if finding_depths:
        return max(finding_depths), float(mean(finding_depths))

    nodes = _dag_nodes(dag)
    if not nodes:
        return 0, 0.0

    node_ids: dict[int, str] = {}
    parents_by_id: dict[str, list[str]] = {}
    for index, node in enumerate(nodes):
        node_id = str(_first_value(node, ("node_id", "id"), default=f"node-{index}"))
        node_ids[index] = node_id
        raw_parents = _first_value(
            node,
            ("parent_ids", "parents", "dependencies", "depends_on"),
            default=[],
        )
        parents_by_id[node_id] = [str(item) for item in _as_list(raw_parents)]

    cache: dict[str, int] = {}
    visiting: set[str] = set()

    def depth(node_id: str) -> int:
        if node_id in cache:
            return cache[node_id]
        if node_id in visiting:
            return 1
        visiting.add(node_id)
        parents = [parent for parent in parents_by_id.get(node_id, []) if parent in parents_by_id]
        value = 1 if not parents else 1 + max(depth(parent) for parent in parents)
        visiting.remove(node_id)
        cache[node_id] = value
        return value

    depths = [depth(node_id) for node_id in parents_by_id]
    return max(depths), float(mean(depths))


def propose_hypotheses_for_gaps(
    gaps: list[str],
    *,
    untested_high_prior_hypotheses: list[str],
    max_items: int = 10,
) -> list[ProposedHypothesis]:
    proposed: list[ProposedHypothesis] = []
    seen_claims: set[str] = set()

    for claim in untested_high_prior_hypotheses:
        proposal = ProposedHypothesis(
            claim=f"Complete testing for high-prior hypothesis: {claim}",
            decision_class="verify",
            prior=0.8,
            rationale="High-prior hypothesis remained pending at critique time.",
            source_gap=claim,
        )
        _append_unique_proposal(proposed, seen_claims, proposal, max_items)

    for gap in gaps:
        gap_lower = gap.lower()
        if "overall coverage" in gap_lower:
            proposal = ProposedHypothesis(
                claim="Expand coverage across untested surface/vector combinations.",
                decision_class="strategy",
                prior=0.75,
                rationale=gap,
                source_gap=gap,
            )
        elif "high-value surface" in gap_lower:
            proposal = ProposedHypothesis(
                claim="Prioritize untested high-value surfaces before finishing.",
                decision_class="strategy",
                prior=0.82,
                rationale=gap,
                source_gap=gap,
            )
        elif "finding lacks verification" in gap_lower:
            proposal = ProposedHypothesis(
                claim="Run adversarial verification for unresolved high-severity findings.",
                decision_class="verify",
                prior=0.78,
                rationale=gap,
                source_gap=gap,
            )
        elif "defense" in gap_lower or "block" in gap_lower:
            proposal = ProposedHypothesis(
                claim="Re-check blocked surfaces with a non-mutating browser or verifier path.",
                decision_class="verify",
                prior=0.7,
                rationale=gap,
                source_gap=gap,
            )
        else:
            continue
        _append_unique_proposal(proposed, seen_claims, proposal, max_items)

    return proposed


def _evaluate_hypothesis_gaps(untested: list[str]) -> list[str]:
    if not untested:
        return []
    joined = "; ".join(untested[:5])
    suffix = "" if len(untested) <= 5 else f"; +{len(untested) - 5} more"
    return [f"High-prior hypotheses remain untested: {joined}{suffix}."]


def _evaluate_finding_gaps(findings: list[Any]) -> list[str]:
    gaps: list[str] = []
    for finding in findings:
        severity = str(
            _first_value(finding, ("severity", "effective_severity"), default="")
        ).lower()
        status = str(_first_value(finding, ("status", "verdict"), default="")).lower()
        title = str(_first_value(finding, ("title", "id", "finding_id"), default="finding")).strip()
        if severity in {"critical", "high"} and status in {"", "open", "unconfirmed", "pending"}:
            gaps.append(f"High-severity finding lacks verification: {title}.")
    return gaps


def _evaluate_pti_gaps(pti: Any | None) -> list[str]:
    if pti is None:
        return []
    defenses = _first_value(pti, ("defenses", "block_history"), default=[])
    gaps: list[str] = []
    for defense in _as_list(defenses):
        bypasses = _first_value(defense, ("bypasses_known", "successful_bypasses"), default=[])
        kind = str(_first_value(defense, ("kind", "detector"), default="defense")).strip()
        if not _as_list(bypasses):
            gaps.append(f"Known defense has no recorded safe follow-up path: {kind}.")
    return gaps


def _coverage_items(matrix: Any) -> list[Any]:
    if matrix is None:
        return []
    if isinstance(matrix, list | tuple):
        return list(matrix)
    for name in ("surfaces", "surface_units", "items", "entries", "rows"):
        value = _first_value(matrix, (name,), default=None)
        if isinstance(value, list | tuple):
            return list(value)
    return []


def _pct_from_items(items: list[Any]) -> float:
    if not items:
        return 0.0
    covered = sum(1 for item in items if _is_covered(item))
    return (covered / len(items)) * 100.0


def _is_covered(item: Any) -> bool:
    status = str(_first_value(item, ("status", "coverage", "state"), default="")).lower()
    return status in {"tested", "covered", "verified", "confirmed", "done", "passed", "complete"}


def _is_high_value_surface(item: Any) -> bool:
    value = _first_value(item, ("high_value", "is_high_value"), default=None)
    if isinstance(value, bool):
        return value
    priority = _first_number(item, ("priority", "risk", "value", "impact"))
    if priority is not None and priority >= 0.75:
        return True
    label = str(_first_value(item, ("value_tier", "risk_tier", "severity"), default="")).lower()
    return label in {"high", "critical", "high-value", "crown"}


def _dag_nodes(dag: Any) -> list[Any]:
    if dag is None:
        return []
    if isinstance(dag, list | tuple):
        return list(dag)
    for name in ("nodes", "hypotheses", "items"):
        value = _first_value(dag, (name,), default=None)
        if isinstance(value, dict):
            return list(value.values())
        if isinstance(value, list | tuple):
            return list(value)
        if callable(value):
            try:
                called = value()
            except TypeError:
                continue
            if isinstance(called, dict):
                return list(called.values())
            if isinstance(called, list | tuple):
                return list(called)
    return []


def _first_number(obj: Any, names: tuple[str, ...]) -> float | None:
    value = _first_value(obj, names, default=None)
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _first_value(obj: Any, names: tuple[str, ...], *, default: Any) -> Any:
    for name in names:
        if isinstance(obj, dict) and name in obj:
            return obj[name]
        if hasattr(obj, name):
            return getattr(obj, name)
    return default


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def _normalize_pct(value: float | int) -> float:
    pct = float(value)
    if 0.0 <= pct <= 1.0:
        pct *= 100.0
    return max(0.0, min(100.0, pct))


def _append_unique_proposal(
    proposed: list[ProposedHypothesis],
    seen_claims: set[str],
    proposal: ProposedHypothesis,
    max_items: int,
) -> None:
    if len(proposed) >= max_items:
        return
    if proposal.claim in seen_claims:
        return
    seen_claims.add(proposal.claim)
    proposed.append(proposal)


def _dedupe_preserve_order(items: list[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    return deduped
