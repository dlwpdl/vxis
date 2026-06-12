"""Pydantic HypothesisNode DAG models used by the v3 cognitive engine."""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vxis.agent.hypothesis.bayes import (
    DEFAULT_PROPAGATION_DECAY,
    bayes_update,
    clamp_probability,
    coerce_delta,
    prior_for_status,
    propagation_seed_delta,
)

DecisionClass = Literal["recon", "triage", "strategy", "exploit", "verify", "critique"]
HypothesisStatus = Literal["untested", "testing", "confirmed", "refuted", "inconclusive"]

HYPOTHESIS_STATUSES: tuple[str, ...] = (
    "untested",
    "testing",
    "confirmed",
    "refuted",
    "inconclusive",
)
FINAL_STATUSES = {"confirmed", "refuted"}


class HypothesisNode(BaseModel):
    """A testable security claim and its current belief state."""

    model_config = ConfigDict(validate_assignment=True)

    node_id: str
    claim: str
    decision_class: DecisionClass
    prior: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    status: HypothesisStatus = "untested"
    parent_ids: list[str] = Field(default_factory=list)
    child_ids: list[str] = Field(default_factory=list)
    proposed_vector_class: str | None = None
    surface_id: str | None = None
    created_iter: int = 0
    last_updated_iter: int = 0

    @field_validator("node_id", "claim")
    @classmethod
    def _require_non_empty_text(cls, value: str) -> str:
        text = str(value or "").strip()
        if not text:
            raise ValueError("value cannot be empty")
        return text

    @field_validator("decision_class", "status", mode="before")
    @classmethod
    def _normalize_literal_text(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("prior", mode="before")
    @classmethod
    def _validate_prior(cls, value: Any) -> float:
        return clamp_probability(value)

    @field_validator("parent_ids", "child_ids", mode="before")
    @classmethod
    def _normalize_id_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            raw_items = [value]
        else:
            raw_items = list(value)
        out: list[str] = []
        seen: set[str] = set()
        for item in raw_items:
            text = str(item or "").strip()
            if not text or text in seen:
                continue
            seen.add(text)
            out.append(text)
        return out

    @field_validator("evidence", mode="before")
    @classmethod
    def _normalize_evidence(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            raw_items = [value]
        else:
            raw_items = list(value)
        return [str(item).strip() for item in raw_items if str(item or "").strip()]

    @field_validator("created_iter", "last_updated_iter", mode="before")
    @classmethod
    def _normalize_iteration(cls, value: Any) -> int:
        if value is None or value == "":
            return 0
        return int(value)

    @model_validator(mode="after")
    def _last_updated_not_before_created(self) -> "HypothesisNode":
        if self.last_updated_iter < self.created_iter:
            self.last_updated_iter = self.created_iter
        return self

    def brief(self) -> dict[str, Any]:
        """Return the compact representation used by tools and summaries."""
        return {
            "node_id": self.node_id,
            "claim": self.claim,
            "decision_class": self.decision_class,
            "prior": round(self.prior, 4),
            "status": self.status,
            "parent_ids": list(self.parent_ids),
            "child_ids": list(self.child_ids),
            "proposed_vector_class": self.proposed_vector_class,
            "surface_id": self.surface_id,
            "created_iter": self.created_iter,
            "last_updated_iter": self.last_updated_iter,
            "evidence_count": len(self.evidence),
        }


class HypothesisDAG(BaseModel):
    """Directed acyclic graph of hypotheses and their belief state."""

    model_config = ConfigDict(validate_assignment=True)

    nodes: dict[str, HypothesisNode] = Field(default_factory=dict)
    roots: list[str] = Field(default_factory=list)

    @field_validator("roots", mode="before")
    @classmethod
    def _normalize_roots(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            raw_items = [value]
        else:
            raw_items = list(value)
        return _unique_ids(raw_items)

    @model_validator(mode="after")
    def _validate_graph_references(self) -> "HypothesisDAG":
        for node_id, node in self.nodes.items():
            if node.node_id != node_id:
                raise ValueError(f"node key {node_id!r} does not match node_id {node.node_id!r}")
            for parent_id in node.parent_ids:
                if parent_id not in self.nodes:
                    raise ValueError(f"node {node_id!r} references unknown parent {parent_id!r}")
            for child_id in node.child_ids:
                if child_id not in self.nodes:
                    raise ValueError(f"node {node_id!r} references unknown child {child_id!r}")
        for root_id in self.roots:
            if root_id not in self.nodes:
                raise ValueError(f"root {root_id!r} is not present in nodes")
        return self

    def add(self, hypothesis: HypothesisNode, parent_ids: list[str] | None = None) -> None:
        """Add a hypothesis and wire parent/child references."""
        node = (
            hypothesis
            if isinstance(hypothesis, HypothesisNode)
            else HypothesisNode.model_validate(hypothesis)
        )
        if node.node_id in self.nodes:
            raise ValueError(f"hypothesis {node.node_id!r} already exists")

        clean_parent_ids = _unique_ids(parent_ids if parent_ids is not None else node.parent_ids)
        if node.node_id in clean_parent_ids:
            raise ValueError("a hypothesis cannot be its own parent")
        missing_parents = [
            parent_id for parent_id in clean_parent_ids if parent_id not in self.nodes
        ]
        if missing_parents:
            raise ValueError(f"unknown parent hypothesis ids: {missing_parents}")

        clean_child_ids = _unique_ids(node.child_ids)
        if node.node_id in clean_child_ids:
            raise ValueError("a hypothesis cannot be its own child")
        missing_children = [child_id for child_id in clean_child_ids if child_id not in self.nodes]
        if missing_children:
            raise ValueError(f"unknown child hypothesis ids: {missing_children}")

        node.parent_ids = clean_parent_ids
        node.child_ids = clean_child_ids
        self.nodes[node.node_id] = node

        if clean_parent_ids:
            for parent_id in clean_parent_ids:
                parent = self.nodes[parent_id]
                if node.node_id not in parent.child_ids:
                    parent.child_ids.append(node.node_id)
            self.roots = [root_id for root_id in self.roots if root_id != node.node_id]
        elif node.node_id not in self.roots:
            self.roots.append(node.node_id)

        for child_id in clean_child_ids:
            child = self.nodes[child_id]
            if node.node_id not in child.parent_ids:
                child.parent_ids.append(node.node_id)
            if child_id in self.roots:
                self.roots.remove(child_id)
        self.roots = _unique_ids(self.roots)

    def update_belief(
        self,
        node_id: str,
        evidence: str,
        delta: float,
        *,
        status_change: HypothesisStatus | str | None = None,
        iteration: int | None = None,
        propagate: bool = True,
    ) -> None:
        """Update a node prior and optionally propagate belief changes to descendants."""
        node = self._require_node(node_id)
        normalized_status = _normalize_status(status_change)
        bounded_delta = coerce_delta(delta)

        evidence_text = str(evidence or "").strip()
        if evidence_text:
            node.evidence.append(evidence_text)
        node.prior = prior_for_status(bayes_update(node.prior, bounded_delta), normalized_status)
        if normalized_status is not None:
            node.status = normalized_status
        self._touch(node, iteration)

        if not propagate or not node.child_ids:
            return
        child_delta = propagation_seed_delta(normalized_status, bounded_delta)
        if child_delta == 0:
            return
        self._propagate_to_children(
            child_ids=node.child_ids,
            delta=child_delta,
            iteration=iteration,
            visited={node_id},
        )

    def prune_dead(self, threshold: float = 0.05) -> int:
        """Remove hypotheses with priors below `threshold` and clean graph links."""
        threshold_probability = clamp_probability(threshold)
        remove_ids = {
            node_id
            for node_id, node in self.nodes.items()
            if node.prior < threshold_probability and node.status != "confirmed"
        }
        if not remove_ids:
            return 0

        for node_id in remove_ids:
            self.nodes.pop(node_id, None)

        for node in self.nodes.values():
            node.parent_ids = [
                parent_id for parent_id in node.parent_ids if parent_id not in remove_ids
            ]
            node.child_ids = [child_id for child_id in node.child_ids if child_id not in remove_ids]

        surviving_roots = [root_id for root_id in self.roots if root_id in self.nodes]
        for node_id, node in self.nodes.items():
            if not node.parent_ids and node_id not in surviving_roots:
                surviving_roots.append(node_id)
        self.roots = _unique_ids(surviving_roots)
        return len(remove_ids)

    def top_untested(self, k: int = 3) -> list[HypothesisNode]:
        """Return the highest-prior untested hypotheses."""
        limit = max(0, int(k))
        if limit == 0:
            return []
        candidates = [node for node in self.nodes.values() if node.status == "untested"]
        return sorted(candidates, key=_priority_sort_key)[:limit]

    def query(
        self,
        *,
        status: str | None = None,
        proposed_vector_class: str | None = None,
        surface_id: str | None = None,
        min_prior: float | None = None,
        max_prior: float | None = None,
        node_id: str | None = None,
        parent_id: str | None = None,
        limit: int | None = None,
    ) -> list[HypothesisNode]:
        """Filter hypotheses for critique and tool responses."""
        nodes = list(self.nodes.values())
        if node_id:
            nodes = [node for node in nodes if node.node_id == node_id]
        if status:
            normalized_status = _normalize_status(status)
            nodes = [node for node in nodes if node.status == normalized_status]
        if proposed_vector_class:
            vector = proposed_vector_class.lower().strip()
            nodes = [
                node
                for node in nodes
                if str(node.proposed_vector_class or "").lower().strip() == vector
            ]
        if surface_id:
            surface = surface_id.strip()
            nodes = [node for node in nodes if node.surface_id == surface]
        if parent_id:
            nodes = [node for node in nodes if parent_id in node.parent_ids]
        if min_prior is not None:
            floor = clamp_probability(min_prior)
            nodes = [node for node in nodes if node.prior >= floor]
        if max_prior is not None:
            ceiling = clamp_probability(max_prior)
            nodes = [node for node in nodes if node.prior <= ceiling]

        sorted_nodes = sorted(nodes, key=_priority_sort_key)
        if limit is None:
            return sorted_nodes
        return sorted_nodes[: max(0, int(limit))]

    def status_counts(self) -> dict[str, int]:
        """Return counts for all known statuses."""
        counts = Counter(node.status for node in self.nodes.values())
        return {status: counts.get(status, 0) for status in HYPOTHESIS_STATUSES}

    def next_node_id(self, prefix: str = "hyp", reserved: set[str] | None = None) -> str:
        """Return a stable unused node id for tool-created hypotheses."""
        reserved_ids = reserved or set()
        index = len(self.nodes) + len(reserved_ids) + 1
        while True:
            candidate = f"{prefix}-{index:04d}"
            if candidate not in self.nodes and candidate not in reserved_ids:
                return candidate
            index += 1

    def to_summary(self, token_budget: int = 400) -> str:
        """Render a compact dashboard summary, roughly bounded by token budget."""
        budget = max(0, int(token_budget))
        if budget == 0:
            return ""

        counts = self.status_counts()
        count_summary = ", ".join(f"{status}={counts[status]}" for status in HYPOTHESIS_STATUSES)
        lines = [
            f"HypothesisNode DAG: {len(self.nodes)} nodes; roots={len(self.roots)}; {count_summary}"
        ]

        top = self.top_untested(k=5)
        if top:
            lines.append("Top untested:")
            lines.extend(f"- {self._format_summary_line(node)}" for node in top)

        testing = self.query(status="testing", limit=3)
        if testing:
            lines.append("Testing:")
            lines.extend(f"- {self._format_summary_line(node)}" for node in testing)

        recent_terminal = [
            node
            for node in self.nodes.values()
            if node.status in {"confirmed", "refuted", "inconclusive"}
        ]
        if recent_terminal:
            lines.append("Recent outcomes:")
            for node in sorted(
                recent_terminal,
                key=lambda item: (-item.last_updated_iter, _priority_sort_key(item)),
            )[:5]:
                lines.append(f"- {self._format_summary_line(node)}")

        return _trim_to_token_budget("\n".join(lines), budget)

    def _require_node(self, node_id: str) -> HypothesisNode:
        try:
            return self.nodes[node_id]
        except KeyError as exc:
            raise KeyError(f"unknown hypothesis id: {node_id}") from exc

    def _touch(self, node: HypothesisNode, iteration: int | None) -> None:
        if iteration is None:
            node.last_updated_iter += 1
            return
        node.last_updated_iter = max(node.created_iter, int(iteration))

    def _propagate_to_children(
        self,
        *,
        child_ids: list[str],
        delta: float,
        iteration: int | None,
        visited: set[str],
    ) -> None:
        next_delta = coerce_delta(delta)
        for child_id in child_ids:
            if child_id in visited:
                continue
            child = self.nodes.get(child_id)
            if child is None:
                continue
            visited.add(child_id)
            if child.status not in FINAL_STATUSES:
                child.prior = bayes_update(child.prior, next_delta)
                self._touch(child, iteration)
            decayed_delta = next_delta * DEFAULT_PROPAGATION_DECAY
            if abs(decayed_delta) >= 0.01 and child.child_ids:
                self._propagate_to_children(
                    child_ids=child.child_ids,
                    delta=decayed_delta,
                    iteration=iteration,
                    visited=visited,
                )

    def _format_summary_line(self, node: HypothesisNode) -> str:
        vector = node.proposed_vector_class or "unknown-vector"
        surface = f" surface={node.surface_id}" if node.surface_id else ""
        return (
            f"{node.node_id} [{node.status} p={node.prior:.2f} {node.decision_class} "
            f"{vector}{surface}] {node.claim}"
        )


def _normalize_status(value: HypothesisStatus | str | None) -> HypothesisStatus | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if not normalized:
        return None
    if normalized not in HYPOTHESIS_STATUSES:
        raise ValueError(f"invalid hypothesis status: {value!r}")
    return normalized  # type: ignore[return-value]


def _unique_ids(values: Any) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in list(values or []):
        text = str(item or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _priority_sort_key(node: HypothesisNode) -> tuple[float, int, int, str]:
    return (-node.prior, node.last_updated_iter, node.created_iter, node.node_id)


def _trim_to_token_budget(text: str, token_budget: int) -> str:
    max_chars = max(1, token_budget * 4)
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    trimmed = text[: max_chars - 3].rstrip()
    line_break = trimmed.rfind("\n")
    if line_break > max_chars // 2:
        trimmed = trimmed[:line_break].rstrip()
    return f"{trimmed}..."
