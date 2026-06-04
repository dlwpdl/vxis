"""Coverage matrix and finish-gate helpers for v3 scans."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel, Field


CoverageStatus = Literal["untested", "tested-clean", "tested-blocked", "found"]
TESTED_STATUSES = frozenset({"tested-clean", "tested-blocked", "found"})
TERMINAL_HYPOTHESIS_STATUSES = frozenset({"confirmed", "refuted"})

VECTOR_CLASSES = [
    "sqli",
    "xss",
    "idor",
    "bola",
    "ssrf",
    "auth-bypass",
    "path-traversal",
    "rce",
    "ssti",
    "xxe",
    "race",
    "business-logic",
]

HIGH_VALUE_PATH_HINTS = ("admin", "login", "pay", "auth")


class SurfaceUnitRef(BaseModel):
    surface_id: str
    path: str
    method: str
    auth_role: str


class CoverageCell(BaseModel):
    surface_id: str
    vector_class: str
    status: CoverageStatus = "untested"
    last_iter: int = -1
    hypothesis_ids: list[str] = Field(default_factory=list)
    prior: float = Field(default=1.0, ge=0.0, le=1.0)


class CoverageGateReport(BaseModel):
    allowed: bool
    coverage_percent: float
    required_percent: float
    high_value_gaps: list[CoverageCell] = Field(default_factory=list)
    overall_gaps: list[CoverageCell] = Field(default_factory=list)
    unresolved_hypothesis_ids: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)

    @property
    def blocks_finish(self) -> bool:
        return not self.allowed


def _normalize_vector_class(vector_class: str) -> str:
    normalized = str(vector_class).strip().lower()
    if not normalized:
        raise ValueError("vector_class cannot be empty")
    return normalized


def _normalize_vector_classes(vector_classes: Iterable[str] | None) -> tuple[str, ...]:
    raw_values = VECTOR_CLASSES if vector_classes is None else vector_classes
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_value in raw_values:
        value = _normalize_vector_class(raw_value)
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    if not normalized:
        raise ValueError("at least one vector class is required")
    return tuple(normalized)


def _surface_value(surface: SurfaceUnitRef | Mapping[str, Any], key: str) -> Any:
    if isinstance(surface, Mapping):
        return surface.get(key, "")
    return getattr(surface, key, "")


def _surface_id(surface: SurfaceUnitRef | Mapping[str, Any]) -> str:
    surface_id = str(_surface_value(surface, "surface_id")).strip()
    if not surface_id:
        raise ValueError("surface_id cannot be empty")
    return surface_id


def _hypothesis_value(hypothesis: Any, key: str, default: Any = None) -> Any:
    if isinstance(hypothesis, Mapping):
        return hypothesis.get(key, default)
    return getattr(hypothesis, key, default)


def is_high_value_surface(surface: SurfaceUnitRef | Mapping[str, Any]) -> bool:
    """Return true for admin, login, payment, or auth-like surfaces."""
    path = str(_surface_value(surface, "path")).lower()
    auth_role = str(_surface_value(surface, "auth_role")).strip().lower()
    if auth_role == "admin":
        return True
    return any(hint in path for hint in HIGH_VALUE_PATH_HINTS)


def high_value_surfaces(
    surfaces: Iterable[SurfaceUnitRef | Mapping[str, Any]],
) -> list[SurfaceUnitRef | Mapping[str, Any]]:
    return [surface for surface in surfaces if is_high_value_surface(surface)]


class CoverageMatrix(BaseModel):
    cells: dict[tuple[str, str], CoverageCell] = Field(default_factory=dict)

    @classmethod
    def for_surfaces(
        cls,
        surfaces: Iterable[SurfaceUnitRef | Mapping[str, Any]],
        *,
        vector_classes: Iterable[str] | None = None,
        prior: float = 1.0,
    ) -> "CoverageMatrix":
        matrix = cls()
        for surface in surfaces:
            matrix.ensure_surface(surface, vector_classes=vector_classes, prior=prior)
        return matrix

    def ensure_surface(
        self,
        surface: SurfaceUnitRef | Mapping[str, Any],
        *,
        vector_classes: Iterable[str] | None = None,
        prior: float = 1.0,
    ) -> None:
        surface_id = _surface_id(surface)
        for vector_class in _normalize_vector_classes(vector_classes):
            key = (surface_id, vector_class)
            if key not in self.cells:
                self.cells[key] = CoverageCell(
                    surface_id=surface_id,
                    vector_class=vector_class,
                    status="untested",
                    last_iter=-1,
                    prior=prior,
                )

    def mark(
        self,
        surface_id: str,
        vector_class: str,
        status: CoverageStatus,
        iter: int,
        hypothesis_id: str | None = None,
        *,
        prior: float | None = None,
    ) -> None:
        normalized_surface_id = str(surface_id).strip()
        if not normalized_surface_id:
            raise ValueError("surface_id cannot be empty")
        normalized_vector_class = _normalize_vector_class(vector_class)
        iteration = int(iter)
        key = (normalized_surface_id, normalized_vector_class)
        cell = self.cells.get(key)
        if cell is None:
            cell = CoverageCell(
                surface_id=normalized_surface_id,
                vector_class=normalized_vector_class,
                status=status,
                last_iter=iteration,
                prior=1.0 if prior is None else prior,
            )
            self.cells[key] = cell
        else:
            cell.status = status
            cell.last_iter = iteration
            if prior is not None:
                cell.prior = prior
        if hypothesis_id:
            hypothesis = str(hypothesis_id)
            if hypothesis not in cell.hypothesis_ids:
                cell.hypothesis_ids.append(hypothesis)

    def coverage_percent(
        self,
        surface_filter: Callable[[CoverageCell], bool] | None = None,
    ) -> float:
        cells = [
            cell for cell in self.cells.values() if surface_filter is None or surface_filter(cell)
        ]
        if not cells:
            return 100.0
        tested = sum(1 for cell in cells if cell.status in TESTED_STATUSES)
        return round(tested / len(cells) * 100.0, 2)

    def gaps(self, prior_threshold: float = 0.3) -> list[CoverageCell]:
        return sorted(
            [
                cell
                for cell in self.cells.values()
                if cell.status == "untested" and cell.prior >= prior_threshold
            ],
            key=lambda cell: (-cell.prior, cell.surface_id, cell.vector_class),
        )

    def high_value_gaps(
        self,
        surfaces: Iterable[SurfaceUnitRef | Mapping[str, Any]],
        *,
        vector_classes: Iterable[str] | None = None,
    ) -> list[CoverageCell]:
        vectors = _normalize_vector_classes(vector_classes)
        gaps: list[CoverageCell] = []
        for surface in surfaces:
            if not is_high_value_surface(surface):
                continue
            surface_id = _surface_id(surface)
            for vector_class in vectors:
                cell = self.cells.get((surface_id, vector_class))
                if cell is None:
                    cell = CoverageCell(
                        surface_id=surface_id,
                        vector_class=vector_class,
                        status="untested",
                        last_iter=-1,
                    )
                if cell.status not in TESTED_STATUSES:
                    gaps.append(cell)
        return sorted(gaps, key=lambda cell: (cell.surface_id, cell.vector_class))

    def finish_gate_report(
        self,
        *,
        surfaces: Iterable[SurfaceUnitRef | Mapping[str, Any]] | None = None,
        hypotheses: Iterable[Any] | None = None,
        required_coverage_percent: float = 70.0,
        vector_classes: Iterable[str] | None = None,
        high_value_vector_classes: Iterable[str] | None = None,
        hypothesis_prior_threshold: float = 0.5,
    ) -> CoverageGateReport:
        if required_coverage_percent < 0.0 or required_coverage_percent > 100.0:
            raise ValueError("required_coverage_percent must be between 0 and 100")

        surface_list = list(surfaces or [])
        known_vectors = _normalize_vector_classes(
            vector_classes or self._known_vector_classes() or VECTOR_CLASSES
        )
        matrix = self.model_copy(deep=True)
        for surface in surface_list:
            matrix.ensure_surface(surface, vector_classes=known_vectors)

        coverage_percent = matrix.coverage_percent()
        high_value_vectors = _normalize_vector_classes(high_value_vector_classes or known_vectors)
        high_value_gaps = matrix.high_value_gaps(
            surface_list,
            vector_classes=high_value_vectors,
        )
        unresolved_hypothesis_ids = _unresolved_hypothesis_ids(
            hypotheses or [],
            prior_threshold=hypothesis_prior_threshold,
        )
        overall_gaps = matrix.gaps()

        reasons: list[str] = []
        if high_value_gaps:
            reasons.append("high-value coverage gaps remain")
        if unresolved_hypothesis_ids:
            reasons.append("high-prior hypotheses unresolved")
        if coverage_percent < required_coverage_percent:
            reasons.append("overall coverage below threshold")

        return CoverageGateReport(
            allowed=not reasons,
            coverage_percent=coverage_percent,
            required_percent=required_coverage_percent,
            high_value_gaps=high_value_gaps,
            overall_gaps=overall_gaps,
            unresolved_hypothesis_ids=unresolved_hypothesis_ids,
            reasons=reasons,
        )

    def to_summary(self, token_budget: int) -> str:
        if token_budget <= 0:
            return ""
        total = len(self.cells)
        if total == 0:
            return _clip_to_token_budget("coverage: no cells", token_budget)

        counts = {status: 0 for status in ("untested", "tested-clean", "tested-blocked", "found")}
        for cell in self.cells.values():
            counts[cell.status] += 1
        tested = counts["tested-clean"] + counts["tested-blocked"] + counts["found"]
        lines = [
            f"coverage: {self.coverage_percent():.1f}% ({tested}/{total} probed)",
            (
                "status: "
                f"found={counts['found']} clean={counts['tested-clean']} "
                f"blocked={counts['tested-blocked']} untested={counts['untested']}"
            ),
        ]
        gaps = self.gaps()[:5]
        if gaps:
            gap_text = ", ".join(f"{cell.surface_id}:{cell.vector_class}" for cell in gaps)
            lines.append(f"top gaps: {gap_text}")
        return _clip_to_token_budget("\n".join(lines), token_budget)

    def _known_vector_classes(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(cell.vector_class for cell in self.cells.values()))


def _unresolved_hypothesis_ids(
    hypotheses: Iterable[Any],
    *,
    prior_threshold: float,
) -> list[str]:
    unresolved: list[str] = []
    for index, hypothesis in enumerate(hypotheses):
        try:
            prior = float(_hypothesis_value(hypothesis, "prior", 0.0))
        except (TypeError, ValueError):
            prior = 0.0
        status = str(_hypothesis_value(hypothesis, "status", "")).strip().lower()
        if prior < prior_threshold or status in TERMINAL_HYPOTHESIS_STATUSES:
            continue
        hypothesis_id = (
            _hypothesis_value(hypothesis, "node_id", None)
            or _hypothesis_value(hypothesis, "hypothesis_id", None)
            or _hypothesis_value(hypothesis, "id", None)
            or f"hypothesis-{index}"
        )
        unresolved.append(str(hypothesis_id))
    return unresolved


def _clip_to_token_budget(text: str, token_budget: int) -> str:
    max_chars = max(1, int(token_budget) * 4)
    if len(text) <= max_chars:
        return text
    if max_chars <= 3:
        return text[:max_chars]
    return text[: max_chars - 3].rstrip() + "..."


def evaluate_finish_gate(
    matrix: CoverageMatrix,
    **kwargs: Any,
) -> CoverageGateReport:
    return matrix.finish_gate_report(**kwargs)


__all__ = [
    "CoverageCell",
    "CoverageGateReport",
    "CoverageMatrix",
    "CoverageStatus",
    "HIGH_VALUE_PATH_HINTS",
    "SurfaceUnitRef",
    "TESTED_STATUSES",
    "VECTOR_CLASSES",
    "evaluate_finish_gate",
    "high_value_surfaces",
    "is_high_value_surface",
]
