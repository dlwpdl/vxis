"""Typed query helpers for PTI dossiers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator

from vxis.pti.models import (
    AuthRole,
    Dossier,
    FindingStatus,
    HypothesisFinalStatus,
    PayloadOutcome,
    SurfaceStatus,
)

QueryType = Literal[
    "stack",
    "surfaces",
    "defenses",
    "findings_history",
    "tools",
    "payloads",
    "hypotheses",
]


class QueryFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")


class StackFilter(QueryFilter):
    tech: str | None = None
    min_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    first_seen_scan: str | None = None
    last_seen_scan: str | None = None


class SurfaceFilter(QueryFilter):
    surface_id: str | None = None
    path: str | None = None
    path_prefix: str | None = None
    method: str | None = None
    auth_role: AuthRole | None = None
    status: SurfaceStatus | None = None
    param: str | None = None
    last_seen_scan: str | None = None

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str | None) -> str | None:
        return value.strip().upper() if value else None


class DefenseFilter(QueryFilter):
    kind: str | None = None
    detector: str | None = None
    blocked_payload_class: str | None = None
    bypass_known: str | None = None
    first_seen_scan: str | None = None


class FindingHistoryFilter(QueryFilter):
    finding_id: str | None = None
    finding_type: str | None = None
    surface_id: str | None = None
    status: FindingStatus | None = None
    first_seen_scan: str | None = None
    last_verified_scan: str | None = None


class ToolFilter(QueryFilter):
    name: str | None = None
    purpose_contains: str | None = None
    created_scan: str | None = None
    last_used_scan: str | None = None
    min_success_count: int | None = Field(default=None, ge=0)


class PayloadFilter(QueryFilter):
    payload_contains: str | None = None
    vector_class: str | None = None
    outcome: PayloadOutcome | None = None
    scan_id: str | None = None


class HypothesisFilter(QueryFilter):
    claim_contains: str | None = None
    final_status: HypothesisFinalStatus | None = None
    scan_id: str | None = None


FilterInput: TypeAlias = QueryFilter | Mapping[str, Any] | None


def query_stack(dossier: Dossier, filters: StackFilter | Mapping[str, Any] | None = None):
    query_filter = _coerce_filter(filters, StackFilter)
    return [
        entry
        for entry in dossier.stack
        if _matches(query_filter.tech, entry.tech)
        and _gte(entry.confidence, query_filter.min_confidence)
        and _matches(query_filter.first_seen_scan, entry.first_seen_scan)
        and _matches(query_filter.last_seen_scan, entry.last_seen_scan)
    ]


def query_surfaces(dossier: Dossier, filters: SurfaceFilter | Mapping[str, Any] | None = None):
    query_filter = _coerce_filter(filters, SurfaceFilter)
    return [
        entry
        for entry in dossier.surface
        if _matches(query_filter.surface_id, entry.surface_id)
        and _matches(query_filter.path, entry.path)
        and _prefix(entry.path, query_filter.path_prefix)
        and _matches(query_filter.method, entry.method)
        and _matches(query_filter.auth_role, entry.auth_role)
        and _matches(query_filter.status, entry.status)
        and _contains(entry.params, query_filter.param)
        and _matches(query_filter.last_seen_scan, entry.last_seen_scan)
    ]


def query_defenses(dossier: Dossier, filters: DefenseFilter | Mapping[str, Any] | None = None):
    query_filter = _coerce_filter(filters, DefenseFilter)
    return [
        entry
        for entry in dossier.defenses
        if _matches(query_filter.kind, entry.kind)
        and _matches(query_filter.detector, entry.detector)
        and _contains(entry.blocked_payload_classes, query_filter.blocked_payload_class)
        and _contains(entry.bypasses_known, query_filter.bypass_known)
        and _matches(query_filter.first_seen_scan, entry.first_seen_scan)
    ]


def query_findings_history(
    dossier: Dossier,
    filters: FindingHistoryFilter | Mapping[str, Any] | None = None,
):
    query_filter = _coerce_filter(filters, FindingHistoryFilter)
    return [
        entry
        for entry in dossier.findings_history
        if _matches(query_filter.finding_id, entry.finding_id)
        and _matches(query_filter.finding_type, entry.finding_type)
        and _matches(query_filter.surface_id, entry.surface_id)
        and _matches(query_filter.status, entry.status)
        and _matches(query_filter.first_seen_scan, entry.first_seen_scan)
        and _matches(query_filter.last_verified_scan, entry.last_verified_scan)
    ]


def query_tools(dossier: Dossier, filters: ToolFilter | Mapping[str, Any] | None = None):
    query_filter = _coerce_filter(filters, ToolFilter)
    return [
        entry
        for entry in dossier.authored_tools
        if _matches(query_filter.name, entry.name)
        and _text_contains(entry.purpose, query_filter.purpose_contains)
        and _matches(query_filter.created_scan, entry.created_scan)
        and _matches(query_filter.last_used_scan, entry.last_used_scan)
        and _gte(entry.success_count, query_filter.min_success_count)
    ]


def query_payloads(dossier: Dossier, filters: PayloadFilter | Mapping[str, Any] | None = None):
    query_filter = _coerce_filter(filters, PayloadFilter)
    return [
        entry
        for entry in dossier.payload_library
        if _text_contains(entry.payload, query_filter.payload_contains)
        and _matches(query_filter.vector_class, entry.vector_class)
        and _matches(query_filter.outcome, entry.outcome)
        and _matches(query_filter.scan_id, entry.scan_id)
    ]


def query_hypotheses(
    dossier: Dossier,
    filters: HypothesisFilter | Mapping[str, Any] | None = None,
):
    query_filter = _coerce_filter(filters, HypothesisFilter)
    return [
        entry
        for entry in dossier.hypothesis_history
        if _text_contains(entry.claim, query_filter.claim_contains)
        and _matches(query_filter.final_status, entry.final_status)
        and _matches(query_filter.scan_id, entry.scan_id)
    ]


def query_pti(dossier: Dossier, query_type: QueryType, filters: FilterInput = None) -> list[Any]:
    if query_type == "stack":
        return query_stack(dossier, filters)
    if query_type == "surfaces":
        return query_surfaces(dossier, filters)
    if query_type == "defenses":
        return query_defenses(dossier, filters)
    if query_type == "findings_history":
        return query_findings_history(dossier, filters)
    if query_type == "tools":
        return query_tools(dossier, filters)
    if query_type == "payloads":
        return query_payloads(dossier, filters)
    if query_type == "hypotheses":
        return query_hypotheses(dossier, filters)
    raise ValueError(f"unknown PTI query type: {query_type!r}")


def _coerce_filter[T: QueryFilter](
    filters: T | Mapping[str, Any] | None,
    filter_type: type[T],
) -> T:
    if filters is None:
        return filter_type()
    if isinstance(filters, filter_type):
        return filters
    if isinstance(filters, Mapping):
        return filter_type.model_validate(dict(filters))
    raise TypeError(f"filters must be {filter_type.__name__}, mapping, or None")


def _matches(expected: Any | None, value: Any) -> bool:
    return expected is None or value == expected


def _gte(value: int | float, minimum: int | float | None) -> bool:
    return minimum is None or value >= minimum


def _contains(values: list[str], expected: str | None) -> bool:
    return expected is None or expected in values


def _prefix(value: str, expected_prefix: str | None) -> bool:
    return expected_prefix is None or value.startswith(expected_prefix)


def _text_contains(value: str, expected: str | None) -> bool:
    return expected is None or expected.lower() in value.lower()
