"""Pydantic schemas for Persistent Target Intelligence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from vxis.pti.hashing import normalize_target_url, target_hash_for_url, validate_target_hash

AuthRole = Literal["anon", "user", "admin", "other"]
SurfaceStatus = Literal["alive", "changed", "gone"]
DefenseKind = Literal["waf-signature", "waf-rate", "ip-ban", "honeypot", "behavioral"]
FindingStatus = Literal["present", "fixed", "regressed", "unknown"]
PayloadOutcome = Literal["success", "blocked-signature", "blocked-rate", "no-effect", "error"]
HypothesisFinalStatus = Literal["confirmed", "refuted", "inconclusive"]
DecisionClass = Literal["recon", "triage", "strategy", "exploit", "verify", "critique"]
OutcomeStatus = Literal["success", "blocked", "no-effect", "error", "pending"]

TRAJECTORY_SCHEMA_VERSION = "pti.trajectory.v1"


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc)


class PTIModel(BaseModel):
    """Base PTI model that accepts future schema additions."""

    model_config = ConfigDict(extra="allow")


class StackEntry(PTIModel):
    tech: str
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen_scan: str
    last_seen_scan: str
    evidence: list[str] = Field(default_factory=list)


class SurfaceUnit(PTIModel):
    surface_id: str
    path: str
    method: str
    auth_role: AuthRole
    params: list[str] = Field(default_factory=list)
    forms: list[dict[str, Any]] = Field(default_factory=list)
    status: SurfaceStatus
    last_seen_scan: str

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        method = value.strip().upper()
        if not method:
            raise ValueError("method cannot be empty")
        return method


class Defense(PTIModel):
    kind: DefenseKind
    detector: str
    blocked_payload_classes: list[str] = Field(default_factory=list)
    bypasses_known: list[str] = Field(default_factory=list)
    first_seen_scan: str


class FindingHistoryEntry(PTIModel):
    finding_id: str
    finding_type: str
    surface_id: str
    status: FindingStatus
    first_seen_scan: str
    last_verified_scan: str


class AuthoredTool(PTIModel):
    name: str
    purpose: str
    script_path: str
    created_scan: str
    last_used_scan: str
    success_count: int = Field(ge=0)
    fail_count: int = Field(ge=0)


class PayloadEntry(PTIModel):
    payload: str
    vector_class: str
    outcome: PayloadOutcome
    reason: str | None = None
    scan_id: str


class HypothesisOutcome(PTIModel):
    claim: str
    prior_at_start: float = Field(ge=0.0, le=1.0)
    final_status: HypothesisFinalStatus
    scan_id: str


class Dossier(PTIModel):
    target_hash: str
    target_url: str
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    scan_ids: list[str] = Field(default_factory=list)
    stack: list[StackEntry] = Field(default_factory=list)
    surface: list[SurfaceUnit] = Field(default_factory=list)
    defenses: list[Defense] = Field(default_factory=list)
    findings_history: list[FindingHistoryEntry] = Field(default_factory=list)
    authored_tools: list[AuthoredTool] = Field(default_factory=list)
    payload_library: list[PayloadEntry] = Field(default_factory=list)
    hypothesis_history: list[HypothesisOutcome] = Field(default_factory=list)

    @field_validator("target_hash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        return validate_target_hash(value)

    @field_validator("target_url")
    @classmethod
    def normalize_url(cls, value: str) -> str:
        return normalize_target_url(value)

    @model_validator(mode="after")
    def target_hash_matches_url(self) -> "Dossier":
        expected = target_hash_for_url(self.target_url)
        if self.target_hash != expected:
            raise ValueError("target_hash must be SHA-256 of normalized target_url")
        return self


class TrajectoryRecord(PTIModel):
    schema_version: str = TRAJECTORY_SCHEMA_VERSION
    scan_id: str
    target_hash: str
    iter: int = Field(ge=0)
    decision_class: DecisionClass
    model_used: str
    input_context: dict[str, Any] = Field(default_factory=dict)
    input_token_count: int = Field(ge=0)
    output_action: dict[str, Any] = Field(default_factory=dict)
    output_token_count: int = Field(ge=0)
    outcome_status: OutcomeStatus | None = None
    outcome_evidence: str | None = None
    led_to_finding_id: str | None = None
    led_to_refutation: bool = False
    cost_usd: float = Field(ge=0.0)
    latency_ms: int = Field(ge=0)
    timestamp: datetime = Field(default_factory=utc_now)

    @field_validator("scan_id", "model_used")
    @classmethod
    def non_empty_string(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("value cannot be empty")
        return normalized

    @field_validator("target_hash")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        return validate_target_hash(value)
