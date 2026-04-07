"""Scope schemas | 스코프 데이터 스키마."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ActionPolicy(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"
    FORBIDDEN = "forbidden"


@dataclass
class ScopeConfig:
    scan_id: str
    target: str
    in_scope_domains: list[str]
    out_of_scope: list[str]
    path_rules: dict[str, list[str]]
    http_methods: dict[str, list[str]]
    data_sensitivity: dict[str, Any]
    account_rules: dict[str, str]
    destructive_actions: dict[str, str]
    time_window: dict[str, Any]
    rate_limits: dict[str, int]
    audit: dict[str, bool]


@dataclass
class ScopeCheckResult:
    allowed: bool
    policy: ActionPolicy
    reason: str
    rule_matched: str = ""
    concerns: list[str] = field(default_factory=list)
    requires_approval: bool = False
    risk_level: str = "low"


@dataclass
class PIIDetection:
    found: bool
    types: list[str]
    matches: dict[str, list[str]]
    redacted_text: str
