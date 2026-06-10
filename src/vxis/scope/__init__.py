"""VXIS Scope Enforcement Layer.

Bilingual: Scope rules and PII safeguards | 스코프 규칙 및 PII 보호.
"""

from vxis.scope.schemas import (
    ActionPolicy,
    ScopeConfig,
    ScopeCheckResult,
    PIIDetection,
)
from vxis.scope.loader import load_scope, ScopeLoader
from vxis.scope.enforcer import ScopeEnforcer
from vxis.scope.pii_detector import PIIDetector
from vxis.scope.audit import AuditLog
from vxis.scope.runtime_gate import (
    ScopeGateDecision,
    clear_active_scope,
    enforce_scope_invocation,
    ensure_active_scope,
    set_active_scope,
)

__all__ = [
    "ActionPolicy",
    "ScopeConfig",
    "ScopeCheckResult",
    "PIIDetection",
    "ScopeLoader",
    "load_scope",
    "ScopeEnforcer",
    "PIIDetector",
    "AuditLog",
    "ScopeGateDecision",
    "clear_active_scope",
    "enforce_scope_invocation",
    "ensure_active_scope",
    "set_active_scope",
]
