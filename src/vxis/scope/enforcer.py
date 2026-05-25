"""Scope Enforcer | 스코프 집행기.

Validates URLs, methods, and request bodies against the loaded ScopeConfig.
"""

from __future__ import annotations

import fnmatch
from typing import Any
from urllib.parse import urlparse

from vxis.scope.schemas import ActionPolicy, ScopeCheckResult, ScopeConfig, PIIDetection
from vxis.scope.pii_detector import PIIDetector


_DESTRUCTIVE_URL_HINTS: dict[str, str] = {
    "delete": "file_deletions",
    "remove": "file_deletions",
    "drop": "database_writes",
    "upload": "file_uploads",
    "send": "email_sending",
    "sms": "sms_sending",
    "mail": "email_sending",
}


class ScopeEnforcer:
    def __init__(self, scope: ScopeConfig) -> None:
        self.scope = scope
        self.pii = PIIDetector()

    # ------------------------------------------------------------------ URL
    def check_url(self, url: str) -> ScopeCheckResult:
        try:
            parsed = urlparse(url)
        except Exception as exc:  # pragma: no cover - defensive
            return ScopeCheckResult(
                allowed=False,
                policy=ActionPolicy.DENY,
                reason=f"invalid url: {exc}",
                risk_level="medium",
            )

        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"

        # Out-of-scope blacklist wins
        for bad in self.scope.out_of_scope:
            if bad and (fnmatch.fnmatch(host, bad) or fnmatch.fnmatch(url, bad)):
                return ScopeCheckResult(
                    allowed=False,
                    policy=ActionPolicy.FORBIDDEN,
                    reason=f"host '{host}' matches out_of_scope rule '{bad}'",
                    rule_matched=bad,
                    risk_level="high",
                )

        # In-scope domains (if list non-empty, host must match)
        if self.scope.in_scope_domains:
            host_ok = False
            for dom in self.scope.in_scope_domains:
                pattern = dom.lower()
                if pattern.startswith("*."):
                    suffix = pattern[2:]
                    if host == suffix or host.endswith("." + suffix):
                        host_ok = True
                        break
                if fnmatch.fnmatch(host, pattern):
                    host_ok = True
                    break
            if not host_ok:
                return ScopeCheckResult(
                    allowed=False,
                    policy=ActionPolicy.DENY,
                    reason=f"host '{host}' not in in_scope_domains",
                    risk_level="medium",
                )

        # Path rules — deny first, then allow
        deny_rules = self.scope.path_rules.get("deny", []) or []
        for rule in deny_rules:
            if fnmatch.fnmatch(path, rule):
                return ScopeCheckResult(
                    allowed=False,
                    policy=ActionPolicy.DENY,
                    reason=f"path '{path}' matches deny rule '{rule}'",
                    rule_matched=rule,
                    risk_level="medium",
                )

        allow_rules = self.scope.path_rules.get("allow", []) or []
        if allow_rules:
            allowed = any(fnmatch.fnmatch(path, rule) for rule in allow_rules)
            if not allowed:
                return ScopeCheckResult(
                    allowed=False,
                    policy=ActionPolicy.DENY,
                    reason=f"path '{path}' not matched by any allow rule",
                    risk_level="low",
                )

        return ScopeCheckResult(
            allowed=True,
            policy=ActionPolicy.ALLOW,
            reason="url within scope",
            risk_level="low",
        )

    # --------------------------------------------------------------- Action
    def check_action(
        self,
        method: str,
        url: str,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> ScopeCheckResult:
        method_up = (method or "GET").upper()

        url_result = self.check_url(url)
        if not url_result.allowed:
            return url_result

        # HTTP methods — deny first, then allow
        deny_methods = [m.upper() for m in (self.scope.http_methods.get("deny") or [])]
        if method_up in deny_methods:
            return ScopeCheckResult(
                allowed=False,
                policy=ActionPolicy.FORBIDDEN,
                reason=f"method '{method_up}' denied by scope",
                rule_matched=method_up,
                risk_level="high",
            )
        allow_methods = [m.upper() for m in (self.scope.http_methods.get("allow") or [])]
        if allow_methods and method_up not in allow_methods:
            return ScopeCheckResult(
                allowed=False,
                policy=ActionPolicy.DENY,
                reason=f"method '{method_up}' not in allowlist",
                risk_level="medium",
            )

        # Destructive heuristics
        concerns: list[str] = []
        haystack = url.lower()
        if body:
            try:
                haystack += " " + str(body).lower()
            except Exception:
                pass

        triggered_kinds: set[str] = set()
        for hint, kind in _DESTRUCTIVE_URL_HINTS.items():
            if hint in haystack:
                triggered_kinds.add(kind)

        # DELETE method maps to deletions
        if method_up == "DELETE":
            triggered_kinds.add("file_deletions")

        worst: ActionPolicy = ActionPolicy.ALLOW
        risk = "low"
        for kind in triggered_kinds:
            policy_str = (self.scope.destructive_actions or {}).get(kind, "allow")
            concerns.append(f"{kind}:{policy_str}")
            if policy_str == "forbidden":
                return ScopeCheckResult(
                    allowed=False,
                    policy=ActionPolicy.FORBIDDEN,
                    reason=f"destructive action '{kind}' is forbidden",
                    rule_matched=kind,
                    concerns=concerns,
                    risk_level="critical",
                )
            if policy_str == "approval_required":
                worst = ActionPolicy.APPROVAL_REQUIRED
                risk = "high"

        if worst == ActionPolicy.APPROVAL_REQUIRED:
            return ScopeCheckResult(
                allowed=False,
                policy=ActionPolicy.APPROVAL_REQUIRED,
                reason="destructive action requires approval",
                concerns=concerns,
                requires_approval=True,
                risk_level=risk,
            )

        return ScopeCheckResult(
            allowed=True,
            policy=ActionPolicy.ALLOW,
            reason="action permitted",
            concerns=concerns,
            risk_level=risk,
        )

    # ------------------------------------------------------------------ Data
    def check_data(self, response_body: str, content_type: str = "") -> PIIDetection:
        detection = self.pii.scan(response_body or "")
        sensitivity = (self.scope.data_sensitivity or {}).get("pii_read", "detect_and_redact")
        if not detection.found:
            return detection
        if sensitivity == "detect_only":
            # Keep raw text, but still report
            return PIIDetection(
                found=True,
                types=detection.types,
                matches=detection.matches,
                redacted_text=response_body or "",
            )
        # default → detect_and_redact (already redacted)
        return detection
