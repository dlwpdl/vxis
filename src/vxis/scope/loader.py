"""Scope loader | 스코프 로더.

Priority:
  1. --scope CLI flag (scope_arg path)
  2. ./vxis-scope.json
  3. ~/.vxis/scopes/<target_hostname>.json
  4. ~/.vxis/scopes/default.json
  5. Safe default (all destructive forbidden)
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

from vxis.scope.schemas import ScopeConfig

DEFAULT_SCOPE_LOCATIONS: list[Path] = [
    Path.cwd() / "vxis-scope.json",
    Path.home() / ".vxis" / "scopes" / "default.json",
]


def _safe_default() -> ScopeConfig:
    """Conservative default — approval required for everything risky."""
    return ScopeConfig(
        scan_id="",
        target="",
        in_scope_domains=[],
        out_of_scope=[],
        path_rules={"allow": ["/*"], "deny": []},
        http_methods={"allow": ["GET", "POST", "PUT", "PATCH"], "deny": ["DELETE"]},
        data_sensitivity={
            "pii_read": "detect_and_redact",
            "pii_exfil": "forbidden",
            "financial_data": "forbidden",
            "credentials": "detect_only",
            "phi": "forbidden",
            "max_records_per_query": 10,
        },
        account_rules={
            "create_test_accounts": "approval_required",
            "use_real_user_credentials": "forbidden",
            "credential_stuffing": "forbidden",
        },
        destructive_actions={
            "database_writes": "approval_required",
            "file_uploads": "approval_required",
            "file_deletions": "forbidden",
            "email_sending": "forbidden",
            "sms_sending": "forbidden",
        },
        time_window={"allowed_hours": "00:00-23:59", "timezone": "UTC"},
        rate_limits={"max_rps": 10, "max_concurrent": 5, "max_total_requests": 100000},
        audit={"log_all_requests": True},
    )


def _from_dict(data: dict) -> ScopeConfig:
    base = _safe_default()
    return ScopeConfig(
        scan_id=data.get("scan_id", base.scan_id),
        target=data.get("target", base.target),
        in_scope_domains=data.get("in_scope_domains", base.in_scope_domains),
        out_of_scope=data.get("out_of_scope", base.out_of_scope),
        path_rules=data.get("path_rules", base.path_rules),
        http_methods=data.get("http_methods", base.http_methods),
        data_sensitivity=data.get("data_sensitivity", base.data_sensitivity),
        account_rules=data.get("account_rules", base.account_rules),
        destructive_actions=data.get("destructive_actions", base.destructive_actions),
        time_window=data.get("time_window", base.time_window),
        rate_limits=data.get("rate_limits", base.rate_limits),
        audit=data.get("audit", base.audit),
    )


def _read_json(path: Path) -> ScopeConfig | None:
    try:
        if path.is_file():
            with open(path, "r", encoding="utf-8") as f:
                return _from_dict(json.load(f))
    except (OSError, json.JSONDecodeError):
        return None
    return None


def load_scope(scope_arg: str | None, target: str) -> ScopeConfig:
    """Load scope using priority chain. Falls back to safe default."""
    # 1. CLI explicit
    if scope_arg:
        cfg = _read_json(Path(scope_arg).expanduser())
        if cfg is not None:
            if not cfg.target:
                cfg.target = target
            return cfg

    # 2. Project local
    cfg = _read_json(Path.cwd() / "vxis-scope.json")
    if cfg is not None:
        if not cfg.target:
            cfg.target = target
        return cfg

    # 3. Per-host user fallback
    try:
        host = urlparse(target).hostname or ""
    except Exception:
        host = ""
    if host:
        cfg = _read_json(Path.home() / ".vxis" / "scopes" / f"{host}.json")
        if cfg is not None:
            if not cfg.target:
                cfg.target = target
            return cfg

    # 4. User default
    cfg = _read_json(Path.home() / ".vxis" / "scopes" / "default.json")
    if cfg is not None:
        if not cfg.target:
            cfg.target = target
        return cfg

    # 5. Safe default
    safe = _safe_default()
    safe.target = target
    return safe


class ScopeLoader:
    """OOP wrapper around load_scope for DI / testing."""

    def __init__(self, scope_arg: str | None = None) -> None:
        self.scope_arg = scope_arg

    def load(self, target: str) -> ScopeConfig:
        return load_scope(self.scope_arg, target)

    @staticmethod
    def safe_default() -> ScopeConfig:
        return _safe_default()
