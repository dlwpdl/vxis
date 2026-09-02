"""Skill: enumerate_endpoints — blast common paths, return accessible ones."""

from __future__ import annotations
import asyncio
import logging
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

# 120+ common web paths — covers REST APIs, admin panels, configs, debug endpoints
COMMON_PATHS = _load_ds(
    "enumerate_endpoints", "common_paths"
)  # ADR-007 Phase 3-9 — data in data/payloads/enumerate_endpoints.json

_ACTIONABLE_ERROR_MARKERS = (
    "traceback",
    "stack trace",
    "exception:",
    "undefined",
    "cannot read",
)
_SQL_ERROR_MARKERS = (
    "sql error",
    "sql syntax",
    "sqlite",
    "mysql",
    "postgres",
    "psql",
    "ora-",
    "syntax error",
    "sequelize",
    "typeorm",
    "prisma",
    "jdbc:",
    "sqlstate",
)
_NOISY_ERROR_MARKERS = {
    "unexpected_path": ("unexpected path:",),
    "illegal_activity_block": ("blocked illegal activity by",),
}


def preview_has_sql_error_signal(preview: str) -> bool:
    lower = str(preview or "").lower()
    return bool(lower) and any(marker in lower for marker in _SQL_ERROR_MARKERS)


def classify_endpoint_error_preview(preview: str) -> str:
    lower = str(preview or "").lower()
    if not lower:
        return "unknown"
    for label, markers in _NOISY_ERROR_MARKERS.items():
        if any(marker in lower for marker in markers):
            return label
    if preview_has_sql_error_signal(preview) or any(
        marker in lower for marker in _ACTIONABLE_ERROR_MARKERS
    ):
        return "actionable"
    return "unknown"


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Enumerate all accessible endpoints on a target.

    Returns:
        {
            "accessible": [{"path": "/api/Users/", "status": 200, "size": 1234}, ...],
            "auth_required": [{"path": ..., "status": 401}, ...],
            "errors": [{"path": ..., "status": 500, "error_kind": "actionable|unknown"}, ...],
            "noise_errors": [{"path": ..., "status": 500, "error_kind": "unexpected_path|illegal_activity_block"}, ...],
            "total_scanned": int,
            "baseline_size": int | None,
        }
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    accessible: list[dict] = []
    auth_required: list[dict] = []
    errors: list[dict] = []
    noise_errors: list[dict] = []
    baseline_size: int | None = None

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)

    # Detect SPA baseline
    try:
        r = await _session.request("GET", "/definitely-not-real-xyz-probe")
        if r.status == 200:
            baseline_size = r.body_length
    except Exception:
        pass

    # Blast all paths concurrently (batches of 20)
    sem = asyncio.Semaphore(20)

    async def check(path: str) -> None:
        async with sem:
            try:
                r = await _session.request("GET", path)
                size = r.body_length
                # Skip SPA baseline responses
                if baseline_size and size == baseline_size:
                    return
                if r.status == 404:
                    return

                entry: dict[str, object] = {"path": path, "status": r.status, "size": size}
                if r.status == 200:
                    # Include a body preview for interesting responses
                    if size > 100:
                        entry["preview"] = r.text[:200]
                    accessible.append(entry)
                elif r.status == 401:
                    auth_required.append(entry)
                elif r.status == 500:
                    entry["error_preview"] = r.text[:200]
                    entry["error_kind"] = classify_endpoint_error_preview(
                        str(entry["error_preview"])
                    )
                    if entry["error_kind"] in _NOISY_ERROR_MARKERS:
                        noise_errors.append(entry)
                    else:
                        errors.append(entry)
                elif r.status in (301, 302, 303, 307, 308):
                    entry["redirect"] = r.headers.get("location", "")
                    accessible.append(entry)
            except Exception:
                pass

    await asyncio.gather(*[check(p) for p in COMMON_PATHS])

    # Sort by size descending (bigger = more interesting)
    accessible.sort(key=lambda x: x["size"], reverse=True)
    errors.sort(key=lambda x: x["size"], reverse=True)
    noise_errors.sort(key=lambda x: x["size"], reverse=True)

    logger.info(
        "enumerate_endpoints: %d accessible, %d auth-required, %d errors, %d noisy-500s suppressed",
        len(accessible),
        len(auth_required),
        len(errors),
        len(noise_errors),
    )

    return {
        "accessible": accessible,
        "auth_required": auth_required,
        "errors": errors,
        "noise_errors": noise_errors,
        "total_scanned": len(COMMON_PATHS),
        "baseline_size": baseline_size,
    }
