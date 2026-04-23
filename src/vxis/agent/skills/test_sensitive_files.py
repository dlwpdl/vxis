"""Skill: test_sensitive_files — scan for exposed files, configs, backups."""
from __future__ import annotations
import asyncio
import logging
from typing import Any
from ._payload_loader import load_skill_dataset as _load_ds

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = [tuple(_c) for _c in _load_ds("test_sensitive_files", "sensitive_paths")]  # ADR-007 Phase 3-9 — data in data/payloads/test_sensitive_files.json


def _adjust_severity(path: str, body: str, declared: str) -> tuple[str, str | None]:
    """Content-aware severity adjustment.

    Many defaults (Spring Boot /actuator/env with sanitized "******" values,
    empty Prometheus /metrics, etc.) are flagged as critical in the static
    list but carry far less risk in practice. This looks at the actual
    response body to downgrade when appropriate and upgrade when we spot
    unsanitized secrets.

    Returns (severity, note). note is a short reason string or None.
    """
    lo = body.lower() if body else ""
    # Spring Boot actuator env — downgrade when all values are masked
    if path.startswith("/actuator/env"):
        if "******" in body and ('"value":"******"' in body or ": '******'" in body):
            # Count non-masked values. If everything sensitive-looking is
            # masked, this is informational.
            masked_ratio = body.count('"******"') / max(body.count('"value":') or 1, 1)
            if masked_ratio > 0.6:
                return ("low", "values masked by Spring Boot sanitizer")
        # Look for raw secrets anyway
        for needle in ("secret", "password", "jdbc:", "mongodb://", "postgres://"):
            if needle in lo and "******" not in lo.split(needle, 1)[-1][:40]:
                return ("critical", f"unmasked {needle} leaked in env")
        return (declared, None)

    # Spring Boot actuator root / health — low unless extra endpoints exposed
    if path == "/actuator/" or path == "/actuator":
        risky = ("heapdump", "threaddump", "mappings", "beans", "configprops")
        if any(x in lo for x in risky):
            return ("high", "risky actuator endpoints enumerable")
        return ("low", "only safe actuator links")
    if path == "/actuator/health":
        if '"status":"up"' in lo and len(body) < 50:
            return ("informational", "health check only")
        return (declared, None)

    # .env — confirm it actually looks like env vars rather than a generic 200
    if path in ("/.env", "/.env.bak"):
        if "=" not in body[:1000] or "<html" in lo:
            return ("low", "not a real env file")
        return (declared, None)

    # /metrics — downgrade empty/tiny responses
    if path == "/metrics" and len(body) < 200:
        return ("low", "metrics endpoint nearly empty")

    # robots/sitemap/security.txt — already informational in the list

    return (declared, None)


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Scan for sensitive files and configurations.

    Returns:
        {
            "exposed": [{"path", "severity", "description", "status", "size", "preview"}, ...],
            "total_scanned": int,
        }
    """
    from vxis.interaction.hands import SessionManager

    target = target_url.rstrip("/")
    exposed: list[dict] = []
    baseline_size: int | None = kwargs.get("baseline_size")

    _mgr = SessionManager()
    _session = await _mgr.get_session(target)

    if baseline_size is None:
        try:
            r = await _session.request("GET", "/definitely-not-real-probe")
            if r.status == 200:
                baseline_size = r.body_length
        except Exception:
            pass

    sem = asyncio.Semaphore(20)

    async def check(path: str, severity: str, description: str) -> None:
        async with sem:
            try:
                r = await _session.request("GET", path)
                size = r.body_length
                if r.status == 404 or (baseline_size and size == baseline_size):
                    return
                if r.status == 200 and size > 50:
                    body = r.text
                    final_sev, note = _adjust_severity(path, body, severity)
                    entry = {
                        "path": path,
                        "severity": final_sev,
                        "description": description + (f" [{note}]" if note else ""),
                        "status": r.status,
                        "size": size,
                        "preview": body[:300],
                    }
                    if note:
                        entry["severity_note"] = note
                        entry["original_severity"] = severity
                    exposed.append(entry)
            except Exception:
                pass

    await asyncio.gather(*[check(p, s, d) for p, s, d in SENSITIVE_PATHS])

    exposed.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(x["severity"], 5))

    logger.info("test_sensitive_files: %d exposed out of %d scanned", len(exposed), len(SENSITIVE_PATHS))
    return {"exposed": exposed, "total_scanned": len(SENSITIVE_PATHS)}
