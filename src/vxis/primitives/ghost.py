"""Ghost primitives — anonymity layer control.

Thin wrapper over vxis.ghost.layer.GhostLayer and vxis.ghost.verifier.
No LLM calls.
"""

from __future__ import annotations

import logging
import os

from vxis.ghost.layer import ghost_layer

logger = logging.getLogger(__name__)


# Profile → config map. Each profile configures proxy pool source and timing.
GHOST_CONFIG: dict[str, dict] = {
    "off": {
        "proxies_env": None,
        "timing": {"mean": 0.0, "sigma": 0.0, "min_delay": 0.0, "max_delay": 0.0},
    },
    "standard": {
        "proxies_env": "VXIS_PROXY_POOL",
        "timing": {"mean": 3.0, "sigma": 2.0, "min_delay": 0.5, "max_delay": 15.0},
    },
    "stealth": {
        "proxies_env": "VXIS_PROXY_POOL",
        "timing": {"mean": 8.0, "sigma": 4.0, "min_delay": 2.0, "max_delay": 30.0},
    },
    "paranoid": {
        "proxies_env": "VXIS_PROXY_POOL",
        "timing": {"mean": 20.0, "sigma": 8.0, "min_delay": 5.0, "max_delay": 90.0},
    },
}


def ghost_activate(profile: str = "standard") -> dict:
    """Activate the ghost layer with a named profile.

    Reads proxy pool from the configured environment variable (comma-separated URLs).

    Returns:
        dict with keys: active, profile, proxy_count, timing.
    """
    config = GHOST_CONFIG.get(profile) or GHOST_CONFIG["standard"]

    proxies: list[str] = []
    env = config.get("proxies_env")
    env_names = [str(env)] if env else []
    env_names.append("VXIS_GHOST_PROXIES")
    for env_name in env_names:
        raw = os.environ.get(env_name, "")
        proxies.extend(p.strip() for p in raw.split(",") if p.strip())

    ghost_layer.activate(proxy_pool=proxies)

    # Apply timing config if supported.
    timing = config.get("timing") or {}
    try:
        from vxis.ghost.layer import GhostTiming

        ghost_layer._timing = GhostTiming(  # noqa: SLF001
            mean=timing.get("mean", 3.0),
            sigma=timing.get("sigma", 2.0),
            min_delay=timing.get("min_delay", 0.5),
            max_delay=timing.get("max_delay", 15.0),
        )
    except Exception as exc:
        logger.debug("ghost timing config skipped: %s", exc)

    return {
        "active": ghost_layer.is_active(),
        "profile": profile,
        "proxy_count": len(proxies),
        "timing": timing,
    }


async def ghost_verify() -> dict:
    """Verify the currently exposed exit IP through the ghost layer.

    Returns:
        dict with keys: exit_ip, verified, ghost_active, error.
    """
    from vxis.ghost.verifier import GhostVerifier

    verifier = GhostVerifier()
    try:
        result = await verifier.check()
    except Exception as exc:
        return {"exit_ip": None, "verified": False, "ghost_active": ghost_layer.is_active(), "error": str(exc)}

    return {
        "exit_ip": result.get("detected_ip"),
        "verified": result.get("error") is None and bool(result.get("detected_ip")),
        "ghost_active": result.get("ghost_active", False),
        "error": result.get("error"),
    }


def ghost_status() -> dict:
    """Return the current ghost layer status."""
    return {
        "active": ghost_layer.is_active(),
        "proxy_count": len(getattr(ghost_layer, "_proxy_pool", []) or []),
    }


def ghost_deactivate() -> None:
    """Deactivate the ghost layer."""
    ghost_layer.deactivate()
