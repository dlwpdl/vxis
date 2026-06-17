"""Persisted env store for API keys (no extra dependency).

Keys entered in the TUI live only in the process env and vanish on exit, so the
operator had to re-type them every run. This stores them in ``~/.vxis/.env``
(0600) and loads them at CLI startup WITHOUT overriding anything already set in
the real environment — so an explicit env var / CI secret always wins.
"""
from __future__ import annotations

import os
from pathlib import Path


def _default_path() -> Path:
    override = os.environ.get("VXIS_ENV_STORE", "").strip()
    if override:
        return Path(override)
    return Path(os.path.expanduser("~/.vxis/.env"))


def upsert_env(key: str, value: str, path: Path | None = None) -> Path:
    """Upsert ``KEY=value`` into the env store (created 0600). Updates an existing
    key in place and preserves other lines. Also sets it live in os.environ."""
    p = path or _default_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = p.read_text(encoding="utf-8").splitlines() if p.exists() else []
    prefix = f"{key}="
    for i, ln in enumerate(lines):
        if ln.strip().startswith(prefix):
            lines[i] = f"{key}={value}"
            break
    else:
        lines.append(f"{key}={value}")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    os.environ[key] = value
    return p


def load_env(path: Path | None = None, *, override: bool = False) -> dict[str, str]:
    """Load ``KEY=value`` lines into os.environ. By default does NOT override keys
    already present in the environment. Returns the dict of parsed pairs. Never
    raises (missing/unreadable file → empty)."""
    p = path or _default_path()
    loaded: dict[str, str] = {}
    try:
        if not p.exists():
            return loaded
        for raw in p.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if not key:
                continue
            loaded[key] = value
            if override or key not in os.environ:
                os.environ[key] = value
    except OSError:
        pass
    return loaded


__all__ = ["upsert_env", "load_env"]
