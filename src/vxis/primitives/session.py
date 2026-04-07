"""Session primitives — authenticated HTTP session lifecycle.

Thin wrapper around vxis.interaction.hands.SessionManager. No LLM calls.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from vxis.interaction.hands import SessionManager

from vxis.primitives import sensing as _sensing

logger = logging.getLogger(__name__)


def _mgr() -> SessionManager:
    return _sensing._get_manager()  # noqa: SLF001 — intentional reuse


def _sid(target: str) -> str:
    return urlparse(target).netloc or target


async def session_create(
    target: str,
    auth_type: str = "anonymous",
    credentials: dict | None = None,
) -> str:
    """Create a new session for a target and return its session id.

    Args:
        target: Base URL.
        auth_type: "anonymous", "basic", "form", "bearer".
        credentials: For basic/form: {"username":..., "password":...},
                     for bearer: {"token":...}, login_url optional.

    Returns:
        Session id (stable per target host).
    """
    mgr = _mgr()
    session = await mgr.get_session(target)
    sid = _sid(target)
    _sensing._session_cache[sid] = session  # noqa: SLF001

    creds = credentials or {}
    auth = (auth_type or "anonymous").lower()

    if auth == "anonymous":
        return sid

    if auth == "basic":
        import base64

        u = creds.get("username", "")
        p = creds.get("password", "")
        token = base64.b64encode(f"{u}:{p}".encode()).decode()
        try:
            session._client.headers["Authorization"] = f"Basic {token}"  # noqa: SLF001
        except Exception as exc:
            logger.warning("basic auth header injection failed: %s", exc)
        return sid

    if auth == "bearer":
        token = creds.get("token", "")
        try:
            session._client.headers["Authorization"] = f"Bearer {token}"  # noqa: SLF001
        except Exception as exc:
            logger.warning("bearer header injection failed: %s", exc)
        return sid

    if auth == "form":
        login_url = creds.get("login_url", "/login")
        data = {
            k: v
            for k, v in creds.items()
            if k not in ("login_url",)
        }
        try:
            await session.login(url=login_url, data=data)
        except Exception as exc:
            logger.warning("form login failed: %s", exc)
        return sid

    return sid


async def session_get(target: str) -> str:
    """Return a session id for the target, creating one if needed."""
    sid = _sid(target)
    if sid in _sensing._session_cache:  # noqa: SLF001
        return sid
    mgr = _mgr()
    session = await mgr.get_session(target)
    _sensing._session_cache[sid] = session  # noqa: SLF001
    return sid


async def session_list() -> list[dict]:
    """Return a list of active sessions with their auth state."""
    mgr = _mgr()
    out: list[dict] = []
    for url, state in mgr.active_sessions.items():
        out.append(
            {
                "session_id": url,
                "target": url,
                "auth_state": state.name if hasattr(state, "name") else str(state),
            }
        )
    return out


async def session_close(session_id: str) -> bool:
    """Close a specific session by id."""
    mgr = _mgr()
    cached = _sensing._session_cache.pop(session_id, None)  # noqa: SLF001
    base_url = cached.base_url if cached else f"http://{session_id}"
    try:
        await mgr.close_session(base_url)
        return True
    except Exception as exc:
        logger.debug("session_close failed: %s", exc)
        return False
