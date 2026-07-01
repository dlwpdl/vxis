"""Dashboard session-based user authentication.

Provides a minimal cookie-session layer on top of the existing token
middleware.  Sessions are signed with an HMAC derived from
``VXIS_SESSION_SECRET`` (or a generated runtime secret) so the cookie
cannot be forged.

This module is intentionally dependency-free — it uses only stdlib
``hashlib`` / ``hmac`` and SQLAlchemy models that already ship with VXIS.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from functools import wraps
from typing import Awaitable, Callable

from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from vxis.core.db import get_session
from vxis.models.db_models import UserRecord

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SESSION_COOKIE = "vxis_session"
ROLE_LEVELS: dict[str, int] = {"viewer": 1, "reviewer": 2, "admin": 3}

# Runtime fallback secret — regenerated each process start unless
# VXIS_SESSION_SECRET is configured.  Sessions therefore survive across
# requests in one process but not across restarts (good enough for the
# minimal happy path).
_RUNTIME_SECRET = secrets.token_hex(32)


def _secret() -> str:
    return os.environ.get("VXIS_SESSION_SECRET") or _RUNTIME_SECRET


# ---------------------------------------------------------------------------
# Password hashing — stdlib only (PBKDF2-HMAC-SHA256)
# ---------------------------------------------------------------------------


def hash_password(password: str, *, salt: str | None = None) -> str:
    """Hash *password* with PBKDF2-HMAC-SHA256.

    Returned format: ``"<salt_hex>$<hash_hex>"``.
    """
    salt_bytes = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt_bytes, 100_000
    )
    return f"{salt_bytes.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(stored, hash_password(password, salt=salt_hex))


# ---------------------------------------------------------------------------
# Session cookies — signed user_id payload
# ---------------------------------------------------------------------------


def _sign(payload: str) -> str:
    return hmac.new(
        _secret().encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def make_session_token(user_id: int) -> str:
    payload = str(user_id)
    return f"{payload}.{_sign(payload)}"


def parse_session_token(token: str) -> int | None:
    if not token or "." not in token:
        return None
    payload, sig = token.rsplit(".", 1)
    if not hmac.compare_digest(sig, _sign(payload)):
        return None
    try:
        return int(payload)
    except ValueError:
        return None


def set_session_cookie(response: Response, user_id: int) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        make_session_token(user_id),
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")


# ---------------------------------------------------------------------------
# current_user / role check
# ---------------------------------------------------------------------------


async def current_user(request: Request) -> UserRecord | None:
    """Resolve the user from the session cookie, or ``None`` if anonymous."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    user_id = parse_session_token(token)
    if user_id is None:
        return None

    engine = getattr(request.app.state, "engine", None)
    if engine is None:
        from vxis.dashboard.app import _engine  # type: ignore

        engine = _engine

    async with get_session(engine) as session:
        result = await session.execute(
            select(UserRecord).where(UserRecord.id == user_id)
        )
        return result.scalar_one_or_none()


def _role_ok(user: UserRecord | None, required: str) -> bool:
    if user is None:
        return False
    return ROLE_LEVELS.get(user.role, 0) >= ROLE_LEVELS.get(required, 99)


def require_role(required: str) -> Callable:
    """Decorator: enforce a minimum role on a FastAPI route.

    The decorated function MUST accept ``request: Request`` as its first
    parameter.  Anonymous users are redirected to ``/login``; authenticated
    users with insufficient privileges receive a 403 response.
    """

    def decorator(
        fn: Callable[..., Awaitable[Response]],
    ) -> Callable[..., Awaitable[Response]]:
        @wraps(fn)
        async def wrapper(request: Request, *args, **kwargs):  # type: ignore[no-untyped-def]
            user = await current_user(request)
            if user is None:
                return RedirectResponse(url="/login", status_code=303)
            if not _role_ok(user, required):
                return Response("Forbidden", status_code=403)
            kwargs["user"] = user
            return await fn(request, *args, **kwargs)

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# Seed helper
# ---------------------------------------------------------------------------


async def ensure_default_admin(
    engine,
    password: str | None = None,
) -> UserRecord | None:  # type: ignore[no-untyped-def]
    """Create the first admin only when an explicit password is provided."""
    password = password or os.environ.get("VXIS_DASHBOARD_ADMIN_PASSWORD")
    if not password:
        return None

    async with get_session(engine) as session:
        existing = (await session.execute(select(UserRecord))).scalars().first()
        if existing is not None:
            return None
        admin = UserRecord(
            username="admin",
            email=None,
            role="admin",
            password_hash=hash_password(password),
        )
        session.add(admin)
        await session.flush()
        return admin
