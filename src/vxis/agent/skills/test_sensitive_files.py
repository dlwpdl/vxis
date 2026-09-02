"""Skill: test_sensitive_files — scan for exposed files, configs, backups."""
from __future__ import annotations
import asyncio
import logging
import re
from typing import Any
from urllib.parse import urljoin, urlparse
from ._payload_loader import load_skill_dataset as _load_ds
from .test_infra import _seeded_git_env_paths

logger = logging.getLogger(__name__)

SENSITIVE_PATHS = [tuple(_c) for _c in _load_ds("test_sensitive_files", "sensitive_paths")]  # ADR-007 Phase 3-9 — data in data/payloads/test_sensitive_files.json
_HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.IGNORECASE)
_URL_RE = re.compile(r"""https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{6,}""")
_AUTH_PATH_RE = re.compile(
    r"""(?i)(/(?:[A-Za-z0-9_-]+/)*(?:api|auth|rest)[A-Za-z0-9_./-]{0,80}(?:login|sign[_-]?in|signin|sessions?|token|forgot|reset|otp|unlock)[A-Za-z0-9_./-]{0,40})"""
)
_KEY_VALUE_RE = re.compile(r"""^\s*([A-Za-z][A-Za-z0-9_.-]{1,63})\s*[:=]\s*(.+?)\s*$""")
_JSON_CRED_RE = re.compile(
    r"""(?is)["'](email|username|user)["']\s*[:=]\s*["']([^"' \t\r\n,}]{3,120})["'].{0,160}?["'](password|pass|pwd)["']\s*[:=]\s*["']([^"'\r\n]{1,120})["']"""
)
_JSON_RESET_RE = re.compile(
    r"""(?is)["'](email|username|user)["']\s*[:=]\s*["']([^"' \t\r\n,}]{3,120})["'].{0,240}?["']([A-Za-z0-9_.-]*answer[A-Za-z0-9_.-]*)["']\s*[:=]\s*["']([^"'\r\n]{1,120})["']"""
)
_LISTING_MARKERS = ("listing directory", "index of")
_AUTH_IDENTITY_MARKERS = ("email", "username", "user", "login", "account", "admin")
_AUTH_PASSWORD_MARKERS = ("password", "pass", "pwd")
_RESET_ANSWER_MARKERS = (
    "answer",
    "securityanswer",
    "security_answer",
    "challengeanswer",
    "challenge_answer",
    "secretanswer",
    "secret_answer",
)
_INFRA_CRED_MARKERS = ("db", "mongo", "mysql", "postgres", "pgsql", "jdbc", "redis", "smtp", "kafka")
_ARTIFACT_EXTENSIONS = (
    ".bak",
    ".kdbx",
    ".sql",
    ".zip",
    ".db",
    ".sqlite",
    ".md",
    ".pdf",
)
_SECRET_EXTENSIONS = (".key", ".pem", ".p12", ".jks")
_CONFIG_EXTENSIONS = (".json", ".yml", ".yaml", ".properties", ".conf", ".config", ".env")
_FOLLOWUP_NAME_MARKERS = (
    "log",
    "audit",
    "incident",
    "support",
    "config",
    "env",
    "secret",
    "token",
    "credential",
    "auth",
    "key",
    "backup",
    "dump",
)
_LOGIN_PATH_MARKERS = ("login", "sign-in", "sign_in", "signin", "session", "token")
_RESET_PATH_MARKERS = ("forgot", "reset", "otp", "unlock")
_CROWN_SIGNAL_MARKERS = (
    "ftp",
    "log",
    "audit",
    "key",
    "secret",
    "token",
    "credential",
    "env",
    "config",
    "backup",
    "dump",
    "git",
    "passwd",
    "encryption",
)


def _normalize_path(path: str) -> str:
    cleaned = str(path or "").strip()
    if not cleaned:
        return ""
    if "://" in cleaned:
        cleaned = urlparse(cleaned).path or "/"
    if not cleaned.startswith("/"):
        cleaned = f"/{cleaned.lstrip('/')}"
    return cleaned.split("#", 1)[0].split("?", 1)[0]


def _looks_directory_listing(path: str, body: str) -> bool:
    lower = body.lower() if body else ""
    return path.endswith("/") or any(marker in lower for marker in _LISTING_MARKERS)


def _extract_directory_children(path: str, body: str) -> list[str]:
    children: list[str] = []
    seen: set[str] = set()
    base = path or "/"
    base_name = base.rstrip("/").rsplit("/", 1)[-1]
    for match in _HREF_RE.finditer(body or ""):
        href = str(match.group(1) or "").strip()
        if not href or href in {".", "./", "..", "./.."} or href.startswith("?") or "://" in href:
            continue
        resolved_base = base
        resolved_href = href
        if not resolved_base.endswith("/"):
            resolved_base = f"{resolved_base}/"
            if base_name and resolved_href.rstrip("/") == base_name:
                continue
            if base_name and resolved_href.startswith(f"{base_name}/"):
                resolved_href = resolved_href[len(base_name) + 1 :]
        if not resolved_href:
            continue
        child = _normalize_path(urljoin(resolved_base, resolved_href))
        if not child or child == path or child in seen:
            continue
        seen.add(child)
        children.append(child)
    return children[:24]


def _extract_urls(body: str) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for match in _URL_RE.finditer(body or ""):
        url = str(match.group(0) or "").strip().rstrip('\'"),.;')
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls[:20]


def _extract_internal_auth_paths(body: str) -> list[str]:
    seen: set[str] = set()
    paths: list[str] = []
    for match in _AUTH_PATH_RE.finditer(body or ""):
        prefix = body[max(0, match.start() - 8) : match.start()]
        if "://" in prefix or prefix.endswith("//"):
            continue
        path = _normalize_path(str(match.group(1) or "").rstrip('\'"),.;'))
        if not path or path in seen:
            continue
        seen.add(path)
        paths.append(path)
    return paths[:12]


def _is_auth_identity_key(key: str) -> bool:
    lower = str(key or "").lower()
    return any(marker in lower for marker in _AUTH_IDENTITY_MARKERS) and not any(
        marker in lower for marker in _INFRA_CRED_MARKERS
    )


def _is_auth_password_key(key: str) -> bool:
    lower = str(key or "").lower()
    return any(marker in lower for marker in _AUTH_PASSWORD_MARKERS) and not any(
        marker in lower for marker in _INFRA_CRED_MARKERS
    )


def _is_reset_answer_key(key: str) -> bool:
    lower = str(key or "").lower()
    return any(marker == lower or marker in lower for marker in _RESET_ANSWER_MARKERS) and not any(
        marker in lower for marker in _INFRA_CRED_MARKERS
    )


def _extract_auth_credentials(body: str) -> list[dict[str, str]]:
    credentials: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(identity_key: str, identity_value: str, password: str) -> None:
        ident = str(identity_value or "").strip().strip("\"'")
        secret = str(password or "").strip().strip("\"'")
        if not ident or not secret or len(secret) > 160:
            return
        payload: dict[str, str] = {"password": secret}
        if "@" in ident or "email" in identity_key.lower():
            payload["email"] = ident
        else:
            payload["username"] = ident
        key = (
            payload.get("email") or payload.get("username") or "",
            payload["password"],
            "email" if payload.get("email") else "username",
        )
        if key in seen:
            return
        seen.add(key)
        credentials.append(payload)

    key_values: dict[str, str] = {}
    for line in (body or "").splitlines()[:120]:
        match = _KEY_VALUE_RE.match(line)
        if not match:
            continue
        key = str(match.group(1) or "").strip()
        value = str(match.group(2) or "").strip().strip("\"'")
        if key and value:
            key_values[key] = value
    identities = [(key, value) for key, value in key_values.items() if _is_auth_identity_key(key)]
    passwords = [(key, value) for key, value in key_values.items() if _is_auth_password_key(key)]
    for identity_key, identity_value in identities[:4]:
        for _password_key, password in passwords[:4]:
            add(identity_key, identity_value, password)

    for match in _JSON_CRED_RE.finditer(body or ""):
        add(str(match.group(1) or ""), str(match.group(2) or ""), str(match.group(4) or ""))
    return credentials[:8]


def _extract_reset_candidates(body: str) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    def add(identity_key: str, identity_value: str, answer: str) -> None:
        ident = str(identity_value or "").strip().strip("\"'")
        secret = str(answer or "").strip().strip("\"'")
        if not ident or not secret or len(secret) > 160:
            return
        payload: dict[str, str] = {"answer": secret}
        if "@" in ident or "email" in identity_key.lower():
            payload["email"] = ident
        else:
            payload["username"] = ident
        key = (
            payload.get("email") or payload.get("username") or "",
            payload["answer"],
            "email" if payload.get("email") else "username",
        )
        if key in seen:
            return
        seen.add(key)
        candidates.append(payload)

    key_values: dict[str, str] = {}
    for line in (body or "").splitlines()[:120]:
        match = _KEY_VALUE_RE.match(line)
        if not match:
            continue
        key = str(match.group(1) or "").strip()
        value = str(match.group(2) or "").strip().strip("\"'")
        if key and value:
            key_values[key] = value
    identities = [(key, value) for key, value in key_values.items() if _is_auth_identity_key(key)]
    answers = [(key, value) for key, value in key_values.items() if _is_reset_answer_key(key)]
    for identity_key, identity_value in identities[:4]:
        for _answer_key, answer in answers[:4]:
            add(identity_key, identity_value, answer)

    for match in _JSON_RESET_RE.finditer(body or ""):
        add(str(match.group(1) or ""), str(match.group(2) or ""), str(match.group(4) or ""))
    return candidates[:8]


def _loot_items_for_path(path: str, body: str = "") -> list[dict[str, str]]:
    lower_path = path.lower()
    lower_body = body.lower() if body else ""
    items: list[dict[str, str]] = []
    if lower_path.endswith(_ARTIFACT_EXTENSIONS):
        items.append({"kind": "artifact", "path": path})
    if lower_path.endswith(_CONFIG_EXTENSIONS) or re.search(r"^[A-Z_]+=.+", body or "", re.MULTILINE):
        items.append({"kind": "config", "path": path})
    if (
        lower_path.endswith(_SECRET_EXTENSIONS)
        and not lower_path.endswith(".pub")
    ) or "begin private key" in lower_body or (
        any(marker in lower_path for marker in ("token", "secret", "credential"))
        and len(body.strip()) >= 16
    ):
        items.append({"kind": "secret", "path": path})
    return items[:3]


def _is_crown_signal_path(path: str, severity: str) -> bool:
    lower = path.lower()
    if severity in {"critical", "high"}:
        return True
    return any(marker in lower for marker in _CROWN_SIGNAL_MARKERS)


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
    credentials: list[dict[str, str]] = []
    reset_candidates: list[dict[str, str]] = []
    loot: list[dict[str, str]] = []
    urls: list[str] = []
    internal_urls: list[str] = []
    seed_paths: list[str] = []
    login_paths: list[str] = []
    reset_paths: list[str] = []
    secrets: list[dict[str, str]] = []
    baseline_size: int | None = kwargs.get("baseline_size")
    directory_bodies: dict[str, str] = {}
    seen_credentials: set[tuple[str, str, str]] = set()
    seen_reset_candidates: set[tuple[str, str, str]] = set()
    seen_loot: set[tuple[str, str]] = set()
    seen_urls: set[str] = set()
    seen_internal_urls: set[str] = set()
    seen_seed_paths: set[str] = set()
    seen_login_paths: set[str] = set()
    seen_reset_paths: set[str] = set()

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

    def add_seed_path(path: str) -> None:
        normalized = _normalize_path(path)
        if not normalized or normalized in seen_seed_paths:
            return
        seen_seed_paths.add(normalized)
        seed_paths.append(normalized)

        add_internal_url_path(normalized)

    def add_internal_url_path(path: str) -> None:
        normalized = _normalize_path(path)
        if normalized.startswith("/") and normalized not in seen_internal_urls:
            seen_internal_urls.add(normalized)
            internal_urls.append(normalized)

    def add_url(url: str) -> None:
        cleaned = str(url or "").strip()
        if not cleaned or cleaned in seen_urls:
            return
        seen_urls.add(cleaned)
        urls.append(cleaned)

    def add_loot(item: dict[str, str]) -> None:
        kind = str(item.get("kind") or "").strip()
        path = _normalize_path(str(item.get("path") or ""))
        if not kind or not path:
            return
        key = (kind, path)
        if key in seen_loot:
            return
        seen_loot.add(key)
        normalized = {"kind": kind, "path": path}
        loot.append(normalized)
        if kind == "secret":
            secrets.append(normalized)

    def add_login_path(path: str) -> None:
        normalized = _normalize_path(path)
        if not normalized or normalized in seen_login_paths:
            return
        seen_login_paths.add(normalized)
        login_paths.append(normalized)
        add_internal_url_path(normalized)

    def add_reset_path(path: str) -> None:
        normalized = _normalize_path(path)
        if not normalized or normalized in seen_reset_paths:
            return
        seen_reset_paths.add(normalized)
        reset_paths.append(normalized)
        add_internal_url_path(normalized)

    def add_credential(item: dict[str, str], *, source: str) -> None:
        if not isinstance(item, dict):
            return
        identity = str(item.get("email") or item.get("username") or "").strip()
        password = str(item.get("password") or "").strip()
        if not identity or not password:
            return
        key = (
            item.get("email") or item.get("username") or "",
            password,
            "email" if item.get("email") else "username",
        )
        if key in seen_credentials:
            return
        seen_credentials.add(key)
        credentials.append({**item, "source": source})

    def add_reset_candidate(item: dict[str, str], *, source: str) -> None:
        if not isinstance(item, dict):
            return
        identity = str(item.get("email") or item.get("username") or "").strip()
        answer = str(item.get("answer") or "").strip()
        if not identity or not answer:
            return
        key = (
            identity,
            answer,
            "email" if item.get("email") else "username",
        )
        if key in seen_reset_candidates:
            return
        seen_reset_candidates.add(key)
        reset_candidates.append({**item, "source": source})

    def analyze_content(path: str, body: str, *, source: str) -> None:
        for item in _extract_auth_credentials(body):
            add_credential(item, source=source)
        for item in _extract_reset_candidates(body):
            add_reset_candidate(item, source=source)
        for item in _loot_items_for_path(path, body):
            add_loot(item)
        for internal_path in _extract_internal_auth_paths(body):
            lower = internal_path.lower()
            if any(marker in lower for marker in _LOGIN_PATH_MARKERS):
                add_login_path(internal_path)
            if any(marker in lower for marker in _RESET_PATH_MARKERS):
                add_reset_path(internal_path)
        for url in _extract_urls(body):
            add_url(url)

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
                    if not _is_crown_signal_path(path, final_sev):
                        return
                    add_seed_path(path)
                    if _looks_directory_listing(path, body):
                        directory_bodies[path] = body
                        return
                    analyze_content(path, body, source=f"sensitive_file:{path}")
            except Exception:
                pass

    await asyncio.gather(*[check(p, s, d) for p, s, d in SENSITIVE_PATHS])

    followup_queue: list[tuple[str, int]] = []
    queued_paths: set[str] = set()

    def enqueue_followup(path: str, depth: int, *, expand_seeded: bool = True) -> None:
        normalized = _normalize_path(path)
        if not normalized or normalized in queued_paths:
            return
        queued_paths.add(normalized)
        followup_queue.append((normalized, depth))
        add_seed_path(normalized)
        for item in _loot_items_for_path(normalized):
            add_loot(item)
        if not expand_seeded:
            return
        for seeded_path, _signature in _seeded_git_env_paths([normalized]):
            seeded_normalized = _normalize_path(seeded_path)
            add_seed_path(seeded_normalized)
            if (
                seeded_normalized
                and seeded_normalized not in queued_paths
                and len(queued_paths) < 24
            ):
                enqueue_followup(seeded_normalized, min(depth + 1, 2), expand_seeded=False)

    for path, body in directory_bodies.items():
        for child in _extract_directory_children(path, body):
            if any(marker in child.lower() for marker in _FOLLOWUP_NAME_MARKERS) or "." in child.rsplit("/", 1)[-1]:
                enqueue_followup(child, 1)

    while followup_queue and len(queued_paths) <= 24:
        path, depth = followup_queue.pop(0)
        try:
            r = await _session.request("GET", f"{target}{path}")
        except Exception:
            continue
        if r.status != 200 or r.body_length <= 0:
            continue
        body = r.text
        analyze_content(path, body, source=f"sensitive_file:{path}")
        if depth < 2 and _looks_directory_listing(path, body):
            for child in _extract_directory_children(path, body):
                if any(marker in child.lower() for marker in _FOLLOWUP_NAME_MARKERS) or "." in child.rsplit("/", 1)[-1]:
                    enqueue_followup(child, depth + 1)

    exposed.sort(key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}.get(x["severity"], 5))

    logger.info("test_sensitive_files: %d exposed out of %d scanned", len(exposed), len(SENSITIVE_PATHS))
    return {
        "exposed": exposed,
        "credentials": credentials[:10],
        "reset_candidates": reset_candidates[:10],
        "seed_paths": seed_paths[:30],
        "loot": loot[:20],
        "secrets": secrets[:10],
        "urls": urls[:20],
        "internal_urls": internal_urls[:30],
        "login_paths": login_paths[:12],
        "reset_paths": reset_paths[:12],
        "total_scanned": len(SENSITIVE_PATHS),
    }
