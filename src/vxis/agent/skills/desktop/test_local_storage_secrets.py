"""Skill: test_local_storage_secrets — phase-J / DESK-LSS-001.

Walks the application bundle (or directory) of a desktop target and
matches each text-readable file against the `_SECRET_PATTERNS` shared
with the X-Ray module (`vxis.interaction.xray._SECRET_PATTERNS`). Any
match becomes a Finding-shaped dict that Brain can promote via the
existing `report_finding` tool.

This is the macOS-first equivalent of `test_sensitive_files`: instead
of probing HTTP paths, we walk the on-disk artefact for the planted
secrets that ship with so many Electron / Sparkle / signed-installer
apps (license keys, Sentry DSNs, segment.io tokens, AWS credentials
in `Resources/`, etc.).

Args:
    target_url: required — path to .app bundle, directory, or single binary.
        For a Mach-O binary, the parent directory is walked. For a .app
        bundle, the whole `Contents/` tree is walked.
    max_files: optional int (default 800) — stop after N files inspected.
    max_bytes: optional int (default 524288) — bytes read per file.

Returns:
    {
      "scanned": int,
      "findings": [
        {"path": "...", "severity": "high|critical", "pattern": "aws_key",
         "snippet": "...", "vector": "DESK-LSS-001"},
        ...
      ],
      "skipped_binary": int,  # files that looked binary and were skipped
    }
"""
from __future__ import annotations

import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)


# Mirrors the patterns x-ray uses for HTTP body inspection. We keep a
# local copy so this skill stays import-light (the xray module pulls in
# mitmproxy on import, which we don't need here).
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern, str], ...] = (
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("aws_secret_key", re.compile(r"(?i)aws.{0,20}?(?:secret|key).{0,20}?[\"'=:]\s*[A-Za-z0-9/+=]{40}"), "critical"),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "critical"),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "high"),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "high"),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"), "critical"),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "high"),
    ("stripe_secret", re.compile(r"sk_live_[A-Za-z0-9]{24,}"), "critical"),
    ("sentry_dsn", re.compile(r"https://[a-f0-9]{32,}@(?:o\d+\.ingest\.)?sentry\.io/\d+"), "medium"),
    ("generic_secret_assignment", re.compile(
        r"(?i)(?:api[_-]?key|secret|password|token)\s*[=:]\s*[\"'][A-Za-z0-9+/=]{16,}[\"']"
    ), "high"),
)


# Paths that almost never carry secrets and waste cycles to read.
_SKIP_DIRS = {
    "node_modules",
    ".git",
    "Frameworks",       # macOS dylib bundles — binary, not text
    "Helpers",          # Electron helper apps
    "PlugIns",
    "_CodeSignature",
}
_SKIP_EXT = {
    ".dylib", ".so", ".o", ".a", ".jpg", ".jpeg", ".png", ".gif",
    ".webp", ".heic", ".mp3", ".mp4", ".mov", ".pdf", ".zip", ".gz",
    ".tar", ".dmg", ".pkg", ".icns", ".woff", ".woff2", ".ttf",
    ".otf", ".bin", ".dat", ".class",
}


def _mask(matched: str) -> str:
    """Return a fingerprint-safe masked version of a matched secret.

    Keeps up to 6 chars of prefix and up to 6 chars of suffix so the customer
    can verify they found the right value, while replacing the middle with '*'.
    The report is delivered to the customer as HTML; a live secret in the
    report body would itself become an exfiltration channel.

    Examples:
        "AKIAIOSFODNN7EXAMPLE"  -> "AKIAIO**************XAMPLE"
        "eyJhbGciOiJSUzI1NiJ9...sig"  -> "eyJhbG...***...sig" (too short? still masked)
        "abc"  -> "***"  (shorter than 12 chars — fully starred)
    """
    keep = 6
    if len(matched) <= keep * 2:
        return "*" * len(matched)
    stars = "*" * max(1, len(matched) - keep * 2)
    return matched[:keep] + stars + matched[-keep:]


def _looks_binary(chunk: bytes) -> bool:
    """Heuristic: NUL byte in the first chunk → binary."""
    return b"\x00" in chunk


def _walk_root(target: str) -> str:
    """Pick the directory to walk.

    .app bundle → return the bundle root (we want the whole Contents/).
    Mach-O binary inside .app → climb to the .app root if found.
    Bare file → return its parent directory.
    Directory → use as-is.
    """
    if os.path.isdir(target):
        return target
    if os.path.isfile(target):
        # If the target is `.../Foo.app/Contents/MacOS/Foo`, rewind to
        # `.../Foo.app` so we cover Resources/ and the rest of the bundle.
        cur = os.path.abspath(target)
        for _ in range(6):
            if cur.endswith(".app"):
                return cur
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        return os.path.dirname(target)
    return target


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Walk the bundle/dir under `target_url` and report any secrets found."""
    max_files = int(kwargs.get("max_files", 800) or 800)
    max_bytes = int(kwargs.get("max_bytes", 524288) or 524288)

    root = _walk_root(target_url)
    scanned = 0
    skipped_binary = 0
    findings: list[dict[str, Any]] = []

    if not os.path.exists(root):
        return {
            "scanned": 0,
            "findings": [],
            "skipped_binary": 0,
            "error": f"path not found: {root}",
        }

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place so os.walk doesn't descend into them.
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]

        for fname in filenames:
            if scanned >= max_files:
                break

            ext = os.path.splitext(fname)[1].lower()
            if ext in _SKIP_EXT:
                continue

            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "rb") as fh:
                    chunk = fh.read(max_bytes)
            except (OSError, PermissionError):
                continue

            if not chunk:
                continue
            if _looks_binary(chunk):
                skipped_binary += 1
                continue

            try:
                text = chunk.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 — best-effort scan
                continue

            scanned += 1

            for name, pattern, severity in _SECRET_PATTERNS:
                m = pattern.search(text)
                if not m:
                    continue
                # Context (30 chars before/after) stays as-is — it's not the
                # secret itself. Only the matched portion is masked so the
                # customer can verify the finding without the report becoming
                # an exfiltration vector.
                prefix_ctx = text[max(0, m.start() - 30): m.start()].replace("\n", "\\n")
                suffix_ctx = text[m.end(): m.end() + 30].replace("\n", "\\n")
                masked_match = _mask(m.group())
                snippet = (prefix_ctx + masked_match + suffix_ctx)[:240]
                poc_hint = masked_match[:120]
                findings.append({
                    "path": os.path.relpath(fpath, root),
                    "abs_path": fpath,
                    "severity": severity,
                    "pattern": name,
                    "snippet": snippet,
                    "vector": "DESK-LSS-001",
                    "title": f"Secret in app bundle ({name}|||앱 번들 내 시크릿 ({name}))",
                    "description": (
                        f"WHAT: {name} pattern matched in {fpath}\n"
                        f"HOW: filesystem walk of the application bundle\n"
                        f"IMPACT: secret recoverable by anyone with read access to the app\n"
                        f"PoC: open '{fpath}' and look for: {poc_hint}\n"
                        f"|||"
                        f"WHAT: {name} 패턴이 {fpath} 에서 발견됨\n"
                        f"HOW: 애플리케이션 번들 파일 시스템 워크\n"
                        f"IMPACT: 앱 읽기 권한만 있으면 누구나 시크릿 회수 가능\n"
                        f"PoC: '{fpath}' 열어서 다음 확인: {poc_hint}"
                    ),
                })

        if scanned >= max_files:
            break

    logger.info(
        "test_local_storage_secrets: root=%s scanned=%d findings=%d binary_skipped=%d",
        root, scanned, len(findings), skipped_binary,
    )
    return {
        "scanned": scanned,
        "findings": findings,
        "skipped_binary": skipped_binary,
        "root": root,
    }
