"""Skill: test_electron_misconfig — phase-J / DESK-ELC-001|002|003.

Inspects an Electron .app bundle for three well-known security misconfigurations
that turn any XSS in the renderer into full host-OS compromise:

  DESK-ELC-001  nodeIntegration: true   → renderer has full Node.js access
  DESK-ELC-002  contextIsolation: false → preload shares globals with renderer
  DESK-ELC-003  webSecurity: false      → CORS disabled, file:// accessible

Detection strategy:
  1. Identify Electron apps via Frameworks/Electron Framework.framework/ marker.
  2. Walk Contents/Resources/app/**/*.js (skip node_modules).
  3. Optionally extract app.asar with `npx asar` (soft dependency) to /tmp/;
     if asar is unavailable, grep the raw ASAR bytes (the JSON header is still
     readable as UTF-8 at the start of the archive).
  4. Regex-match each flag against BrowserWindow({...}) constructor args.

Args:
    target_url: required — path to .app bundle, directory inside a bundle,
        or a Mach-O binary (parent directory is walked up to the .app root).
    max_files: optional int (default 800) — file scan cap.
    max_bytes: optional int (default 524288) — bytes read per file.

Returns:
    {
      "scanned": int,
      "findings": [
        {"path": "...", "severity": "critical|high", "flag": "nodeIntegration",
         "snippet": "...", "vector": "DESK-ELC-001",
         "title": "...", "description": "..."},
        ...
      ],
      "is_electron": bool,
      "root": str,
    }
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from typing import Any

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Detection patterns — each entry: (flag_name, compiled_regex, severity, vector)
# ─────────────────────────────────────────────────────────────────────────────
_MISCONFIG_PATTERNS: tuple[tuple[str, re.Pattern, str, str], ...] = (
    (
        "nodeIntegration",
        re.compile(r"nodeIntegration\s*:\s*true", re.IGNORECASE),
        "critical",
        "DESK-ELC-001",
    ),
    (
        "contextIsolation",
        re.compile(r"contextIsolation\s*:\s*false", re.IGNORECASE),
        "high",
        "DESK-ELC-002",
    ),
    (
        "webSecurity",
        re.compile(r"webSecurity\s*:\s*false", re.IGNORECASE),
        "high",
        "DESK-ELC-003",
    ),
)

# Directories that do not contain main-process code and are expensive to scan.
_SKIP_DIRS = {
    "node_modules",
    ".git",
    "Frameworks",       # macOS dylib bundles — binary, not text
    "Helpers",          # Electron helper apps
    "PlugIns",
    "_CodeSignature",
}

_ELECTRON_MARKER_SUFFIX = os.path.join(
    "Contents", "Frameworks", "Electron Framework.framework"
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _walk_root(target: str) -> str:
    """Return the directory to use as scan root.

    Mirrors test_local_storage_secrets._walk_root: climbs a Mach-O binary path
    up to the enclosing .app bundle so we cover Contents/ fully.
    """
    if os.path.isdir(target):
        return target
    if os.path.isfile(target):
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


def _is_electron(root: str) -> bool:
    """Return True iff the .app bundle at *root* is an Electron application.

    Detection: presence of
    <root>/Contents/Frameworks/Electron Framework.framework/
    This directory is always present in any Electron .app regardless of version.
    """
    marker = os.path.join(root, _ELECTRON_MARKER_SUFFIX)
    return os.path.exists(marker)


def _extract_asar(asar_path: str) -> str | None:
    """Try to extract app.asar to a temporary directory using `npx asar`.

    Returns the tmp dir path on success, None if npx/asar is not available or
    extraction fails.  The caller is responsible for cleaning up via shutil.rmtree.

    `npx` is intentionally soft-required: if it is not on PATH we fall back to
    raw byte scanning of the ASAR header (see _read_asar_header_bytes).
    """
    if shutil.which("npx") is None:
        return None
    tmp_dir = tempfile.mkdtemp(prefix="vxis_asar_")
    try:
        result = subprocess.run(
            ["npx", "asar", "extract", asar_path, tmp_dir],
            capture_output=True,
            timeout=30,
        )
        if result.returncode == 0:
            return tmp_dir
    except (subprocess.TimeoutExpired, OSError):
        pass
    shutil.rmtree(tmp_dir, ignore_errors=True)
    return None


def _read_asar_header_text(asar_path: str, max_bytes: int = 524288) -> str:
    """Read the JSON header embedded at the start of an ASAR archive.

    ASAR format: 4-byte magic + 4-byte header-size + JSON string (UTF-8).
    Even without extraction, the JSON is readable and BrowserWindow call sites
    frequently appear in the path/file table — good enough for regex matching.
    We read up to *max_bytes* of raw bytes and decode leniently so that the
    main-process JS source (often concatenated near the header in small apps)
    is also covered.
    """
    try:
        with open(asar_path, "rb") as fh:
            raw = fh.read(max_bytes)
        return raw.decode("utf-8", errors="replace")
    except (OSError, PermissionError):
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Finding builder
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding(
    flag_name: str,
    severity: str,
    vector: str,
    fpath: str,
    root: str,
    snippet: str,
) -> dict[str, Any]:
    rel = os.path.relpath(fpath, root)
    # Config flags are NOT secrets — do not mask.  Truncate only for display.
    snippet_display = snippet[:240]
    return {
        "path": rel,
        "abs_path": fpath,
        "severity": severity,
        "flag": flag_name,
        "snippet": snippet_display,
        "vector": vector,
        "title": (
            f"Electron {flag_name} misconfiguration in {rel}"
            f"|||Electron {flag_name} 잘못된 설정 — {rel}"
        ),
        "description": (
            # ── English ──────────────────────────────────────────────────────
            f"WHAT: BrowserWindow option '{flag_name}' is set to an insecure "
            f"value in '{fpath}'.\n"
            f"HOW: Static analysis of Electron main-process JavaScript "
            f"identified the pattern via regex match.\n"
            f"IMPACT: "
            + _impact_en(flag_name)
            + f"\n"
            f"PoC: Open '{fpath}' and search for: {flag_name}\n"
            f"ATTACK PATH: Attacker triggers XSS in renderer → exploits "
            f"'{flag_name}' misconfig → escalates to full host-OS access.\n"
            # ── Korean ───────────────────────────────────────────────────────
            f"|||"
            f"WHAT: '{fpath}' 에서 BrowserWindow 옵션 '{flag_name}' 이 안전하지 않은 "
            f"값으로 설정됨.\n"
            f"HOW: Electron 메인 프로세스 JavaScript 정적 분석 — 정규식 패턴 매칭.\n"
            f"IMPACT: "
            + _impact_ko(flag_name)
            + f"\n"
            f"PoC: '{fpath}' 를 열어 다음을 검색: {flag_name}\n"
            f"ATTACK PATH: 공격자가 렌더러에서 XSS 유발 → '{flag_name}' 잘못된 설정 악용 → "
            f"호스트 OS 전체 접근으로 권한 상승."
        ),
    }


def _impact_en(flag: str) -> str:
    return {
        "nodeIntegration": (
            "Renderer process has direct access to Node.js APIs (require, "
            "fs, child_process). Any XSS in the renderer becomes RCE on the host."
        ),
        "contextIsolation": (
            "Preload script and renderer share the same JavaScript context. "
            "An attacker who achieves XSS can overwrite preload globals and "
            "call privileged APIs injected by the preload."
        ),
        "webSecurity": (
            "Same-origin policy is disabled. The renderer can fetch arbitrary "
            "local files (file://) and cross-origin resources, enabling data "
            "exfiltration without CORS restrictions."
        ),
    }.get(flag, "Security boundary weakened — exploitability depends on app context.")


def _impact_ko(flag: str) -> str:
    return {
        "nodeIntegration": (
            "렌더러 프로세스가 Node.js API (require, fs, child_process)에 직접 접근 가능. "
            "렌더러 XSS 하나로 호스트 OS 원격 코드 실행(RCE) 까지 이어짐."
        ),
        "contextIsolation": (
            "프리로드 스크립트와 렌더러가 동일한 JavaScript 컨텍스트 공유. "
            "XSS 달성 시 공격자가 프리로드 전역 변수를 덮어쓰고 "
            "권한 있는 API를 호출할 수 있음."
        ),
        "webSecurity": (
            "동일 출처 정책이 비활성화됨. 렌더러가 임의 로컬 파일(file://)과 "
            "크로스 오리진 리소스를 자유롭게 가져올 수 있어 "
            "CORS 제한 없이 데이터 탈취 가능."
        ),
    }.get(flag, "보안 경계 약화 — 실제 익스플로잇 가능성은 앱 컨텍스트에 따라 다름.")


# ─────────────────────────────────────────────────────────────────────────────
# Core scan helpers
# ─────────────────────────────────────────────────────────────────────────────

def _scan_text(
    text: str,
    fpath: str,
    root: str,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str]],
) -> None:
    """Match all misconfig patterns against *text* and append to *findings*.

    *seen* prevents duplicate findings for the same (flag, path) pair, which
    can arise when a file is scanned both via raw ASAR bytes and extracted copy.
    """
    for flag_name, pattern, severity, vector in _MISCONFIG_PATTERNS:
        m = pattern.search(text)
        if not m:
            continue
        key = (flag_name, fpath)
        if key in seen:
            continue
        seen.add(key)
        # Build snippet: 60 chars before match, matched text, 60 chars after.
        prefix = text[max(0, m.start() - 60): m.start()].replace("\n", "\\n")
        suffix = text[m.end(): m.end() + 60].replace("\n", "\\n")
        snippet = prefix + m.group() + suffix
        findings.append(_make_finding(flag_name, severity, vector, fpath, root, snippet))


def _walk_js_dir(
    js_root: str,
    app_root: str,
    max_files: int,
    max_bytes: int,
    findings: list[dict[str, Any]],
    seen: set[tuple[str, str]],
) -> int:
    """Walk *js_root* for *.js files and scan each one.  Returns file count."""
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(js_root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            if scanned >= max_files:
                return scanned
            if not fname.endswith(".js"):
                continue
            fpath = os.path.join(dirpath, fname)
            try:
                with open(fpath, "rb") as fh:
                    raw = fh.read(max_bytes)
            except (OSError, PermissionError):
                continue
            if not raw:
                continue
            try:
                text = raw.decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                continue
            scanned += 1
            _scan_text(text, fpath, app_root, findings, seen)
    return scanned


# ─────────────────────────────────────────────────────────────────────────────
# Public entrypoint
# ─────────────────────────────────────────────────────────────────────────────

async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Detect Electron security misconfigurations in an app bundle."""
    max_files = int(kwargs.get("max_files", 800) or 800)
    max_bytes = int(kwargs.get("max_bytes", 524288) or 524288)

    root = _walk_root(target_url)

    if not os.path.exists(root):
        return {
            "scanned": 0,
            "findings": [],
            "is_electron": False,
            "root": root,
            "error": f"path not found: {root}",
        }

    # ── 1. Electron detection ────────────────────────────────────────────────
    if not _is_electron(root):
        logger.debug("test_electron_misconfig: not an Electron app — %s", root)
        return {
            "scanned": 0,
            "findings": [],
            "is_electron": False,
            "root": root,
        }

    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    scanned = 0
    asar_tmp: str | None = None

    resources_app = os.path.join(root, "Contents", "Resources", "app")
    asar_path = os.path.join(root, "Contents", "Resources", "app.asar")

    try:
        # ── 2. Unpacked app/ directory ───────────────────────────────────────
        if os.path.isdir(resources_app):
            scanned += _walk_js_dir(
                resources_app, root, max_files - scanned, max_bytes, findings, seen
            )

        # ── 3. Packed app.asar ───────────────────────────────────────────────
        if os.path.isfile(asar_path):
            # 3a. Try to extract with npx asar (optional dependency).
            asar_tmp = _extract_asar(asar_path)
            if asar_tmp:
                scanned += _walk_js_dir(
                    asar_tmp, root, max_files - scanned, max_bytes, findings, seen
                )
            else:
                # 3b. Fallback: grep the raw ASAR bytes. The JSON header and
                # often the concatenated source JS are readable without extraction.
                text = _read_asar_header_text(asar_path, max_bytes)
                if text:
                    scanned += 1
                    _scan_text(text, asar_path, root, findings, seen)

    finally:
        if asar_tmp:
            shutil.rmtree(asar_tmp, ignore_errors=True)

    logger.info(
        "test_electron_misconfig: root=%s scanned=%d findings=%d",
        root, scanned, len(findings),
    )
    return {
        "scanned": scanned,
        "findings": findings,
        "is_electron": True,
        "root": root,
    }
