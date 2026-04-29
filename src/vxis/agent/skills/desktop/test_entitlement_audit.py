"""Skill: test_entitlement_audit — phase-J / DESK-ENT-001|002|003.

Reads the code-signing entitlements of a macOS .app bundle and flags
dangerous entitlement keys that weaken the Hardened Runtime protections:

  DESK-ENT-001  disable-library-validation = true
                → unsigned dylibs may be loaded → dylib hijack vector
  DESK-ENT-002  allow-dyld-environment-variables = true
                → DYLD_INSERT_LIBRARIES injection allowed
  DESK-ENT-003  allow-jit OR allow-unsigned-executable-memory = true
                → JIT / unsigned page mappings allowed

Detection strategy:
  1. _walk_root: resolve the .app bundle root from the given path.
  2. Run `codesign -d --entitlements - --xml <root>` (plist XML output).
  3. If returncode != 0 or no XML emitted → return empty result with
     `error` key.  NOT a finding — signature absence is test_signature_audit's job.
  4. Parse the plist XML via plistlib.
  5. Emit a finding for each dangerous key whose value is boolean True.
  6. Also collect all dangerous keys (True/False) in the `entitlements`
     return field so Brain can chain on this state (e.g. correlate with
     test_electron_misconfig findings for compound severity escalation).
  7. Non-boolean entitlements (strings like application-identifier) are
     stored in `entitlements` but NOT used for boolean checks.

Args:
    target_url: required — path to .app bundle, directory, or Mach-O binary.
        The skill resolves to the enclosing .app root automatically.

Returns:
    {
      "scanned": int,            # 1 if codesign ran, 0 if not applicable
      "findings": list[dict],    # one per dangerous-key-is-True hit
      "entitlements": dict[str, bool | str],  # parsed dangerous keys → value
      "root": str,               # resolved bundle path
      "error"?: str,             # present when codesign unavailable/unsigned
    }
"""
from __future__ import annotations

import logging
import os
import plistlib
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Dangerous entitlement key → (vector_id, severity)
#
# Only boolean keys are checked. String entitlements like
# com.apple.application-identifier are captured in `entitlements` but
# never trigger a finding.
# ─────────────────────────────────────────────────────────────────────────────
_DANGEROUS_BOOL_KEYS: tuple[tuple[str, str, str], ...] = (
    (
        "com.apple.security.cs.disable-library-validation",
        "DESK-ENT-001",
        "high",
    ),
    (
        "com.apple.security.cs.allow-dyld-environment-variables",
        "DESK-ENT-002",
        "high",
    ),
    # ENT-003 covers two alternate keys — either alone is sufficient.
    (
        "com.apple.security.cs.allow-jit",
        "DESK-ENT-003",
        "medium",
    ),
    (
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "DESK-ENT-003",
        "medium",
    ),
)

# Informational-only keys: risky combos but not an independent vector.
# We report these as informational findings when the app also lacks
# com.apple.security.app-sandbox.
_INFORMATIONAL_KEYS: frozenset[str] = frozenset({
    "com.apple.security.files.all-files",
    "com.apple.security.device.microphone",
    "com.apple.security.device.camera",
    "com.apple.security.personal-information.contacts",
    "com.apple.security.personal-information.location",
    "com.apple.security.personal-information.calendars",
})


# ─────────────────────────────────────────────────────────────────────────────
# Bundle resolution helper (mirrors test_local_storage_secrets._walk_root)
# ─────────────────────────────────────────────────────────────────────────────

def _walk_root(target: str) -> str:
    """Return the .app bundle root (or best-effort directory) for *target*."""
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


# ─────────────────────────────────────────────────────────────────────────────
# Finding builder
# ─────────────────────────────────────────────────────────────────────────────

def _make_finding(
    entitlement_key: str,
    vector: str,
    severity: str,
    root: str,
) -> dict[str, Any]:
    short_key = entitlement_key.split(".")[-1]  # e.g. "disable-library-validation"

    _titles = {
        "DESK-ENT-001": (
            "Disabled Library Validation"
            "|||"
            "라이브러리 검증 비활성화"
        ),
        "DESK-ENT-002": (
            "Allows DYLD Environment Variables"
            "|||"
            "DYLD 환경 변수 허용"
        ),
        "DESK-ENT-003": (
            "Allow JIT or Unsigned Executable Memory"
            "|||"
            "JIT/서명되지 않은 실행 메모리 허용"
        ),
    }
    _impacts_en = {
        "DESK-ENT-001": (
            "Any process that can write a dylib to a directory on the app's "
            "DYLD_LIBRARY_PATH (or a rpath entry) can force the app to load "
            "unsigned code, achieving arbitrary code execution in the app's "
            "security context."
        ),
        "DESK-ENT-002": (
            "DYLD_INSERT_LIBRARIES and related environment variables are "
            "honoured by the dynamic linker. An attacker who can set environment "
            "variables for this process (e.g. via a parent-process exploit, "
            "a LaunchAgent plist, or sudo env) can inject an arbitrary dylib."
        ),
        "DESK-ENT-003": (
            "Pages may be mapped as simultaneously writable and executable. "
            "This weakens exploit mitigations (W^X / PAC) and is a prerequisite "
            "for shellcode injection without ROP chains."
        ),
    }
    _impacts_ko = {
        "DESK-ENT-001": (
            "앱의 DYLD_LIBRARY_PATH 또는 rpath 항목에 속한 디렉토리에 dylib를 쓸 수 있는 "
            "프로세스는 앱이 서명되지 않은 코드를 로드하도록 강제할 수 있어 "
            "앱의 보안 컨텍스트에서 임의 코드 실행이 가능합니다."
        ),
        "DESK-ENT-002": (
            "DYLD_INSERT_LIBRARIES 및 관련 환경 변수가 동적 링커에 의해 허용됩니다. "
            "상위 프로세스 익스플로잇, LaunchAgent plist, sudo env 등을 통해 "
            "환경 변수를 설정할 수 있는 공격자는 임의 dylib를 주입할 수 있습니다."
        ),
        "DESK-ENT-003": (
            "페이지가 쓰기 가능하면서 동시에 실행 가능하도록 매핑될 수 있습니다. "
            "이는 W^X / PAC 등 익스플로잇 완화 기법을 약화시키며 "
            "ROP 체인 없이 셸코드를 주입하기 위한 전제 조건이 됩니다."
        ),
    }

    title = _titles.get(vector, f"{short_key}|||{short_key}")
    impact_en = _impacts_en.get(vector, "Security boundary weakened.")
    impact_ko = _impacts_ko.get(vector, "보안 경계 약화.")

    description = (
        # ── English ──────────────────────────────────────────────────────────
        f"WHAT: The entitlement '{entitlement_key}' is set to true in the "
        f"code signature of '{root}'.\n"
        f"HOW: Extracted via `codesign -d --entitlements - --xml '{root}'` "
        f"and parsed the embedded plist.\n"
        f"IMPACT: {impact_en}\n"
        f"PoC: Run `codesign -d --entitlements - '{root}'` and verify "
        f"'{entitlement_key}' = true in the output.\n"
        f"ATTACK PATH: Attacker places/controls a dylib on load path → "
        f"app auto-loads it at launch → arbitrary code runs in app sandbox context.\n"
        # ── Korean ────────────────────────────────────────────────────────────
        f"|||"
        f"WHAT: '{root}' 의 코드 서명에 '{entitlement_key}' 권한이 true로 설정되어 있음.\n"
        f"HOW: `codesign -d --entitlements - --xml '{root}'` 실행 후 내장 plist 파싱.\n"
        f"IMPACT: {impact_ko}\n"
        f"PoC: `codesign -d --entitlements - '{root}'` 실행하여 출력에서 "
        f"'{entitlement_key}' = true 확인.\n"
        f"ATTACK PATH: 공격자가 로드 경로에 dylib 배치/제어 → "
        f"앱 실행 시 자동 로드 → 앱 샌드박스 컨텍스트에서 임의 코드 실행."
    )

    return {
        "entitlement_key": entitlement_key,
        "vector": vector,
        "severity": severity,
        "title": title,
        "description": description,
        "root": root,
    }


def _make_informational_finding(
    entitlement_key: str,
    root: str,
) -> dict[str, Any]:
    """Build a low-severity informational finding for privacy-sensitive entitlements."""
    short_key = entitlement_key.split(".")[-1]
    return {
        "entitlement_key": entitlement_key,
        "vector": None,
        "severity": "informational",
        "title": (
            f"Sensitive entitlement without sandbox: {short_key}"
            f"|||"
            f"샌드박스 없이 민감 권한 사용: {short_key}"
        ),
        "description": (
            f"WHAT: The entitlement '{entitlement_key}' is granted but "
            f"'com.apple.security.app-sandbox' is absent.\n"
            f"HOW: Parsed via `codesign -d --entitlements - --xml '{root}'`.\n"
            f"IMPACT: Without sandboxing, the entitlement grants unrestricted "
            f"access to the named resource beyond the usual OS prompt.\n"
            f"PoC: Run `codesign -d --entitlements - '{root}'` and confirm "
            f"both '{entitlement_key}' and absence of app-sandbox.\n"
            f"ATTACK PATH: Malicious/compromised app accesses sensitive "
            f"resources without sandbox containment.\n"
            f"|||"
            f"WHAT: '{entitlement_key}' 권한이 부여되어 있지만 "
            f"'com.apple.security.app-sandbox' 가 없음.\n"
            f"HOW: `codesign -d --entitlements - --xml '{root}'` 로 파싱.\n"
            f"IMPACT: 샌드박스 없이는 일반적인 OS 프롬프트를 초월하여 "
            f"해당 리소스에 무제한 접근이 허용됨.\n"
            f"PoC: `codesign -d --entitlements - '{root}'` 실행 후 "
            f"'{entitlement_key}' 존재 및 app-sandbox 부재 확인.\n"
            f"ATTACK PATH: 악성/감염된 앱이 샌드박스 격리 없이 민감 리소스 접근."
        ),
        "root": root,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public entrypoint
# ─────────────────────────────────────────────────────────────────────────────

async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Audit dangerous macOS entitlements in the app bundle at *target_url*."""
    root = _walk_root(target_url)

    # ── 1. Run codesign ───────────────────────────────────────────────────────
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", "-", "--xml", root],
            check=False,
            capture_output=True,
            text=False,          # We want raw bytes for plistlib.loads()
        )
    except FileNotFoundError:
        return {
            "scanned": 0,
            "findings": [],
            "entitlements": {},
            "root": root,
            "error": "codesign binary not found — not running on macOS?",
        }
    except OSError as exc:
        return {
            "scanned": 0,
            "findings": [],
            "entitlements": {},
            "root": root,
            "error": f"codesign OSError: {exc}",
        }

    # codesign writes the plist XML to stdout.  Some older macOS versions
    # write to stderr instead; we prefer stdout but fall back to stderr.
    xml_bytes = result.stdout or result.stderr or b""

    if result.returncode != 0 or not xml_bytes.strip():
        logger.debug(
            "test_entitlement_audit: codesign returned rc=%d for %s — likely unsigned",
            result.returncode, root,
        )
        return {
            "scanned": 0,
            "findings": [],
            "entitlements": {},
            "root": root,
            "error": "no entitlements (likely unsigned)",
        }

    # ── 2. Parse plist ────────────────────────────────────────────────────────
    # codesign --xml output may be prefixed by a "Entitlements:\n" header line
    # before the <?xml ...> declaration.  Strip everything up to the first '<'.
    xml_start = xml_bytes.find(b"<")
    if xml_start > 0:
        xml_bytes = xml_bytes[xml_start:]

    try:
        plist_data: dict[str, Any] = plistlib.loads(xml_bytes)
    except Exception as exc:  # noqa: BLE001 — malformed plist
        logger.warning("test_entitlement_audit: plist parse error for %s: %s", root, exc)
        return {
            "scanned": 0,
            "findings": [],
            "entitlements": {},
            "root": root,
            "error": f"plist parse error: {exc}",
        }

    if not isinstance(plist_data, dict):
        return {
            "scanned": 1,
            "findings": [],
            "entitlements": {},
            "root": root,
            "error": "unexpected plist structure (not a dict)",
        }

    # ── 3. Check dangerous boolean keys ──────────────────────────────────────
    findings: list[dict[str, Any]] = []
    entitlements_out: dict[str, Any] = {}

    # Track emitted vectors to avoid duplicate ENT-003 findings when both
    # allow-jit and allow-unsigned-executable-memory are set.
    emitted_vectors: set[str] = set()

    for key, vector, severity in _DANGEROUS_BOOL_KEYS:
        value = plist_data.get(key)
        # Only boolean True triggers a finding. String/int/None → skip.
        if isinstance(value, bool):
            entitlements_out[key] = value
            if value and vector not in emitted_vectors:
                emitted_vectors.add(vector)
                findings.append(_make_finding(key, vector, severity, root))

    # ── 4. Informational: sensitive entitlements without sandbox ──────────────
    is_sandboxed = bool(plist_data.get("com.apple.security.app-sandbox", False))
    if not is_sandboxed:
        for key in _INFORMATIONAL_KEYS:
            value = plist_data.get(key)
            if isinstance(value, bool) and value:
                findings.append(_make_informational_finding(key, root))

    logger.info(
        "test_entitlement_audit: root=%s scanned=1 findings=%d dangerous_keys=%d",
        root, len(findings), len(entitlements_out),
    )
    return {
        "scanned": 1,
        "findings": findings,
        "entitlements": entitlements_out,
        "root": root,
    }
