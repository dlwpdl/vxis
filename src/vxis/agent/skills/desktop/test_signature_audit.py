"""Skill: test_signature_audit — phase-J / DESK-SIG-001|002|003|004.

Audits the code signature of a macOS .app bundle or Mach-O binary using
the system `codesign(1)` tool and reports three distinct issues:

  DESK-SIG-002  Unsigned binary — codesign returns non-zero or emits
                "code object is not signed at all".
  DESK-SIG-003  Ad-hoc signed (no Developer ID) — Authority line is
                absent, is "(unknown)", or starts with "-" (ad-hoc marker).
  DESK-SIG-004  Hardened Runtime disabled — the runtime flag (0x10000)
                is absent from the flags= output line.

Args:
    target_url: required — path to .app bundle, directory, or Mach-O
        binary. For a Mach-O binary the skill climbs up to the enclosing
        .app bundle (up to 6 levels) before running codesign.

Returns:
    {
      "scanned": int,           # 1 if codesign ran, 0 on early exit
      "findings": list[dict],   # Finding-shaped dicts for each issue
      "signed": bool,           # True iff codesign exit-code == 0
      "authority": str | None,  # First Authority= line, or None
      "hardened_runtime": bool, # True iff flags include 0x10000(runtime)
      "root": str,              # Resolved path codesign was invoked on
      "error": str,             # (optional) human-readable error message
    }

All finding titles and descriptions are bilingual (English|||한국어) and
follow the WHAT/HOW/IMPACT/PoC/ATTACK PATH structure.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

# Regex patterns for codesign -dv stderr output parsing.
# Authority= always starts at the beginning of a line.
_RE_AUTHORITY = re.compile(r"^Authority=(.+)$", re.MULTILINE)
# flags= appears mid-line in the CodeDirectory line, e.g.:
#   "CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=..."
# We do NOT use a ^ anchor here — flags= is never at column 0.
_RE_FLAGS = re.compile(r"\bflags=(0x[0-9a-fA-F]+)\(([^)]*)\)")
_RUNTIME_FLAG = 0x10000  # Hardened Runtime bit


def _walk_root(target: str) -> str:
    """Return the path to pass to codesign.

    Mirrors the pattern from test_local_storage_secrets and test_electron_misconfig:
    climb a Mach-O binary path up to the enclosing .app bundle so that
    codesign receives the bundle root rather than a single binary.
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
        # Bare Mach-O not inside a bundle — pass it directly to codesign.
        return target
    return target


def _parse_authority(stderr: str) -> str | None:
    """Return the first Authority= value from codesign stderr, or None."""
    m = _RE_AUTHORITY.search(stderr)
    return m.group(1).strip() if m else None


def _has_hardened_runtime(stderr: str) -> bool:
    """Return True iff the flags line includes the 0x10000 runtime bit."""
    m = _RE_FLAGS.search(stderr)
    if not m:
        return False
    flags_value = int(m.group(1), 16)
    return bool(flags_value & _RUNTIME_FLAG)


def _is_adhoc(authority: str | None, stderr: str) -> bool:
    """Return True iff the signature is ad-hoc (no Developer ID).

    Ad-hoc detection rules (codesign -dv output):
      1. No Authority= lines at all.
      2. Authority value is "(unknown)".
      3. Authority value starts with "-" (literal ad-hoc marker).
    """
    if authority is None:
        return True
    stripped = authority.strip()
    return stripped in ("(unknown)", "-") or stripped.startswith("-")


def _make_finding(
    vector: str,
    severity: str,
    title_en: str,
    title_ko: str,
    what_en: str,
    what_ko: str,
    how_en: str,
    how_ko: str,
    impact_en: str,
    impact_ko: str,
    poc_en: str,
    poc_ko: str,
    attack_path_en: str,
    attack_path_ko: str,
    root: str,
) -> dict[str, Any]:
    return {
        "path": root,
        "severity": severity,
        "vector": vector,
        "title": f"{title_en}|||{title_ko}",
        "description": (
            f"WHAT: {what_en}\n"
            f"HOW: {how_en}\n"
            f"IMPACT: {impact_en}\n"
            f"PoC: {poc_en}\n"
            f"ATTACK PATH: {attack_path_en}\n"
            f"|||"
            f"WHAT: {what_ko}\n"
            f"HOW: {how_ko}\n"
            f"IMPACT: {impact_ko}\n"
            f"PoC: {poc_ko}\n"
            f"ATTACK PATH: {attack_path_ko}"
        ),
    }


async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Run codesign audit on the target and return structured findings."""
    root = _walk_root(target_url)

    if not os.path.exists(root):
        return {
            "scanned": 0,
            "findings": [],
            "signed": False,
            "authority": None,
            "hardened_runtime": False,
            "root": root,
            "error": f"path not found: {root}",
        }

    # Run codesign -dv --verbose=4 <root>. codesign writes all output to
    # stderr — stdout is empty for most invocations.
    poc_cmd = f"codesign -dv --verbose=4 '{root}'"
    try:
        proc = subprocess.run(
            ["codesign", "-dv", "--verbose=4", root],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return {
            "scanned": 0,
            "findings": [],
            "signed": False,
            "authority": None,
            "hardened_runtime": False,
            "root": root,
            "error": "codesign binary not found — is this a macOS system?",
        }
    except OSError as exc:
        return {
            "scanned": 0,
            "findings": [],
            "signed": False,
            "authority": None,
            "hardened_runtime": False,
            "root": root,
            "error": f"codesign invocation failed: {exc}",
        }

    stderr = proc.stderr or ""
    stdout = proc.stdout or ""
    combined = stderr + stdout

    # ── Parse signature state ────────────────────────────────────────────────
    not_signed_at_all = "code object is not signed at all" in combined
    signed = proc.returncode == 0 and not not_signed_at_all
    authority = _parse_authority(combined)
    hardened_runtime = _has_hardened_runtime(combined)
    adhoc = _is_adhoc(authority, combined)

    findings: list[dict[str, Any]] = []

    # ── DESK-SIG-002: Unsigned binary ────────────────────────────────────────
    if not signed:
        findings.append(_make_finding(
            vector="DESK-SIG-002",
            severity="high",
            title_en="Unsigned binary",
            title_ko="서명 안 된 바이너리",
            what_en=(
                f"The binary or bundle at '{root}' carries no valid code signature. "
                "codesign(1) returned a non-zero exit code or reported 'code object "
                "is not signed at all'."
            ),
            what_ko=(
                f"'{root}' 의 바이너리 또는 번들에 유효한 코드 서명이 없습니다. "
                "codesign(1)이 0이 아닌 종료 코드를 반환하거나 'code object is not "
                "signed at all'을 보고했습니다."
            ),
            how_en="codesign(1) was invoked on the target path and the signature check failed.",
            how_ko="codesign(1)을 타겟 경로에 대해 실행하여 서명 검증이 실패했습니다.",
            impact_en=(
                "Unsigned macOS binaries bypass Gatekeeper assessment for local "
                "execution. An attacker who can swap or trojanise the binary faces "
                "no signature-verification barrier. macOS SIP / Notarization controls "
                "that rely on a valid signature are ineffective."
            ),
            impact_ko=(
                "서명되지 않은 macOS 바이너리는 로컬 실행 시 Gatekeeper 평가를 우회합니다. "
                "바이너리를 교체하거나 트로이목마로 변조할 수 있는 공격자에게 "
                "서명 검증 장벽이 없습니다. 유효한 서명에 의존하는 macOS SIP / "
                "Notarization 통제가 무력화됩니다."
            ),
            poc_en=f"Run: {poc_cmd}  # returns non-zero or emits 'not signed at all'",
            poc_ko=f"실행: {poc_cmd}  # 0이 아닌 종료 코드 또는 'not signed at all' 메시지",
            attack_path_en=(
                "Attacker obtains write access to app bundle → replaces binary with "
                "malicious payload → no signature check blocks execution → RCE / "
                "persistence achieved."
            ),
            attack_path_ko=(
                "공격자가 앱 번들 쓰기 권한 획득 → 바이너리를 악성 페이로드로 교체 → "
                "서명 검증 없이 실행 → RCE / 지속성 달성."
            ),
            root=root,
        ))

    # ── DESK-SIG-003: Ad-hoc signed (no Developer ID) ───────────────────────
    # Only emit if the binary IS signed (unsigned already covered by SIG-002).
    if signed and adhoc:
        findings.append(_make_finding(
            vector="DESK-SIG-003",
            severity="medium",
            title_en="Ad-hoc signed (no Developer ID)",
            title_ko="Ad-hoc 서명 (Developer ID 없음)",
            what_en=(
                f"The bundle at '{root}' is signed but has no Developer ID Authority. "
                "The Authority field is absent, '(unknown)', or starts with '-', "
                "indicating an ad-hoc signature."
            ),
            what_ko=(
                f"'{root}' 의 번들은 서명되어 있지만 Developer ID Authority가 없습니다. "
                "Authority 필드가 없거나 '(unknown)' 또는 '-'로 시작하여 "
                "ad-hoc 서명임을 나타냅니다."
            ),
            how_en=(
                "codesign -dv output was parsed for Authority= lines. "
                "Absence of a Developer ID Authority indicates ad-hoc signing."
            ),
            how_ko=(
                "codesign -dv 출력에서 Authority= 라인을 파싱했습니다. "
                "Developer ID Authority 부재는 ad-hoc 서명을 의미합니다."
            ),
            impact_en=(
                "Ad-hoc signatures are not validated by Apple's certificate chain. "
                "Gatekeeper will block ad-hoc signed apps downloaded from the internet "
                "(quarantine bit set). Users may be conditioned to approve arbitrary "
                "apps, weakening the macOS trust model."
            ),
            impact_ko=(
                "Ad-hoc 서명은 Apple의 인증서 체인으로 검증되지 않습니다. "
                "Gatekeeper는 인터넷에서 다운로드된 ad-hoc 서명 앱을 차단합니다(격리 비트 설정). "
                "사용자가 임의 앱 승인에 익숙해져 macOS 신뢰 모델이 약화될 수 있습니다."
            ),
            poc_en=f"Run: {poc_cmd}  # Authority= line absent or shows '(unknown)' / '-'",
            poc_ko=f"실행: {poc_cmd}  # Authority= 라인 없음 또는 '(unknown)' / '-' 표시",
            attack_path_en=(
                "Attacker distributes a trojanised copy of the app without a valid "
                "Developer ID → target system's Gatekeeper does not validate chain → "
                "malicious code executes under user trust."
            ),
            attack_path_ko=(
                "공격자가 유효한 Developer ID 없이 변조된 앱 사본 배포 → "
                "대상 시스템의 Gatekeeper가 체인을 검증하지 않음 → "
                "악성 코드가 사용자 신뢰 하에 실행."
            ),
            root=root,
        ))

    # ── DESK-SIG-004: Hardened Runtime disabled ──────────────────────────────
    # Emit whenever the binary is signed (unsigned binaries have no runtime to check).
    if signed and not hardened_runtime:
        findings.append(_make_finding(
            vector="DESK-SIG-004",
            severity="medium",
            title_en="Hardened Runtime disabled",
            title_ko="Hardened Runtime 비활성화",
            what_en=(
                f"The bundle at '{root}' does not have the Hardened Runtime enabled. "
                "The flags= output from codesign does not include the 0x10000(runtime) bit."
            ),
            what_ko=(
                f"'{root}' 의 번들에 Hardened Runtime이 활성화되어 있지 않습니다. "
                "codesign의 flags= 출력에 0x10000(runtime) 비트가 없습니다."
            ),
            how_en=(
                "codesign -dv output was parsed for 'flags=0x...(...)'. "
                "The runtime flag (0x10000) was not found."
            ),
            how_ko=(
                "codesign -dv 출력에서 'flags=0x...(...)' 를 파싱했습니다. "
                "runtime 플래그(0x10000)가 발견되지 않았습니다."
            ),
            impact_en=(
                "Without Hardened Runtime, the process is susceptible to classic "
                "code injection attacks: DYLD_INSERT_LIBRARIES hijacking, "
                "task_for_pid() debugging, and ptrace-based memory manipulation. "
                "Apple requires Hardened Runtime for Notarization."
            ),
            impact_ko=(
                "Hardened Runtime 없이는 프로세스가 클래식 코드 인젝션 공격에 취약합니다: "
                "DYLD_INSERT_LIBRARIES 하이재킹, task_for_pid() 디버깅, "
                "ptrace 기반 메모리 조작. "
                "Apple은 Notarization을 위해 Hardened Runtime을 요구합니다."
            ),
            poc_en=f"Run: {poc_cmd}  # flags= line lacks 'runtime'",
            poc_ko=f"실행: {poc_cmd}  # flags= 라인에 'runtime' 없음",
            attack_path_en=(
                "Attacker injects malicious dylib via DYLD_INSERT_LIBRARIES or "
                "attaches debugger via task_for_pid → hijacks process execution flow → "
                "credential theft or privilege escalation."
            ),
            attack_path_ko=(
                "공격자가 DYLD_INSERT_LIBRARIES 또는 task_for_pid로 악성 dylib 인젝션 → "
                "프로세스 실행 흐름 하이재킹 → 자격증명 탈취 또는 권한 상승."
            ),
            root=root,
        ))

    logger.info(
        "test_signature_audit: root=%s signed=%s authority=%r hardened_runtime=%s findings=%d",
        root, signed, authority, hardened_runtime, len(findings),
    )
    return {
        "scanned": 1,
        "findings": findings,
        "signed": signed,
        "authority": authority,
        "hardened_runtime": hardened_runtime,
        "root": root,
    }
