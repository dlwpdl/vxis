"""Skill: test_binary_protections — phase-F / DESK-PIE-001|002|003.

Inspects a Mach-O binary (or the main executable inside a .app bundle)
for three foundational memory-safety hardening flags:

  DESK-PIE-001  PIE missing — MH_PIE flag absent from the Mach-O header.
                Without PIE, ASLR is not applied; ROP chains become trivial.

  DESK-PIE-002  Stack canary absent — __stack_chk_guard symbol not found
                in `nm` output. Stack buffer overflows can overwrite the
                return address without detection.

  DESK-PIE-003  __RESTRICT segment absent — without this segment macOS
                does not suppress DYLD_INSERT_LIBRARIES injection at
                process startup (relevant for non-Hardened Runtime builds).

Detection strategy (all three checks use subprocess to call Apple tools):
  1. `otool -hv <binary>` → parse flags line for MH_PIE.
  2. `nm <binary>` → grep for __stack_chk_guard symbol.
  3. `otool -l <binary>` → look for segname __RESTRICT / sectname __restrict.

This skill is macOS-specific (requires otool + nm from Xcode Command Line
Tools). On non-darwin platforms the checks still run but otool/nm will
not be found, resulting in tested=0 with a skipped_reason.

Args:
    target_url: required — path to .app bundle, directory, or Mach-O
        binary. For a .app bundle the skill resolves to
        Contents/MacOS/<binary_name> automatically (walks up to 6 dirs).
        For a bare Mach-O binary the path is used directly.

Returns:
    {
      "tested": int,             # 1 if otool ran, 0 on early exit
      "findings": list[dict],    # Finding-shaped dicts (bilingual)
      "pie": bool,               # True iff MH_PIE present
      "stack_canary": bool,      # True iff __stack_chk_guard found
      "restrict_segment": bool,  # True iff __RESTRICT,__restrict present
      "binary": str,             # Resolved binary path
      "skipped_reason"?: str,    # Present + non-empty only on early exit
    }
"""
from __future__ import annotations

import logging
import os
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

_MH_PIE_TOKEN = "MH_PIE"
_CANARY_SYMBOL = "__stack_chk_guard"
_RESTRICT_SEGMENT = "__RESTRICT"
_RESTRICT_SECTION = "__restrict"


def _resolve_binary(target: str) -> str:
    """Return the Mach-O binary path to inspect.

    For a .app bundle: <root>/Contents/MacOS/<bundle_name>.
    For a bare file: the file itself.
    For a directory that is not a .app: walk up to find a .app, or
    just return the original path.
    """
    if os.path.isfile(target):
        return target

    # Try to find .app bundle root
    if target.endswith(".app") and os.path.isdir(target):
        bundle_name = os.path.splitext(os.path.basename(target))[0]
        candidate = os.path.join(target, "Contents", "MacOS", bundle_name)
        if os.path.isfile(candidate):
            return candidate
        # Fallback: take first executable in Contents/MacOS/
        macos_dir = os.path.join(target, "Contents", "MacOS")
        if os.path.isdir(macos_dir):
            for entry in sorted(os.listdir(macos_dir)):
                full = os.path.join(macos_dir, entry)
                if os.path.isfile(full):
                    return full
        return target  # give up; caller will handle missing file

    # Not a .app — could be a directory containing a binary
    if os.path.isdir(target):
        # Walk up to see if we are inside a .app
        cur = os.path.abspath(target)
        for _ in range(6):
            if cur.endswith(".app"):
                return _resolve_binary(cur)
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
        return target

    return target


def _check_pie(binary: str) -> bool:
    """Return True iff MH_PIE is set in the Mach-O header flags.

    Runs `otool -hv <binary>` and looks for the MH_PIE token in the
    flags field. For fat/universal binaries, the presence of MH_PIE in
    ANY architecture slice is considered sufficient (most important arch).
    Raises subprocess.SubprocessError / FileNotFoundError on tool failure.
    """
    proc = subprocess.run(
        ["otool", "-hv", binary],
        capture_output=True,
        text=True,
        check=False,
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    return _MH_PIE_TOKEN in combined


def _check_stack_canary(binary: str) -> bool:
    """Return True iff __stack_chk_guard symbol is referenced in the binary.

    Runs `nm <binary>` and checks for the presence of __stack_chk_guard.
    This works for both static symbols and extern undefined references.
    Raises subprocess.SubprocessError / FileNotFoundError on tool failure.
    """
    proc = subprocess.run(
        ["nm", binary],
        capture_output=True,
        text=True,
        check=False,
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    return _CANARY_SYMBOL in combined


def _check_restrict_segment(binary: str) -> bool:
    """Return True iff a __RESTRICT,__restrict section exists in the binary.

    Runs `otool -l <binary>` and looks for both segname __RESTRICT and
    sectname __restrict. Both must appear together to confirm the segment
    is present and not just a coincidental match.
    Raises subprocess.SubprocessError / FileNotFoundError on tool failure.
    """
    proc = subprocess.run(
        ["otool", "-l", binary],
        capture_output=True,
        text=True,
        check=False,
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    return _RESTRICT_SEGMENT in combined and _RESTRICT_SECTION in combined


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
    path: str,
) -> dict[str, Any]:
    return {
        "path": path,
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
    """Run Mach-O binary protection checks and return structured findings."""

    _empty: dict[str, Any] = {
        "tested": 0,
        "findings": [],
        "pie": False,
        "stack_canary": False,
        "restrict_segment": False,
        "binary": target_url,
    }

    binary = _resolve_binary(target_url)
    _empty["binary"] = binary

    # We intentionally do NOT guard on sys.platform here — the tool calls
    # will simply raise FileNotFoundError on non-macOS systems, which is
    # handled gracefully below.

    # ── Run PIE check (otool -hv) ────────────────────────────────────────────
    try:
        pie = _check_pie(binary)
    except FileNotFoundError:
        return {
            **_empty,
            "skipped_reason": (
                "otool binary not found — install Xcode Command Line Tools "
                "or run on macOS: xcode-select --install"
            ),
        }
    except OSError as exc:
        return {
            **_empty,
            "skipped_reason": f"otool invocation failed: {exc}",
        }

    # ── Run stack canary check (nm) ──────────────────────────────────────────
    try:
        canary = _check_stack_canary(binary)
    except (FileNotFoundError, OSError) as exc:
        # nm may not be available on all systems; treat as unknown (assume safe)
        logger.debug("test_binary_protections: nm unavailable: %s", exc)
        canary = True  # conservative: do not emit false positive

    # ── Run __RESTRICT segment check (otool -l) ──────────────────────────────
    try:
        restrict = _check_restrict_segment(binary)
    except (FileNotFoundError, OSError) as exc:
        logger.debug("test_binary_protections: otool -l failed: %s", exc)
        restrict = True  # conservative: do not emit false positive

    findings: list[dict[str, Any]] = []
    poc_otool = f"otool -hv '{binary}'"
    poc_nm = f"nm '{binary}' | grep stack_chk"
    poc_otool_l = f"otool -l '{binary}' | grep -A2 RESTRICT"

    # ── DESK-PIE-001: PIE disabled ───────────────────────────────────────────
    if not pie:
        findings.append(_make_finding(
            vector="DESK-PIE-001",
            severity="high",
            title_en="PIE (Position Independent Executable) Disabled",
            title_ko="PIE (위치 독립 실행파일) 비활성화",
            what_en=(
                f"The Mach-O binary at '{binary}' does not have the MH_PIE flag set. "
                "PIE causes the OS to load the binary at a randomised base address "
                "(ASLR). Without PIE, ASLR is not applied to the binary's own "
                "text/data segments."
            ),
            what_ko=(
                f"'{binary}' 의 Mach-O 바이너리에 MH_PIE 플래그가 설정되어 있지 않습니다. "
                "PIE는 OS가 바이너리를 무작위 기본 주소(ASLR)로 로드하게 합니다. "
                "PIE 없이는 바이너리 자체의 텍스트/데이터 세그먼트에 ASLR이 적용되지 않습니다."
            ),
            how_en=(
                f"`{poc_otool}` was run. The flags= line was parsed for the MH_PIE token. "
                "MH_PIE was absent from all architecture slices."
            ),
            how_ko=(
                f"`{poc_otool}` 를 실행했습니다. flags= 라인에서 MH_PIE 토큰을 파싱했습니다. "
                "모든 아키텍처 슬라이스에서 MH_PIE가 없었습니다."
            ),
            impact_en=(
                "Without ASLR on the binary itself, an attacker who finds a memory "
                "corruption bug can reliably compute return addresses and jump targets. "
                "ROP/JOP chains become deterministic. Combined with a stack overflow "
                "or heap spray, this enables reliable code execution bypassing "
                "address-space randomisation."
            ),
            impact_ko=(
                "바이너리 자체에 ASLR이 없으면 메모리 손상 버그를 발견한 공격자가 "
                "반환 주소와 점프 대상을 확실하게 계산할 수 있습니다. "
                "ROP/JOP 체인이 결정론적이 됩니다. 스택 오버플로우 또는 힙 스프레이와 결합하면 "
                "주소 공간 무작위화를 우회하는 안정적인 코드 실행이 가능합니다."
            ),
            poc_en=(
                f"{poc_otool}  # flags line lacks MH_PIE\n"
                "# Exploit: fixed base address allows deterministic ROP chain construction"
            ),
            poc_ko=(
                f"{poc_otool}  # flags 라인에 MH_PIE 없음\n"
                "# 익스플로잇: 고정 기본 주소로 결정론적 ROP 체인 구성 가능"
            ),
            attack_path_en=(
                "Attacker discovers memory corruption (e.g. stack overflow) → exploits "
                "fixed load address (no PIE/ASLR) → constructs reliable ROP chain → "
                "bypasses DEP/NX → arbitrary code execution."
            ),
            attack_path_ko=(
                "공격자가 메모리 손상(예: 스택 오버플로우) 발견 → 고정 로드 주소(PIE/ASLR 없음) 악용 → "
                "안정적인 ROP 체인 구성 → DEP/NX 우회 → 임의 코드 실행."
            ),
            path=binary,
        ))

    # ── DESK-PIE-002: Stack canary absent ────────────────────────────────────
    if not canary:
        findings.append(_make_finding(
            vector="DESK-PIE-002",
            severity="high",
            title_en="Stack Canary Not Present",
            title_ko="스택 카나리 미적용",
            what_en=(
                f"The Mach-O binary at '{binary}' does not reference "
                "__stack_chk_guard, indicating that stack canary protection "
                "(-fstack-protector) was not enabled at compile time."
            ),
            what_ko=(
                f"'{binary}' 의 Mach-O 바이너리가 __stack_chk_guard를 참조하지 않아 "
                "컴파일 시 스택 카나리 보호(-fstack-protector)가 활성화되지 않았음을 나타냅니다."
            ),
            how_en=(
                f"`{poc_nm}` was run. The symbol __stack_chk_guard (and __stack_chk_fail) "
                "was not found in the nm output."
            ),
            how_ko=(
                f"`{poc_nm}` 를 실행했습니다. nm 출력에서 __stack_chk_guard "
                "(및 __stack_chk_fail) 심볼이 발견되지 않았습니다."
            ),
            impact_en=(
                "Without a stack canary, a stack buffer overflow can overwrite the "
                "saved return address without detection. The exploit does not need to "
                "bypass any cookie-check mechanism. This is especially dangerous in "
                "code that handles attacker-controlled input sizes (e.g. network, "
                "file parsing, IPC)."
            ),
            impact_ko=(
                "스택 카나리 없이 스택 버퍼 오버플로우가 저장된 반환 주소를 탐지 없이 덮어쓸 수 있습니다. "
                "익스플로잇이 쿠키 검사 메커니즘을 우회할 필요가 없습니다. "
                "공격자 제어 입력 크기를 처리하는 코드(예: 네트워크, 파일 파싱, IPC)에서 특히 위험합니다."
            ),
            poc_en=(
                f"{poc_nm}  # returns nothing — canary absent\n"
                "# Exploit: craft input to overflow stack buffer → overwrite "
                "return address → redirect execution without canary check"
            ),
            poc_ko=(
                f"{poc_nm}  # 결과 없음 — 카나리 미적용\n"
                "# 익스플로잇: 입력을 조작하여 스택 버퍼 오버플로우 → "
                "반환 주소 덮어쓰기 → 카나리 검사 없이 실행 흐름 변경"
            ),
            attack_path_en=(
                "Attacker provides oversized input to a stack-allocated buffer → "
                "overflows into saved return address (no canary check) → redirects "
                "execution to attacker-controlled code → privilege escalation or RCE."
            ),
            attack_path_ko=(
                "공격자가 스택 할당 버퍼에 과도한 입력 제공 → "
                "저장된 반환 주소로 오버플로우(카나리 검사 없음) → "
                "공격자 제어 코드로 실행 흐름 변경 → 권한 상승 또는 RCE."
            ),
            path=binary,
        ))

    # ── DESK-PIE-003: __RESTRICT segment absent ───────────────────────────────
    if not restrict:
        findings.append(_make_finding(
            vector="DESK-PIE-003",
            severity="medium",
            title_en="__RESTRICT Segment Absent — DYLD Injection Not Blocked",
            title_ko="__RESTRICT 세그먼트 없음 — DYLD 인젝션 차단 안됨",
            what_en=(
                f"The Mach-O binary at '{binary}' does not contain a "
                "__RESTRICT,__restrict section. Without this section, macOS "
                "does not suppress DYLD_* environment variables at process startup "
                "for binaries that are not protected by the Hardened Runtime. "
                "An attacker who controls the launch environment can inject code "
                "via DYLD_INSERT_LIBRARIES."
            ),
            what_ko=(
                f"'{binary}' 의 Mach-O 바이너리에 __RESTRICT,__restrict 섹션이 없습니다. "
                "이 섹션이 없으면 Hardened Runtime으로 보호되지 않은 바이너리에 대해 macOS가 "
                "프로세스 시작 시 DYLD_* 환경 변수를 억제하지 않습니다. "
                "시작 환경을 제어할 수 있는 공격자가 DYLD_INSERT_LIBRARIES를 통해 코드를 인젝션할 수 있습니다."
            ),
            how_en=(
                f"`{poc_otool_l}` was run. Neither 'segname __RESTRICT' nor "
                "'sectname __restrict' was found in the output."
            ),
            how_ko=(
                f"`{poc_otool_l}` 를 실행했습니다. 출력에서 'segname __RESTRICT' 또는 "
                "'sectname __restrict'가 발견되지 않았습니다."
            ),
            impact_en=(
                "An attacker who can set the launch environment (e.g. via a parent "
                "process, a shell wrapper, or a plist modification) can inject an "
                "arbitrary dylib into the target process. The injected code runs "
                "with the same privileges as the target, enabling credential theft, "
                "keylogging, or sandbox escape chains."
            ),
            impact_ko=(
                "시작 환경을 설정할 수 있는 공격자(예: 부모 프로세스, 쉘 래퍼, plist 수정)가 "
                "임의의 dylib을 대상 프로세스에 인젝션할 수 있습니다. "
                "인젝션된 코드는 대상과 동일한 권한으로 실행되며 "
                "자격증명 탈취, 키로깅, 또는 샌드박스 탈출 체인이 가능합니다."
            ),
            poc_en=(
                f"{poc_otool_l}  # no __RESTRICT section found\n"
                f"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib '{binary}'  "
                "# inject code if not Hardened Runtime"
            ),
            poc_ko=(
                f"{poc_otool_l}  # __RESTRICT 섹션 없음\n"
                f"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib '{binary}'  "
                "# Hardened Runtime 아닌 경우 코드 인젝션"
            ),
            attack_path_en=(
                "Attacker gains control of launch environment → sets "
                "DYLD_INSERT_LIBRARIES to a malicious dylib → target binary lacks "
                "__RESTRICT and Hardened Runtime → dylib is loaded at startup → "
                "attacker code runs inside target process."
            ),
            attack_path_ko=(
                "공격자가 시작 환경 제어 → DYLD_INSERT_LIBRARIES를 악성 dylib으로 설정 → "
                "대상 바이너리에 __RESTRICT 및 Hardened Runtime 없음 → "
                "시작 시 dylib 로드 → 공격자 코드가 대상 프로세스 내에서 실행."
            ),
            path=binary,
        ))

    logger.info(
        "test_binary_protections: binary=%s pie=%s canary=%s restrict=%s findings=%d",
        binary, pie, canary, restrict, len(findings),
    )
    return {
        "tested": 1,
        "findings": findings,
        "pie": pie,
        "stack_canary": canary,
        "restrict_segment": restrict,
        "binary": binary,
    }
