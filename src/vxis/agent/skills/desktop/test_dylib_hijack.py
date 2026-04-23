"""Skill: test_dylib_hijack — phase-J / DESK-DYL-001|002|003.

Detects macOS dylib hijacking opportunities in a .app bundle or Mach-O binary
using `otool(1)`. Three distinct vectors are checked:

  DESK-DYL-001  Writable dylib path — an @rpath-relative dylib resolves to a
                directory that is writable by the current user. An attacker can
                drop a malicious dylib there and it will be loaded at next launch.

  DESK-DYL-002  Missing dylib (LC_LOAD_WEAK_DYLIB) — a weakly-linked dylib
                whose on-disk path does not exist. If an attacker can write the
                file at that path the binary loads it unconditionally.

  DESK-DYL-003  Multiple RPATH entries — the binary has >1 RPATH and at least
                one of them is writable by the current user. The dynamic linker
                resolves @rpath references in RPATH search order; controlling the
                first writable entry wins the race.

Brain should chain these findings with DESK-ENT-001 (disable-library-validation)
to assess the full exploitability of the hijack primitive.

Args:
    target_url: required — path to .app bundle, directory, or single Mach-O binary.
        For a Mach-O binary the skill climbs up to the enclosing .app bundle (up to
        6 levels) and then walks Contents/MacOS/ and Contents/Frameworks/.

Returns:
    {
      "scanned": int,           # total otool -L invocations that succeeded
      "findings": list[dict],   # Finding-shaped dicts (capped at 20)
      "macho_inspected": int,   # number of Mach-O binaries fed to otool
      "rpaths": list[str],      # union of all RPATH entries seen across binaries
      "root": str,              # resolved root path used for the walk
      "error": str,             # (optional) human-readable early-exit message
    }

All finding titles and descriptions are bilingual (English|||한국어) following the
WHAT/HOW/IMPACT/PoC/ATTACK PATH structure mandated by the VXIS report format.
"""
from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any

logger = logging.getLogger(__name__)

# Maximum Mach-O binaries to inspect per invocation.  Electron and large apps
# can have hundreds of dylibs in Frameworks/; inspecting all of them could take
# minutes.  10 binaries × 2 otool calls = 20 subprocesses — fast enough.
_MAX_BINARIES = 10

# Maximum findings returned to Brain.  A large Electron bundle with hundreds of
# @rpath references and a writable home dir would otherwise flood the context.
_MAX_FINDINGS = 20

# Regex to detect the weak-load command in `otool -l` output.
_RE_WEAK_CMD = re.compile(r"LC_LOAD_WEAK_DYLIB", re.IGNORECASE)

# Regex to parse one dylib entry from `otool -L` output.
# Each line looks like:
#   "\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, ...)"
#   "\t@rpath/Sparkle.framework/Versions/B/Sparkle (compatibility version ...)"
_RE_DYLIB_LINE = re.compile(r"^\t(.+?)\s+\(", re.MULTILINE)

# Regex to parse an RPATH value from `otool -l` output after LC_RPATH.
# The relevant section looks like:
#   Load command N
#        cmd LC_RPATH
#    cmdsize 48
#       path /usr/local/lib (offset 12)
_RE_RPATH_PATH = re.compile(r"^\s+path\s+(.+?)\s+\(offset", re.MULTILINE)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _walk_root(target: str) -> str:
    """Return the root directory to walk.

    Mirrors the pattern from test_local_storage_secrets and test_signature_audit:
    climb a Mach-O binary path up to the enclosing .app bundle so the whole
    Contents/ tree is covered, not just the single binary.
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
        # Bare Mach-O not inside a bundle — return its parent directory.
        return os.path.dirname(os.path.abspath(target))
    return target


def _collect_macho_binaries(root: str) -> list[str]:
    """Return up to _MAX_BINARIES Mach-O binary paths from the bundle.

    Walk strategy (priority order):
      1. Contents/MacOS/ — always contains the main executable(s).
      2. Contents/Frameworks/*/Versions/A/ — framework binaries.
      3. Bare directory root — if no .app structure found.

    Filtering: we skip files whose name looks like a pure dylib
    (ending in .dylib) because otool -L on a dylib is rarely interesting
    for hijack analysis (hijack requires a *consumer* binary).
    """
    candidates: list[str] = []

    macos_dir = os.path.join(root, "Contents", "MacOS")
    frameworks_dir = os.path.join(root, "Contents", "Frameworks")

    def _add_from(directory: str) -> None:
        if not os.path.isdir(directory):
            return
        for entry in os.scandir(directory):
            if entry.is_file() and not entry.name.endswith(".dylib"):
                candidates.append(entry.path)
                if len(candidates) >= _MAX_BINARIES:
                    return

    _add_from(macos_dir)

    if len(candidates) < _MAX_BINARIES and os.path.isdir(frameworks_dir):
        for fw_entry in os.scandir(frameworks_dir):
            if not fw_entry.is_dir():
                continue
            versions_a = os.path.join(fw_entry.path, "Versions", "A")
            if os.path.isdir(versions_a):
                _add_from(versions_a)
            if len(candidates) >= _MAX_BINARIES:
                break

    # Fallback: bare directory (not .app structure).
    if not candidates:
        for entry in os.scandir(root):
            if entry.is_file() and not entry.name.endswith(".dylib"):
                candidates.append(entry.path)
                if len(candidates) >= _MAX_BINARIES:
                    break

    return candidates[:_MAX_BINARIES]


def _run_otool_L(binary: str) -> list[str] | None:
    """Run `otool -L <binary>` and return a list of dylib path strings.

    Returns None if otool is not found or the binary cannot be parsed.
    Returns an empty list if there are no linked dylibs.
    """
    try:
        proc = subprocess.run(
            ["otool", "-L", binary],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        raise  # propagate so execute() can surface a clean error
    except OSError:
        return None

    if proc.returncode != 0:
        logger.debug("otool -L non-zero rc=%d for %s", proc.returncode, binary)
        return None

    output = (proc.stdout or "") + (proc.stderr or "")
    return _RE_DYLIB_LINE.findall(output)


def _run_otool_l_rpaths(binary: str) -> tuple[list[str], bool]:
    """Run `otool -l <binary>` and extract RPATH entries and weak-link presence.

    Returns:
        (rpaths, has_weak_dylib) where rpaths is a list of resolved RPATH strings
        and has_weak_dylib is True iff any LC_LOAD_WEAK_DYLIB command was found.
    """
    try:
        proc = subprocess.run(
            ["otool", "-l", binary],
            capture_output=True,
            text=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return [], False

    if proc.returncode != 0:
        return [], False

    output = (proc.stdout or "") + (proc.stderr or "")
    has_weak = bool(_RE_WEAK_CMD.search(output))

    rpaths: list[str] = []
    # Split on LC_RPATH so each segment contains one RPATH command block.
    for segment in output.split("LC_RPATH"):
        m = _RE_RPATH_PATH.search(segment)
        if m:
            rpaths.append(m.group(1).strip())

    return rpaths, has_weak


def _resolve_rpath(rpath_template: str, rpaths: list[str]) -> list[str]:
    """Resolve an @rpath/... dylib reference against each RPATH entry.

    Returns a list of candidate absolute paths (one per RPATH entry).
    """
    suffix = rpath_template[len("@rpath"):]  # e.g. "/Sparkle.framework/..."
    return [rp.rstrip("/") + suffix for rp in rpaths]


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
    binary: str,
) -> dict[str, Any]:
    """Build a Finding-shaped dict matching VXIS report format."""
    return {
        "path": binary,
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


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Inspect Mach-O binaries in the target bundle for dylib hijack vectors."""
    root = _walk_root(target_url)

    if not os.path.exists(root):
        return {
            "scanned": 0,
            "findings": [],
            "macho_inspected": 0,
            "rpaths": [],
            "root": root,
            "error": f"path not found: {root}",
        }

    binaries = _collect_macho_binaries(root)
    if not binaries:
        return {
            "scanned": 0,
            "findings": [],
            "macho_inspected": 0,
            "rpaths": [],
            "root": root,
            "error": "no candidate Mach-O binaries found under root",
        }

    findings: list[dict[str, Any]] = []
    all_rpaths: list[str] = []
    scanned = 0
    macho_inspected = 0

    for binary in binaries:
        # ── Step 1: get linked dylibs ─────────────────────────────────────────
        try:
            dylibs = _run_otool_L(binary)
        except FileNotFoundError:
            return {
                "scanned": scanned,
                "findings": findings[:_MAX_FINDINGS],
                "macho_inspected": macho_inspected,
                "rpaths": all_rpaths,
                "root": root,
                "error": "otool binary not found — is this a macOS system?",
            }

        if dylibs is None:
            # otool returned non-zero — skip this binary, continue
            continue

        # ── Step 2: get RPATHs and weak-link flag ─────────────────────────────
        rpaths, has_weak = _run_otool_l_rpaths(binary)

        scanned += 1
        macho_inspected += 1
        all_rpaths.extend(rp for rp in rpaths if rp not in all_rpaths)

        # ── Step 3: DESK-DYL-001 — writable resolved @rpath dir ──────────────
        for dylib in dylibs:
            if not dylib.startswith("@rpath/"):
                continue
            candidates = _resolve_rpath(dylib, rpaths)
            for candidate_path in candidates:
                candidate_dir = os.path.dirname(candidate_path)
                if not candidate_dir:
                    continue
                dir_exists = os.path.isdir(candidate_dir)
                dir_writable = dir_exists and os.access(candidate_dir, os.W_OK)
                if dir_writable and len(findings) < _MAX_FINDINGS:
                    findings.append(_make_finding(
                        vector="DESK-DYL-001",
                        severity="high",
                        title_en="Writable dylib path",
                        title_ko="쓰기 가능한 dylib 경로",
                        what_en=(
                            f"The binary '{binary}' references '{dylib}' via @rpath. "
                            f"The resolved candidate path '{candidate_path}' sits in a "
                            f"directory '{candidate_dir}' that is writable by the current user."
                        ),
                        what_ko=(
                            f"바이너리 '{binary}'가 @rpath를 통해 '{dylib}'를 참조합니다. "
                            f"해석된 후보 경로 '{candidate_path}'가 현재 사용자가 "
                            f"쓸 수 있는 디렉토리 '{candidate_dir}'에 위치합니다."
                        ),
                        how_en=(
                            "otool -L was used to list linked dylibs. "
                            "otool -l was used to extract RPATH entries. "
                            "Each @rpath reference was resolved against each RPATH entry "
                            "and the resulting directory was checked for write permission "
                            "via os.access(dir, os.W_OK)."
                        ),
                        how_ko=(
                            "otool -L로 링크된 dylib 목록을 수집하고, "
                            "otool -l로 RPATH 항목을 추출했습니다. "
                            "각 @rpath 참조를 RPATH 항목과 조합해 해석한 뒤 "
                            "os.access(dir, os.W_OK)로 쓰기 가능 여부를 확인했습니다."
                        ),
                        impact_en=(
                            "An attacker who can place a malicious dylib at "
                            f"'{candidate_path}' will have it loaded automatically "
                            "on next application launch, achieving code execution "
                            "under the victim application's process identity and entitlements. "
                            "Combine with DESK-ENT-001 (disabled library validation) "
                            "for guaranteed load even on hardened targets."
                        ),
                        impact_ko=(
                            f"공격자가 '{candidate_path}'에 악성 dylib를 배치하면 "
                            "다음 애플리케이션 실행 시 자동으로 로드되어 피해자 "
                            "프로세스의 신원과 entitlement 하에 코드 실행이 가능합니다. "
                            "DESK-ENT-001 (라이브러리 검증 비활성화)과 결합하면 "
                            "강화된 타겟에서도 로드가 보장됩니다."
                        ),
                        poc_en=(
                            f"cp /path/to/malicious.dylib '{candidate_path}' && "
                            f"open '{root}'"
                        ),
                        poc_ko=(
                            f"cp /path/to/malicious.dylib '{candidate_path}' && "
                            f"open '{root}'"
                        ),
                        attack_path_en=(
                            f"Attacker writes malicious dylib to '{candidate_path}' → "
                            f"victim launches '{root}' → dyld resolves @rpath against "
                            f"RPATH list → malicious dylib loaded first → "
                            "attacker code runs inside victim process."
                        ),
                        attack_path_ko=(
                            f"공격자가 '{candidate_path}'에 악성 dylib 배치 → "
                            f"피해자가 '{root}' 실행 → dyld가 RPATH 목록에서 "
                            f"@rpath 해석 → 악성 dylib 우선 로드 → "
                            "피해자 프로세스 내에서 공격자 코드 실행."
                        ),
                        binary=binary,
                    ))

        # ── Step 4: DESK-DYL-002 — missing weak dylib ────────────────────────
        if has_weak and len(findings) < _MAX_FINDINGS:
            for dylib in dylibs:
                # Weak dylibs can use any load path scheme.  We check only those
                # that are not @rpath-relative (absolute or @executable_path).
                # For @rpath dylibs under the weak-load flag we check all
                # candidate paths for absence.
                if dylib.startswith("@rpath/"):
                    candidates = _resolve_rpath(dylib, rpaths) if rpaths else []
                    missing_candidates = [p for p in candidates if not os.path.exists(p)]
                    if candidates and len(missing_candidates) == len(candidates):
                        # All resolved candidates are missing — plant any one of them.
                        target_path = candidates[0]
                        if len(findings) < _MAX_FINDINGS:
                            findings.append(_make_finding(
                                vector="DESK-DYL-002",
                                severity="medium",
                                title_en="Missing dylib (LC_LOAD_WEAK_DYLIB)",
                                title_ko="누락된 dylib (LC_LOAD_WEAK_DYLIB)",
                                what_en=(
                                    f"Binary '{binary}' weakly links '{dylib}' but none of "
                                    f"the resolved candidate paths exist on disk. "
                                    f"Closest candidate: '{target_path}'."
                                ),
                                what_ko=(
                                    f"바이너리 '{binary}'가 '{dylib}'를 약한 링크(LC_LOAD_WEAK_DYLIB)로 "
                                    f"참조하지만 해석된 후보 경로가 디스크에 존재하지 않습니다. "
                                    f"가장 가까운 후보: '{target_path}'."
                                ),
                                how_en=(
                                    "otool -l was parsed for LC_LOAD_WEAK_DYLIB commands. "
                                    "The corresponding dylib path was resolved against each "
                                    "RPATH entry and checked for existence on disk."
                                ),
                                how_ko=(
                                    "otool -l 출력에서 LC_LOAD_WEAK_DYLIB 커맨드를 파싱했습니다. "
                                    "해당 dylib 경로를 RPATH 항목과 조합해 해석하고 "
                                    "디스크에서 존재 여부를 확인했습니다."
                                ),
                                impact_en=(
                                    "LC_LOAD_WEAK_DYLIB means the binary continues to run "
                                    "even if the dylib is absent.  If an attacker can create a "
                                    f"file at '{target_path}', dyld will load it on next launch, "
                                    "granting code execution inside the victim process."
                                ),
                                impact_ko=(
                                    "LC_LOAD_WEAK_DYLIB는 dylib가 없어도 바이너리가 계속 실행됨을 "
                                    "의미합니다. 공격자가 "
                                    f"'{target_path}'에 파일을 생성할 수 있으면 "
                                    "다음 실행 시 dyld가 이를 로드해 피해자 프로세스 내 "
                                    "코드 실행 권한을 얻습니다."
                                ),
                                poc_en=(
                                    f"cp /path/to/malicious.dylib '{target_path}' && "
                                    f"open '{root}'"
                                ),
                                poc_ko=(
                                    f"cp /path/to/malicious.dylib '{target_path}' && "
                                    f"open '{root}'"
                                ),
                                attack_path_en=(
                                    f"Attacker creates '{target_path}' with malicious dylib → "
                                    f"victim launches '{root}' → dyld finds the file and loads it "
                                    "despite weak-link flag → attacker code executes."
                                ),
                                attack_path_ko=(
                                    f"공격자가 악성 dylib로 '{target_path}' 생성 → "
                                    f"피해자가 '{root}' 실행 → dyld가 파일을 발견해 로드 "
                                    "(약한 링크 플래그에도 불구하고) → 공격자 코드 실행."
                                ),
                                binary=binary,
                            ))
                elif dylib.startswith(("/", "@executable_path", "@loader_path")):
                    # Absolute or relative-to-binary path.
                    path_to_check = dylib
                    if not os.path.exists(path_to_check) and len(findings) < _MAX_FINDINGS:
                        findings.append(_make_finding(
                            vector="DESK-DYL-002",
                            severity="medium",
                            title_en="Missing dylib (LC_LOAD_WEAK_DYLIB)",
                            title_ko="누락된 dylib (LC_LOAD_WEAK_DYLIB)",
                            what_en=(
                                f"Binary '{binary}' weakly links '{dylib}' "
                                "but that path does not exist on disk."
                            ),
                            what_ko=(
                                f"바이너리 '{binary}'가 '{dylib}'를 약한 링크로 참조하지만 "
                                "해당 경로가 디스크에 존재하지 않습니다."
                            ),
                            how_en=(
                                "otool -l was parsed for LC_LOAD_WEAK_DYLIB commands. "
                                "The dylib path was checked directly for existence."
                            ),
                            how_ko=(
                                "otool -l 출력에서 LC_LOAD_WEAK_DYLIB 커맨드를 파싱했습니다. "
                                "dylib 경로의 존재 여부를 직접 확인했습니다."
                            ),
                            impact_en=(
                                "If an attacker can create a file at the missing path "
                                f"'{dylib}', dyld will load it on the next application launch."
                            ),
                            impact_ko=(
                                f"공격자가 누락된 경로 '{dylib}'에 파일을 생성할 수 있으면 "
                                "다음 애플리케이션 실행 시 dyld가 이를 로드합니다."
                            ),
                            poc_en=(
                                f"cp /path/to/malicious.dylib '{dylib}' && "
                                f"open '{root}'"
                            ),
                            poc_ko=(
                                f"cp /path/to/malicious.dylib '{dylib}' && "
                                f"open '{root}'"
                            ),
                            attack_path_en=(
                                f"Attacker plants malicious dylib at '{dylib}' → "
                                f"victim launches '{root}' → dyld loads it → code execution."
                            ),
                            attack_path_ko=(
                                f"공격자가 '{dylib}'에 악성 dylib 배치 → "
                                f"피해자가 '{root}' 실행 → dyld 로드 → 코드 실행."
                            ),
                            binary=binary,
                        ))

        # ── Step 5: DESK-DYL-003 — multiple RPATHs with ≥1 writable ─────────
        if len(rpaths) > 1 and len(findings) < _MAX_FINDINGS:
            writable_rpaths = [rp for rp in rpaths if os.path.isdir(rp) and os.access(rp, os.W_OK)]
            if writable_rpaths and len(findings) < _MAX_FINDINGS:
                findings.append(_make_finding(
                    vector="DESK-DYL-003",
                    severity="medium",
                    title_en="Multiple RPATH entries",
                    title_ko="다중 RPATH 항목",
                    what_en=(
                        f"Binary '{binary}' has {len(rpaths)} RPATH entries "
                        f"and {len(writable_rpaths)} of them are writable by the "
                        f"current user: {writable_rpaths}. "
                        "dyld resolves @rpath references in order — the first entry "
                        "whose resolved path exists wins."
                    ),
                    what_ko=(
                        f"바이너리 '{binary}'에 RPATH 항목이 {len(rpaths)}개 있으며 "
                        f"그 중 {len(writable_rpaths)}개가 현재 사용자에 의해 "
                        f"쓰기 가능합니다: {writable_rpaths}. "
                        "dyld는 @rpath 참조를 순서대로 해석하며 — 먼저 존재하는 "
                        "해석된 경로가 우선권을 가집니다."
                    ),
                    how_en=(
                        "otool -l was parsed for all LC_RPATH entries. "
                        "Each RPATH directory was checked for write permission "
                        "via os.access(dir, os.W_OK)."
                    ),
                    how_ko=(
                        "otool -l 출력에서 모든 LC_RPATH 항목을 파싱했습니다. "
                        "각 RPATH 디렉토리를 os.access(dir, os.W_OK)로 "
                        "쓰기 가능 여부를 확인했습니다."
                    ),
                    impact_en=(
                        "With multiple RPATHs and at least one writable, an attacker "
                        "can plant a malicious dylib in the writable RPATH early in the "
                        "search order so it shadows a legitimate dylib elsewhere in the "
                        "list, achieving search-order hijacking."
                    ),
                    impact_ko=(
                        "다중 RPATH 중 쓰기 가능한 항목이 있으면 공격자가 "
                        "검색 순서 초반의 쓰기 가능한 RPATH에 악성 dylib를 심어 "
                        "목록 후반의 정상 dylib를 가릴 수 있습니다 — "
                        "검색 순서 하이재킹이 달성됩니다."
                    ),
                    poc_en=(
                        f"# First writable RPATH: '{writable_rpaths[0]}'\n"
                        f"cp /path/to/malicious.dylib '{writable_rpaths[0]}/<target_dylib_name>' && "
                        f"open '{root}'"
                    ),
                    poc_ko=(
                        f"# 첫 번째 쓰기 가능 RPATH: '{writable_rpaths[0]}'\n"
                        f"cp /path/to/malicious.dylib '{writable_rpaths[0]}/<target_dylib_name>' && "
                        f"open '{root}'"
                    ),
                    attack_path_en=(
                        f"Attacker plants malicious dylib in '{writable_rpaths[0]}' → "
                        "dyld resolves @rpath references in RPATH order → "
                        "malicious dylib found before legitimate one → "
                        "attacker code executes inside victim process."
                    ),
                    attack_path_ko=(
                        f"공격자가 '{writable_rpaths[0]}'에 악성 dylib 배치 → "
                        "dyld가 RPATH 순서로 @rpath 참조 해석 → "
                        "정상 dylib보다 먼저 악성 dylib 발견 → "
                        "피해자 프로세스 내에서 공격자 코드 실행."
                    ),
                    binary=binary,
                ))

    logger.info(
        "test_dylib_hijack: root=%s macho_inspected=%d scanned=%d findings=%d rpaths=%d",
        root, macho_inspected, scanned, len(findings), len(all_rpaths),
    )
    return {
        "scanned": scanned,
        "findings": findings[:_MAX_FINDINGS],
        "macho_inspected": macho_inspected,
        "rpaths": all_rpaths,
        "root": root,
    }
