"""Skill: test_ipc_injection — phase-F / DESK-IPC-001.

macOS adaptation of the IPC injection vector. Inspects XPC services
bundled inside a .app to detect two classes of risk:

  DESK-IPC-001  Writable XPC bundle — the XPC service bundle directory
                is group- or world-writable, allowing an attacker with
                local access to plant a malicious binary or plist before
                the service is (re)launched.

  DESK-IPC-001  Typosquat Mach service name — a bundled XPC service
                registers a Mach service name that starts with
                "com.apple." but whose bundle identifier does NOT match
                the "com.apple.*" namespace, indicating an attempt to
                impersonate an Apple system service.

The skill does NOT use subprocess for its main checks — it reads
Info.plist files and calls os.stat(). This keeps it fast and safe to
run in any environment.

Args:
    target_url: required — path to .app bundle, directory, or binary.
        The skill resolves to the enclosing .app root automatically (up
        to 6 levels). It then looks for:
          <root>/Contents/XPCServices/*.xpc/Contents/Info.plist

Returns:
    {
      "vulnerable": bool,        # True iff >=1 finding emitted
      "findings": list[dict],    # Finding-shaped dicts (bilingual)
      "tested": int,             # Number of XPC bundles inspected
      "skipped_reason": str,     # Present + non-empty only on early exit
    }

On non-darwin platforms the skill executes identically (no sys.platform
guard) because all checks are pure Python / POSIX stat — but callers
should note that the XPCServices layout is macOS-specific, so `tested`
will almost always be 0 on other platforms.
"""
from __future__ import annotations

import logging
import os
import plistlib
import stat
from typing import Any

logger = logging.getLogger(__name__)

# Mach service prefix used by Apple system daemons.
_APPLE_PREFIX = "com.apple."


def _walk_root(target: str) -> str:
    """Resolve a path to the nearest enclosing .app bundle (up to 6 levels)."""
    if os.path.isdir(target):
        if target.endswith(".app"):
            return target
        # Maybe it is already inside a bundle — climb up.
    if os.path.isfile(target):
        cur = os.path.abspath(target)
        for _ in range(6):
            if cur.endswith(".app"):
                return cur
            parent = os.path.dirname(cur)
            if parent == cur:
                break
            cur = parent
    return target


def _is_other_writable(path: str) -> bool:
    """Return True if the path is group- or world-writable by someone
    other than the current process owner.

    We check S_IWGRP (group write) and S_IWOTH (others write). Both are
    dangerous for a privileged XPC service bundle because any process in
    the group or any local user could modify the bundle before relaunch.
    """
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return False
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def _is_typosquat(mach_service_name: str, bundle_id: str) -> bool:
    """Return True iff the Mach service name starts with 'com.apple.'
    but the bundle identifier does NOT also start with 'com.apple.'.

    This pattern is used by malware to register a service name that
    looks like an Apple system daemon while actually being a third-party
    (or attacker-controlled) process.
    """
    if not mach_service_name.startswith(_APPLE_PREFIX):
        return False
    # Allow legitimate Apple apps (com.apple.*) to register com.apple.* services.
    return not bundle_id.startswith(_APPLE_PREFIX)


def _read_bundle_id(info_plist: dict[str, Any]) -> str:
    """Extract CFBundleIdentifier from a parsed Info.plist dict."""
    return str(info_plist.get("CFBundleIdentifier", ""))


def _read_mach_services(info_plist: dict[str, Any]) -> list[str]:
    """Return the list of Mach service names declared in MachServices."""
    mach_services = info_plist.get("MachServices", {})
    if isinstance(mach_services, dict):
        return list(mach_services.keys())
    return []


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
    """Inspect XPC services inside a .app bundle and return structured findings."""

    _empty: dict[str, Any] = {
        "vulnerable": False,
        "findings": [],
        "tested": 0,
    }

    root = _walk_root(target_url)

    if not os.path.exists(root):
        return {
            **_empty,
            "skipped_reason": f"path not found: {root}",
        }

    xpc_services_dir = os.path.join(root, "Contents", "XPCServices")

    if not os.path.isdir(xpc_services_dir):
        # No XPCServices directory — nothing to test.
        return {
            **_empty,
            "skipped_reason": None,
        }

    findings: list[dict[str, Any]] = []
    tested = 0

    try:
        entries = sorted(os.listdir(xpc_services_dir))
    except OSError as exc:
        return {
            **_empty,
            "skipped_reason": f"cannot list XPCServices: {exc}",
        }

    for entry in entries:
        if not entry.endswith(".xpc"):
            continue

        xpc_path = os.path.join(xpc_services_dir, entry)
        if not os.path.isdir(xpc_path):
            continue

        info_plist_path = os.path.join(xpc_path, "Contents", "Info.plist")
        if not os.path.isfile(info_plist_path):
            logger.debug("test_ipc_injection: no Info.plist at %s — skipping", xpc_path)
            tested += 1  # counted as inspected even without a plist
            continue

        # Parse the plist.
        try:
            with open(info_plist_path, "rb") as fh:
                plist_data: dict[str, Any] = plistlib.load(fh)
        except Exception as exc:  # noqa: BLE001 — plist parse is best-effort
            logger.debug("test_ipc_injection: plist parse error at %s: %s", info_plist_path, exc)
            tested += 1
            continue

        tested += 1
        bundle_id = _read_bundle_id(plist_data)
        mach_services = _read_mach_services(plist_data)

        # ── Check 1: Writable XPC bundle ────────────────────────────────────
        if _is_other_writable(xpc_path):
            findings.append(_make_finding(
                vector="DESK-IPC-001",
                severity="high",
                title_en="Writable XPC Service Bundle",
                title_ko="쓰기 가능한 XPC 서비스 번들",
                what_en=(
                    f"The XPC service bundle at '{xpc_path}' is group- or world-writable. "
                    "An attacker with local access can modify the bundle contents "
                    "(binary or Info.plist) before the service is relaunched by launchd."
                ),
                what_ko=(
                    f"'{xpc_path}' 의 XPC 서비스 번들이 그룹 또는 전체 쓰기 가능 상태입니다. "
                    "로컬 접근 권한을 가진 공격자가 launchd에 의해 서비스가 재시작되기 전에 "
                    "번들 내용(바이너리 또는 Info.plist)을 수정할 수 있습니다."
                ),
                how_en=(
                    f"os.stat('{xpc_path}') revealed group-write (S_IWGRP) or "
                    "world-write (S_IWOTH) permission bits set on the XPC bundle directory."
                ),
                how_ko=(
                    f"os.stat('{xpc_path}') 결과 XPC 번들 디렉토리에 그룹 쓰기(S_IWGRP) 또는 "
                    "기타 쓰기(S_IWOTH) 권한 비트가 설정되어 있음이 확인되었습니다."
                ),
                impact_en=(
                    "Privilege escalation via XPC service impersonation. The attacker "
                    "replaces the XPC binary with a malicious payload that inherits the "
                    "service's entitlements and sandbox permissions when launchd restarts it. "
                    "This is especially critical for services with com.apple.security.cs.* "
                    "entitlements."
                ),
                impact_ko=(
                    "XPC 서비스 위장을 통한 권한 상승. 공격자가 XPC 바이너리를 악성 페이로드로 교체하면 "
                    "launchd가 서비스를 재시작할 때 해당 서비스의 entitlement와 샌드박스 권한을 상속합니다. "
                    "com.apple.security.cs.* entitlement를 가진 서비스의 경우 특히 치명적입니다."
                ),
                poc_en=(
                    f"ls -la '{xpc_services_dir}'  "
                    f"# shows group/world write on {entry}\n"
                    f"cp /path/to/malicious '{xpc_path}/Contents/MacOS/'  "
                    "# plant payload\n"
                    "# wait for launchd restart → malicious code runs with XPC entitlements"
                ),
                poc_ko=(
                    f"ls -la '{xpc_services_dir}'  "
                    f"# {entry}에 그룹/전체 쓰기 권한 확인\n"
                    f"cp /path/to/malicious '{xpc_path}/Contents/MacOS/'  "
                    "# 악성 페이로드 배치\n"
                    "# launchd 재시작 대기 → 악성 코드가 XPC entitlement로 실행"
                ),
                attack_path_en=(
                    "Local attacker discovers writable XPC bundle → plants malicious binary → "
                    "triggers service restart (e.g. reboot, crash) → code executes under "
                    "XPC service identity with its entitlements → privilege escalation or "
                    "sandbox escape."
                ),
                attack_path_ko=(
                    "로컬 공격자가 쓰기 가능한 XPC 번들 발견 → 악성 바이너리 배치 → "
                    "서비스 재시작 유발(예: 재부팅, 크래시) → XPC 서비스 식별자와 "
                    "entitlement로 코드 실행 → 권한 상승 또는 샌드박스 탈출."
                ),
                path=xpc_path,
            ))

        # ── Check 2: Typosquat Mach service name ────────────────────────────
        for svc_name in mach_services:
            if _is_typosquat(svc_name, bundle_id):
                findings.append(_make_finding(
                    vector="DESK-IPC-001",
                    severity="medium",
                    title_en="Mach Service Name Impersonates Apple Namespace (Typosquat)",
                    title_ko="Apple 네임스페이스를 흉내내는 Mach 서비스 이름 (타이포스쿼팅)",
                    what_en=(
                        f"The XPC service '{entry}' (bundle ID: '{bundle_id}') registers "
                        f"a Mach service named '{svc_name}' which starts with 'com.apple.' "
                        "but the bundle is NOT an Apple-signed system component. "
                        "This pattern is used by malware to blend into the system service "
                        "namespace and evade detection."
                    ),
                    what_ko=(
                        f"XPC 서비스 '{entry}' (번들 ID: '{bundle_id}')가 "
                        f"'com.apple.'로 시작하는 Mach 서비스 이름 '{svc_name}'을 등록했지만 "
                        "이 번들은 Apple 서명 시스템 구성요소가 아닙니다. "
                        "이 패턴은 악성코드가 시스템 서비스 네임스페이스에 위장하여 탐지를 회피하는 데 사용됩니다."
                    ),
                    how_en=(
                        f"Info.plist at '{info_plist_path}' was parsed. "
                        f"MachServices key contains '{svc_name}' which starts with 'com.apple.' "
                        f"but CFBundleIdentifier is '{bundle_id}' (not in com.apple.* namespace)."
                    ),
                    how_ko=(
                        f"'{info_plist_path}' 의 Info.plist를 파싱했습니다. "
                        f"MachServices 키에 'com.apple.'로 시작하는 '{svc_name}'이 있지만 "
                        f"CFBundleIdentifier는 '{bundle_id}'로 com.apple.* 네임스페이스가 아닙니다."
                    ),
                    impact_en=(
                        "A Mach service name in the com.apple.* namespace may be confused "
                        "with a legitimate Apple service by IPC clients performing name-based "
                        "trust decisions. On older macOS versions this can enable "
                        "service registration races. Persistence and evasion are primary risks."
                    ),
                    impact_ko=(
                        "com.apple.* 네임스페이스의 Mach 서비스 이름은 이름 기반 신뢰 결정을 수행하는 "
                        "IPC 클라이언트에 의해 정상 Apple 서비스로 오인될 수 있습니다. "
                        "구버전 macOS에서는 서비스 등록 경쟁 상태를 유발할 수 있습니다. "
                        "지속성 및 탐지 회피가 주요 위험입니다."
                    ),
                    poc_en=(
                        f"plutil -p '{info_plist_path}'  "
                        f"# MachServices: {svc_name} (not com.apple.*)\n"
                        "# Client code trusting com.apple.* prefix may accept this service "
                        "as legitimate."
                    ),
                    poc_ko=(
                        f"plutil -p '{info_plist_path}'  "
                        f"# MachServices: {svc_name} (com.apple.* 아님)\n"
                        "# com.apple.* 접두사를 신뢰하는 클라이언트 코드가 이 서비스를 "
                        "정상으로 수용할 수 있습니다."
                    ),
                    attack_path_en=(
                        "Attacker installs third-party app with com.apple.* Mach service "
                        "name → IPC client performs name-based trust → attacker intercepts "
                        "or influences IPC messages intended for Apple services → information "
                        "disclosure or privilege escalation."
                    ),
                    attack_path_ko=(
                        "공격자가 com.apple.* Mach 서비스 이름을 가진 서드파티 앱 설치 → "
                        "IPC 클라이언트가 이름 기반 신뢰 수행 → Apple 서비스를 대상으로 한 "
                        "IPC 메시지 가로채기 또는 영향 → 정보 노출 또는 권한 상승."
                    ),
                    path=xpc_path,
                ))

    logger.info(
        "test_ipc_injection: root=%s tested=%d findings=%d",
        root, tested, len(findings),
    )
    return {
        "vulnerable": len(findings) > 0,
        "findings": findings,
        "tested": tested,
    }
