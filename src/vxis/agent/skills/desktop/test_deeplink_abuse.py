"""Skill: test_deeplink_abuse — phase-J / DESK-DLK-001|002|003.

Parses the Info.plist of a macOS .app bundle and flags risky URL scheme
(deep link) registrations **without launching the app**. Static analysis
only — no Frida, no app execution.

Detection logic:
  DESK-DLK-001 (medium) — scheme name is generic / collidable:
      in _GENERIC_SCHEMES  OR  matches ^[a-z]{1,3}$ (too short).
  DESK-DLK-002 (high)   — CFBundleURLTypes entry lacks CFBundleTypeRole.
      Apps without a declared role accept ALL incoming URLs unconditionally.
  DESK-DLK-003 (medium) — total scheme count across all entries > 5.
      Broad attack surface; higher probability of squatting / collision.

Args:
    target_url: required — path to .app bundle, directory, or file inside
        the bundle. The skill climbs up to locate Contents/Info.plist.

Returns:
    {
      "scanned": int,           # 1 if Info.plist was parsed, else 0
      "findings": list[dict],   # one dict per vector hit
      "schemes": list[str],     # all registered scheme strings (flat)
      "url_types": list[dict],  # raw CFBundleURLTypes list (serialisable)
      "root": str,              # resolved .app root path
      "error"?: str,            # present on failure (not a finding)
    }
"""
from __future__ import annotations

import logging
import os
import plistlib
import re
from typing import Any

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Well-known generic / collidable scheme names that multiple apps or
# an attacker's squatting app could register to intercept traffic.
_GENERIC_SCHEMES: frozenset[str] = frozenset({
    "app", "update", "auth", "oauth", "callback", "login", "open",
    "file", "data", "fb", "twitter",
})

# Any all-lowercase scheme whose total length is 1–3 chars is also
# treated as generic (trivially guessable / collidable).
_SHORT_SCHEME_RE: re.Pattern[str] = re.compile(r"^[a-z]{1,3}$")


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
    # Path doesn't exist yet (e.g. tests with tmp_path) — return as-is so
    # the Info.plist lookup can produce a clear "not found" error.
    return target


# ─────────────────────────────────────────────────────────────────────────────
# Finding builders
# ─────────────────────────────────────────────────────────────────────────────

def _finding_dlk_001(scheme: str, root: str) -> dict[str, Any]:
    """DESK-DLK-001 — generic / collidable URL scheme."""
    return {
        "vector": "DESK-DLK-001",
        "severity": "medium",
        "scheme": scheme,
        "title": (
            f"Generic URL scheme registered: {scheme}"
            "|||"
            f"일반적 URL scheme 등록: {scheme}"
        ),
        "description": (
            # ── English ──────────────────────────────────────────────────────
            f"WHAT: The application bundle at '{root}' registers the URL scheme "
            f"'{scheme}://', which is a well-known generic or very short name.\n"
            f"HOW: Parsed CFBundleURLTypes in Contents/Info.plist. "
            f"'{scheme}' matches the collidable scheme list or the short-scheme "
            f"pattern (^[a-z]{{1,3}}$).\n"
            f"IMPACT: On macOS, the first-registered handler wins. A malicious "
            f"or competing app can register the same scheme before this app is "
            f"launched and intercept every '{scheme}://' invocation — including "
            f"OAuth callbacks, session tokens, and authentication codes.\n"
            f"PoC: Open a browser on the same machine and navigate to "
            f"'{scheme}://attacker_payload'. If another app registers this "
            f"scheme first, macOS routes the URL there instead.\n"
            f"ATTACK PATH: Attacker publishes app with '{scheme}://' → victim "
            f"clicks legitimate auth link → attacker app receives OAuth code / "
            f"session token → account takeover.\n"
            # ── Korean ────────────────────────────────────────────────────────
            "|||"
            f"WHAT: '{root}' 앱 번들이 '{scheme}://' URL scheme을 등록하고 있으며, "
            f"이는 널리 알려진 일반적인 이름이거나 매우 짧은 이름입니다.\n"
            f"HOW: Contents/Info.plist의 CFBundleURLTypes를 파싱했습니다. "
            f"'{scheme}'은 충돌 가능 scheme 목록 또는 짧은 scheme 패턴(^[a-z]{{1,3}}$)에 해당합니다.\n"
            f"IMPACT: macOS에서는 먼저 등록된 핸들러가 우선권을 가집니다. "
            f"악성 앱이 동일한 scheme을 이 앱보다 먼저 등록하면 "
            f"OAuth 콜백, 세션 토큰, 인증 코드 등 '{scheme}://' 호출을 모두 가로챌 수 있습니다.\n"
            f"PoC: 동일 머신의 브라우저에서 '{scheme}://attacker_payload'로 이동합니다. "
            f"다른 앱이 이 scheme을 먼저 등록했다면 macOS가 해당 URL을 그 앱으로 라우팅합니다.\n"
            f"ATTACK PATH: 공격자가 '{scheme}://'를 등록한 앱 배포 → "
            f"피해자가 정상 인증 링크 클릭 → 공격자 앱이 OAuth 코드/세션 토큰 수신 → "
            f"계정 탈취."
        ),
        "root": root,
    }


def _finding_dlk_002(schemes: list[str], root: str) -> dict[str, Any]:
    """DESK-DLK-002 — CFBundleURLTypes entry with no CFBundleTypeRole."""
    schemes_str = ", ".join(f"{s}://" for s in schemes)
    first = schemes[0] if schemes else "unknown"
    return {
        "vector": "DESK-DLK-002",
        "severity": "high",
        "schemes": schemes,
        "title": (
            "Privileged URL scheme without role declaration"
            "|||"
            "권한 있는 URL scheme 의 role 미선언"
        ),
        "description": (
            # ── English ──────────────────────────────────────────────────────
            f"WHAT: A CFBundleURLTypes entry in '{root}/Contents/Info.plist' "
            f"registers the scheme(s) [{schemes_str}] but omits the "
            f"CFBundleTypeRole key (expected values: 'Viewer', 'Editor', 'Shell', "
            f"'QLGenerator', or 'None').\n"
            f"HOW: Parsed CFBundleURLTypes; CFBundleTypeRole key was absent or "
            f"empty for the entry covering these schemes.\n"
            f"IMPACT: Without a declared role the OS treats the app as an "
            f"unconditional handler. Any deep link — including those carrying "
            f"sensitive payloads (auth codes, file references, IPC commands) — "
            f"is delivered without a user-visible role hint, removing one layer "
            f"of user-consent friction and making exploitation silently transparent.\n"
            f"PoC: Paste '{first}://attacker_controlled_payload' into Safari's "
            f"address bar. macOS will open the app without displaying a role "
            f"confirmation, confirming the unconditional handler behaviour.\n"
            f"ATTACK PATH: Attacker crafts a malicious '{first}://' URL → "
            f"embedded in email / web page → victim clicks → app processes "
            f"payload without consent prompt → privilege action executed.\n"
            # ── Korean ────────────────────────────────────────────────────────
            "|||"
            f"WHAT: '{root}/Contents/Info.plist'의 CFBundleURLTypes 항목이 "
            f"scheme [{schemes_str}]을 등록하지만 CFBundleTypeRole 키가 없습니다 "
            f"(허용 값: 'Viewer', 'Editor', 'Shell', 'QLGenerator', 'None').\n"
            f"HOW: CFBundleURLTypes를 파싱한 결과, 해당 schemes를 포함하는 항목에서 "
            f"CFBundleTypeRole 키가 누락 또는 비어 있었습니다.\n"
            f"IMPACT: role 선언 없이 앱은 무조건적인 핸들러로 동작합니다. "
            f"인증 코드, 파일 참조, IPC 명령 등 민감한 페이로드를 담은 딥 링크도 "
            f"사용자에게 role 힌트 없이 전달되어 권한 남용이 투명하게 발생할 수 있습니다.\n"
            f"PoC: Safari 주소창에 '{first}://attacker_controlled_payload'를 입력합니다. "
            f"macOS가 role 확인 없이 앱을 여는 것을 확인하면 무조건 핸들러 동작이 검증됩니다.\n"
            f"ATTACK PATH: 공격자가 악성 '{first}://' URL 제작 → "
            f"이메일/웹 페이지에 삽입 → 피해자 클릭 → "
            f"앱이 동의 프롬프트 없이 페이로드 처리 → 권한 있는 작업 실행."
        ),
        "root": root,
    }


def _finding_dlk_003(total_count: int, all_schemes: list[str], root: str) -> dict[str, Any]:
    """DESK-DLK-003 — more than 5 URL schemes registered (collision risk)."""
    schemes_preview = ", ".join(f"{s}://" for s in all_schemes[:8])
    if len(all_schemes) > 8:
        schemes_preview += f", … ({len(all_schemes) - 8} more)"
    first = all_schemes[0] if all_schemes else "unknown"
    return {
        "vector": "DESK-DLK-003",
        "severity": "medium",
        "total_scheme_count": total_count,
        "title": (
            f"Multiple URL schemes registered ({total_count} total — collision risk)"
            "|||"
            f"다중 URL scheme 등록 ({total_count}개 — 충돌 위험)"
        ),
        "description": (
            # ── English ──────────────────────────────────────────────────────
            f"WHAT: '{root}' registers {total_count} URL scheme(s): "
            f"{schemes_preview}. More than 5 schemes creates a broad attack "
            f"surface where any one can be squatted by a malicious app.\n"
            f"HOW: Counted all CFBundleURLSchemes entries across all "
            f"CFBundleURLTypes items in Contents/Info.plist.\n"
            f"IMPACT: Each registered scheme is an entry point. A wider scheme "
            f"portfolio increases the probability that at least one name is "
            f"generic enough for an attacker to squat, enabling open-redirect, "
            f"auth-code theft, or arbitrary IPC invocation.\n"
            f"PoC: Test '{first}://x' in a browser — if the scheme is "
            f"sufficiently generic, a competing malicious app registered first "
            f"intercepts the call. Enumerate all {total_count} schemes for "
            f"broader coverage.\n"
            f"ATTACK PATH: Attacker identifies most generic scheme among {total_count} → "
            f"publishes squatting app → intercepts auth callbacks or IPC messages.\n"
            # ── Korean ────────────────────────────────────────────────────────
            "|||"
            f"WHAT: '{root}'가 {total_count}개의 URL scheme을 등록하고 있습니다: "
            f"{schemes_preview}. 5개 초과 등록은 공격자가 그 중 하나를 스쿼팅할 수 있는 "
            f"넓은 공격 표면을 제공합니다.\n"
            f"HOW: Contents/Info.plist의 모든 CFBundleURLTypes 항목에서 "
            f"CFBundleURLSchemes 전체를 집계했습니다.\n"
            f"IMPACT: 등록된 각 scheme은 별도의 진입점입니다. scheme 포트폴리오가 넓을수록 "
            f"공격자가 스쿼팅하기 충분히 일반적인 이름이 포함될 가능성이 높아지며, "
            f"오픈 리다이렉트, 인증 코드 탈취, 임의 IPC 호출이 가능해집니다.\n"
            f"PoC: 브라우저에서 '{first}://x'를 테스트합니다. scheme이 충분히 일반적이면 "
            f"먼저 등록된 악성 앱이 호출을 가로챕니다. {total_count}개 전체를 순서대로 테스트하세요.\n"
            f"ATTACK PATH: 공격자가 {total_count}개 중 가장 일반적인 scheme 식별 → "
            f"스쿼팅 앱 배포 → 인증 콜백 또는 IPC 메시지 가로채기."
        ),
        "root": root,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public entrypoint
# ─────────────────────────────────────────────────────────────────────────────

async def execute(target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Parse Info.plist URL scheme registrations and flag generic/privileged/colliding schemes."""
    root = _walk_root(target_url)
    info_plist = os.path.join(root, "Contents", "Info.plist")

    # ── 1. Locate Info.plist ──────────────────────────────────────────────────
    if not os.path.isfile(info_plist):
        logger.debug(
            "test_deeplink_abuse: Info.plist not found at %s", info_plist
        )
        return {
            "scanned": 0,
            "findings": [],
            "schemes": [],
            "url_types": [],
            "root": root,
            "error": f"Info.plist not found at '{info_plist}'",
        }

    # ── 2. Parse plist ────────────────────────────────────────────────────────
    try:
        with open(info_plist, "rb") as fh:
            plist_data: dict[str, Any] = plistlib.load(fh)
    except Exception as exc:  # noqa: BLE001 — malformed / binary plist
        logger.warning(
            "test_deeplink_abuse: plist parse error for %s: %s", info_plist, exc
        )
        return {
            "scanned": 0,
            "findings": [],
            "schemes": [],
            "url_types": [],
            "root": root,
            "error": f"plist parse error: {exc}",
        }

    if not isinstance(plist_data, dict):
        return {
            "scanned": 1,
            "findings": [],
            "schemes": [],
            "url_types": [],
            "root": root,
            "error": "unexpected plist structure (top level is not a dict)",
        }

    # ── 3. Extract CFBundleURLTypes ───────────────────────────────────────────
    url_types_raw: list[Any] = plist_data.get("CFBundleURLTypes") or []
    if not url_types_raw:
        logger.info(
            "test_deeplink_abuse: root=%s — no CFBundleURLTypes, skipping", root
        )
        return {
            "scanned": 1,
            "findings": [],
            "schemes": [],
            "url_types": [],
            "root": root,
        }

    # Coerce to serialisable list[dict] for the return value.
    url_types: list[dict[str, Any]] = []
    for item in url_types_raw:
        if isinstance(item, dict):
            url_types.append({str(k): v for k, v in item.items()})

    # ── 4. Analyse each url_type entry ────────────────────────────────────────
    findings: list[dict[str, Any]] = []
    all_schemes: list[str] = []

    for url_type in url_types:
        entry_schemes: list[str] = []
        raw_schemes = url_type.get("CFBundleURLSchemes") or []
        if isinstance(raw_schemes, list):
            entry_schemes = [str(s) for s in raw_schemes]
        elif isinstance(raw_schemes, str):
            entry_schemes = [raw_schemes]

        all_schemes.extend(entry_schemes)

        # ── DESK-DLK-001: generic / too-short scheme ──────────────────────
        for scheme in entry_schemes:
            scheme_lower = scheme.lower()
            is_generic = (
                scheme_lower in _GENERIC_SCHEMES
                or bool(_SHORT_SCHEME_RE.match(scheme_lower))
            )
            if is_generic:
                findings.append(_finding_dlk_001(scheme, root))

        # ── DESK-DLK-002: missing CFBundleTypeRole for this entry ─────────
        role = url_type.get("CFBundleTypeRole")
        if entry_schemes and (not role or not str(role).strip()):
            findings.append(_finding_dlk_002(entry_schemes, root))

    # ── 5. DESK-DLK-003: total scheme count > 5 ──────────────────────────────
    if len(all_schemes) > 5:
        findings.append(_finding_dlk_003(len(all_schemes), all_schemes, root))

    logger.info(
        "test_deeplink_abuse: root=%s scanned=1 schemes=%d findings=%d",
        root, len(all_schemes), len(findings),
    )
    return {
        "scanned": 1,
        "findings": findings,
        "schemes": all_schemes,
        "url_types": url_types,
        "root": root,
    }
