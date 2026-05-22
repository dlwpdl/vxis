"""Specialist skill context selection for director and worker agents.

Strix-style skills inject deep technique knowledge into spawned agents. VXIS
goes one step further: every selected skill card includes when to use it, how
to execute it, how to validate it, and when to stop trusting it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class SkillCard:
    """Compact specialist knowledge for one executable skill."""

    name: str
    surface: str
    families: tuple[str, ...]
    roles: tuple[str, ...]
    triggers: tuple[str, ...]
    objective: str
    method: str
    validation: str
    stop_condition: str
    run_hint: str


_CORE_SKILL_CARDS: tuple[SkillCard, ...] = (
    SkillCard(
        name="enumerate_endpoints",
        surface="web",
        families=("recon", "surface"),
        roles=("director", "recon_worker"),
        triggers=("route", "endpoint", "crawl", "map", "surface", "path", "unauthenticated"),
        objective="Map reachable routes before choosing an exploit family.",
        method="Run broad endpoint enumeration, then cluster by auth boundary, API prefix, and parameter shape.",
        validation="Treat this as reconnaissance only; do not convert discovered routes into findings without a second proof step.",
        stop_condition="Stop when routes repeat or no new API/auth/admin paths appear.",
        run_hint='run_skill(skill="enumerate_endpoints", target_url=<target>, params={})',
    ),
    SkillCard(
        name="test_injection",
        surface="web",
        families=("injection", "sqli", "ssti", "cmdi"),
        roles=("director", "exploit_worker"),
        triggers=("sql", "sqli", "injection", "ssti", "cmd", "parameter", "search", "filter"),
        objective="Validate injection with positive and negative probes, not error strings alone.",
        method="Probe one parameter at a time; compare baseline, control payload, and exploit payload status/body/latency.",
        validation="Require a control comparison or a replayable attempt/result transcript before reporting.",
        stop_condition="Stop or pivot if the same parameter produces only generic SPA/error responses.",
        run_hint='run_skill(skill="test_injection", target_url=<target>, params={"url": "<url-with-param>"})',
    ),
    SkillCard(
        name="test_xss",
        surface="web",
        families=("xss", "client"),
        roles=("director", "exploit_worker"),
        triggers=("xss", "script", "dom", "reflected", "stored", "html", "client"),
        objective="Prove script-capable reflection or DOM execution with browser-observable evidence.",
        method="Use URL/form parameters, then confirm reflected/DOM behavior with rendered browser state when possible.",
        validation="A finding needs payload survival plus browser/DOM evidence, not just raw echo.",
        stop_condition="Stop if output is consistently encoded or only appears in inert JSON/string contexts.",
        run_hint='run_skill(skill="test_xss", target_url=<target>, params={"url": "<url-with-param>"})',
    ),
    SkillCard(
        name="test_idor",
        surface="web",
        families=("idor", "access_control"),
        roles=("director", "exploit_worker", "review_worker"),
        triggers=("idor", "access control", "object", "user id", "account", "tenant", "authorization"),
        objective="Find horizontal or vertical object access with paired control identities.",
        method="Mutate numeric/UUID identifiers and compare unauthenticated, owner, and non-owner responses.",
        validation="Require a control showing the victim object is protected from one context but accessible from another.",
        stop_condition="Stop if all ID changes return equivalent 401/403/404 or indistinguishable public data.",
        run_hint='run_skill(skill="test_idor", target_url=<target>, params={"url_pattern": "<path/{id}>"})',
    ),
    SkillCard(
        name="attempt_auth",
        surface="web",
        families=("auth", "credential"),
        roles=("director", "recon_worker", "exploit_worker"),
        triggers=("login", "auth", "credential", "password", "session", "token", "signin"),
        objective="Establish authenticated context or prove login bypass attempts fail cleanly.",
        method="Try default credentials, weak bypasses, and reset surfaces; capture token/session evidence only if successful.",
        validation="Never claim auth bypass unless a protected endpoint accepts the resulting session.",
        stop_condition="Stop after failed credential/bypass attempts unless a new login/reset surface appears.",
        run_hint='run_skill(skill="attempt_auth", target_url=<target>, params={})',
    ),
    SkillCard(
        name="post_auth_enum",
        surface="web",
        families=("auth", "data", "access_control"),
        roles=("director", "post_exploit_worker"),
        triggers=("token", "session", "authenticated", "post-auth", "dashboard", "profile", "admin"),
        objective="Use a real session to enumerate protected routes and privilege boundaries.",
        method="Replay authenticated requests, compare no-auth/control responses, and look for role/tenant crossover.",
        validation="Require token-backed evidence plus unauthenticated or lower-privilege control comparison.",
        stop_condition="Stop when protected routes are exhausted or every sensitive endpoint has matching controls.",
        run_hint='run_skill(skill="post_auth_enum", target_url=<target>, params={"token": "<token>"})',
    ),
    SkillCard(
        name="test_sensitive_files",
        surface="web",
        families=("disclosure", "credential"),
        roles=("director", "recon_worker", "exploit_worker"),
        triggers=("backup", "config", ".env", ".git", "secret", "key", "log", "disclosure"),
        objective="Find readable sensitive artifacts and separate real leaks from binary/noise responses.",
        method="Probe known secret/config paths and inspect readable material, size, content type, and status.",
        validation="Report only readable secret/config/repository metadata, not compressed or opaque binary blobs alone.",
        stop_condition="Stop if candidates are all redirects, static 404 templates, or unreadable blobs.",
        run_hint='run_skill(skill="test_sensitive_files", target_url=<target>, params={})',
    ),
    SkillCard(
        name="test_ssrf",
        surface="web",
        families=("ssrf", "network"),
        roles=("director", "exploit_worker"),
        triggers=("ssrf", "url", "callback", "webhook", "metadata", "fetch", "avatar", "import"),
        objective="Validate server-side fetch behavior without assuming every URL parameter is SSRF.",
        method="Use internal, metadata, file, and callback-style payloads only on URL-consuming parameters.",
        validation="Require differential response, callback, metadata content, or clear server-side fetch artifact.",
        stop_condition="Stop if parameters are reflected/client-side only or controls behave identically.",
        run_hint='run_skill(skill="test_ssrf", target_url=<target>, params={"url": "<url-with-url-param>"})',
    ),
    SkillCard(
        name="test_api_security",
        surface="web",
        families=("api", "auth", "idor", "rate_limit"),
        roles=("director", "exploit_worker", "post_exploit_worker"),
        triggers=("api", "json", "rest", "graphql", "rate", "verb", "mass assignment", "parameter pollution"),
        objective="Test API-specific abuse paths after endpoints are known.",
        method="Check method tampering, mass assignment, parameter pollution, and rate-limit behavior with controls.",
        validation="Require before/after response evidence and a security boundary impact.",
        stop_condition="Stop if endpoints are static/public or no parameter/state boundary exists.",
        run_hint='run_skill(skill="test_api_security", target_url=<target>, params={})',
    ),
    SkillCard(
        name="test_business_logic",
        surface="web",
        families=("business_logic", "race", "state"),
        roles=("director", "exploit_worker", "post_exploit_worker"),
        triggers=("price", "quantity", "coupon", "checkout", "state", "race", "workflow", "logic"),
        objective="Probe state and value manipulation that scanners miss.",
        method="Try negative quantities, skipped workflow transitions, repeated actions, and parallelized state changes.",
        validation="Require observable state/value change or privilege/asset impact, not only accepted input.",
        stop_condition="Stop when the workflow cannot be reached or every mutation is server-normalized.",
        run_hint='run_skill(skill="test_business_logic", target_url=<target>, params={})',
    ),
    SkillCard(
        name="test_auth_deep",
        surface="web",
        families=("auth", "jwt", "session"),
        roles=("director", "exploit_worker", "post_exploit_worker"),
        triggers=("jwt", "session", "reset", "oauth", "role", "claim", "cookie"),
        objective="Attack token/session design after basic auth surface is mapped.",
        method="Check JWT algorithms/claims, session fixation, reset poisoning, and role transition controls.",
        validation="Require protected action success with forged/fixed/altered token plus a clean control.",
        stop_condition="Stop if tokens are opaque and no reset/session mutation surface exists.",
        run_hint='run_skill(skill="test_auth_deep", target_url=<target>, params={"token": "<optional-token>"})',
    ),
    SkillCard(
        name="test_misconfig",
        surface="web",
        families=("misconfig", "cors", "headers", "debug"),
        roles=("director", "recon_worker", "review_worker"),
        triggers=("cors", "header", "debug", "error", "misconfig", "verbose", "swagger", "actuator"),
        objective="Find security-impacting misconfigurations, not cosmetic header gaps.",
        method="Check CORS, debug endpoints, verbose errors, exposed docs, and risky headers in context.",
        validation="Only report when the misconfiguration enables data access, auth bypass, or meaningful attack expansion.",
        stop_condition="Stop if issues are purely informational and no exploit path follows.",
        run_hint='run_skill(skill="test_misconfig", target_url=<target>, params={})',
    ),
    SkillCard(
        name="test_infra",
        surface="web",
        families=("infra", "disclosure", "subdomain"),
        roles=("director", "recon_worker"),
        triggers=("infra", "subdomain", "firebase", "cloud", "metadata", "git", "env", "host"),
        objective="Expand infrastructure surface and catch deployment leaks.",
        method="Probe exposed repo/env/cloud metadata patterns and known platform misconfigurations.",
        validation="Require readable sensitive content, takeover condition, or reachable exposed management surface.",
        stop_condition="Stop when candidates are non-existent, inaccessible, or duplicate static errors.",
        run_hint='run_skill(skill="test_infra", target_url=<target>, params={})',
    ),
    SkillCard(
        name="test_crypto",
        surface="web",
        families=("crypto", "tls", "secret"),
        roles=("director", "recon_worker", "review_worker"),
        triggers=("tls", "crypto", "cipher", "hash", "secret", "javascript", "js"),
        objective="Find cryptographic weakness with exploitable context.",
        method="Check TLS posture, JS-exposed secrets, and weak hashes where the app actually uses them.",
        validation="Report only when weakness affects confidentiality, auth, or key exposure.",
        stop_condition="Stop if findings are default informational TLS observations with no impact path.",
        run_hint='run_skill(skill="test_crypto", target_url=<target>, params={})',
    ),
)

_DESKTOP_SKILL_CARDS: tuple[SkillCard, ...] = (
    SkillCard(
        name="test_local_storage_secrets",
        surface="desktop",
        families=("desktop", "secret", "storage"),
        roles=("director", "recon_worker", "exploit_worker"),
        triggers=("desktop", "app", "local storage", "secret", "keychain", "electron", "plist"),
        objective="Find locally stored secrets in app bundles and adjacent files.",
        method="Walk readable app files and inspect text-like artifacts for credential patterns.",
        validation="Mask live secrets and require file path plus matched secret class.",
        stop_condition="Stop when only binary files or masked framework constants remain.",
        run_hint='run_skill(skill="test_local_storage_secrets", target_url=<app-path>, params={})',
    ),
    SkillCard(
        name="test_electron_misconfig",
        surface="desktop",
        families=("desktop", "electron"),
        roles=("director", "exploit_worker"),
        triggers=("electron", "nodeintegration", "contextisolation", "websecurity", "desktop"),
        objective="Find Electron settings that turn renderer compromise into local impact.",
        method="Inspect Electron config and bundled JS for dangerous webPreferences.",
        validation="Require exact config evidence and explain renderer-to-local impact.",
        stop_condition="Stop if the target is not Electron or configs are hardened.",
        run_hint='run_skill(skill="test_electron_misconfig", target_url=<app-path>, params={})',
    ),
    SkillCard(
        name="test_signature_audit",
        surface="desktop",
        families=("desktop", "signature"),
        roles=("director", "recon_worker", "review_worker"),
        triggers=("codesign", "signature", "hardened runtime", "desktop", "macos"),
        objective="Assess macOS signing and hardened runtime posture.",
        method="Run static signature checks before deeper dylib/entitlement chains.",
        validation="Report only if signing state materially enables tampering or chain escalation.",
        stop_condition="Stop once signing state is known and no dependent chain exists.",
        run_hint='run_skill(skill="test_signature_audit", target_url=<app-path>, params={})',
    ),
    SkillCard(
        name="test_entitlement_audit",
        surface="desktop",
        families=("desktop", "entitlement"),
        roles=("director", "exploit_worker", "review_worker"),
        triggers=("entitlement", "jit", "dyld", "library validation", "macos", "desktop"),
        objective="Find dangerous macOS entitlements that enable local exploitation.",
        method="Inspect entitlements and tie risky flags to concrete abuse paths.",
        validation="Require entitlement evidence plus a plausible local attack chain.",
        stop_condition="Stop if entitlements are absent or unrelated to target behavior.",
        run_hint='run_skill(skill="test_entitlement_audit", target_url=<app-path>, params={})',
    ),
    SkillCard(
        name="test_dylib_hijack",
        surface="desktop",
        families=("desktop", "dylib", "privilege"),
        roles=("director", "exploit_worker"),
        triggers=("dylib", "rpath", "hijack", "library", "privilege", "macos"),
        objective="Find writable or missing dynamic-library load paths.",
        method="Inspect Mach-O load commands, RPATH order, and writable directories.",
        validation="Require writable/missing path evidence and target binary relationship.",
        stop_condition="Stop if paths are system-protected or no writable search path exists.",
        run_hint='run_skill(skill="test_dylib_hijack", target_url=<app-path>, params={})',
    ),
    SkillCard(
        name="test_deeplink_abuse",
        surface="desktop",
        families=("desktop", "deeplink"),
        roles=("director", "exploit_worker"),
        triggers=("deeplink", "url scheme", "scheme", "openurl", "desktop", "macos"),
        objective="Find URL scheme handlers that can be abused for state changes or injection.",
        method="Parse app scheme registrations and reason about privileged handlers.",
        validation="Require registered scheme evidence plus an abuse path or collision.",
        stop_condition="Stop if no schemes exist or handlers are generic but harmless.",
        run_hint='run_skill(skill="test_deeplink_abuse", target_url=<app-path>, params={})',
    ),
    SkillCard(
        name="test_ipc_injection",
        surface="desktop",
        families=("desktop", "ipc", "xpc"),
        roles=("director", "exploit_worker"),
        triggers=("ipc", "xpc", "mach service", "helper", "privilege", "desktop"),
        objective="Find IPC/XPC boundaries that can be impersonated or replaced.",
        method="Inspect XPC services, Mach service names, writable bundles, and privilege boundaries.",
        validation="Require service/bundle evidence plus a privilege or trust-boundary impact.",
        stop_condition="Stop if no helper/IPC surface exists or paths are protected.",
        run_hint='run_skill(skill="test_ipc_injection", target_url=<app-path>, params={})',
    ),
    SkillCard(
        name="test_binary_protections",
        surface="desktop",
        families=("desktop", "binary", "hardening"),
        roles=("director", "recon_worker", "review_worker"),
        triggers=("pie", "aslr", "canary", "restrict", "binary", "macho", "desktop"),
        objective="Check binary hardening as exploitability context for local bugs.",
        method="Inspect Mach-O protection flags and combine with memory-corruption or injection leads.",
        validation="Treat missing hardening as supporting context unless paired with a concrete bug.",
        stop_condition="Stop if binary protections are present or no exploit primitive is in scope.",
        run_hint='run_skill(skill="test_binary_protections", target_url=<app-path>, params={})',
    ),
)

_ROLE_DEFAULTS: dict[str, tuple[str, ...]] = {
    "director": ("enumerate_endpoints", "test_infra", "test_misconfig", "attempt_auth"),
    "recon_worker": ("enumerate_endpoints", "test_infra", "test_sensitive_files", "test_misconfig"),
    "exploit_worker": ("test_injection", "test_idor", "test_xss", "test_ssrf", "test_api_security"),
    "post_exploit_worker": ("post_auth_enum", "test_auth_deep", "test_business_logic", "test_api_security"),
    "review_worker": ("test_idor", "test_misconfig", "test_crypto", "test_api_security"),
}


def select_skill_cards(
    *,
    task: str,
    role: str = "director",
    explicit_skills: Iterable[str] | None = None,
    target_kind: str = "web",
    limit: int = 5,
    include_defaults: bool = True,
) -> list[SkillCard]:
    """Select the most relevant skill cards for a director/worker context."""
    explicit = [str(skill or "").strip() for skill in (explicit_skills or []) if str(skill or "").strip()]
    explicit_set = set(explicit)
    role = str(role or "director").strip().lower()
    target_kind = _normalize_target_kind(target_kind)
    text = f"{role} {task}".lower()

    candidates = _available_cards(target_kind)
    scored: list[tuple[int, int, SkillCard]] = []
    for index, card in enumerate(candidates):
        score = _score_card(card, text=text, role=role, explicit=card.name in explicit_set)
        if score > 0:
            scored.append((score, -index, card))

    selected: list[SkillCard] = []
    seen: set[str] = set()

    for skill in explicit:
        card = _card_by_name(skill, target_kind=target_kind)
        if card is not None and card.name not in seen:
            selected.append(card)
            seen.add(card.name)

    for _, _, card in sorted(scored, reverse=True):
        if card.name in seen:
            continue
        selected.append(card)
        seen.add(card.name)
        if len(selected) >= limit:
            break

    if include_defaults and len(selected) < limit:
        for skill in _ROLE_DEFAULTS.get(role, _ROLE_DEFAULTS["director"]):
            card = _card_by_name(skill, target_kind=target_kind)
            if card is not None and card.name not in seen:
                selected.append(card)
                seen.add(card.name)
            if len(selected) >= limit:
                break

    return selected[: max(1, limit)]


def recommend_skill_names(
    *,
    task: str,
    role: str = "director",
    explicit_skills: Iterable[str] | None = None,
    target_kind: str = "web",
    limit: int = 5,
    include_defaults: bool = True,
) -> list[str]:
    return [
        card.name
        for card in select_skill_cards(
            task=task,
            role=role,
            explicit_skills=explicit_skills,
            target_kind=target_kind,
            limit=limit,
            include_defaults=include_defaults,
        )
    ]


def render_skill_context(
    *,
    task: str,
    role: str = "director",
    explicit_skills: Iterable[str] | None = None,
    target_kind: str = "web",
    limit: int = 5,
    max_chars: int = 2_400,
    include_defaults: bool = True,
) -> str:
    """Render selected skills as a compact prompt block."""
    cards = select_skill_cards(
        task=task,
        role=role,
        explicit_skills=explicit_skills,
        target_kind=target_kind,
        limit=limit,
        include_defaults=include_defaults,
    )
    if not cards:
        return ""
    lines: list[str] = [
        "Use these specialist cards as technique memory. They do not prove findings by themselves.",
    ]
    for idx, card in enumerate(cards, start=1):
        lines.extend([
            f"{idx}. {card.name} [{', '.join(card.families)}]",
            f"   objective: {card.objective}",
            f"   method: {card.method}",
            f"   validate: {card.validation}",
            f"   stop: {card.stop_condition}",
            f"   action: {card.run_hint}",
        ])
    rendered = "\n".join(lines)
    if len(rendered) <= max_chars:
        return rendered
    return rendered[: max(0, max_chars - 24)].rstrip() + "\n...truncated..."


def _available_cards(target_kind: str) -> tuple[SkillCard, ...]:
    target_kind = _normalize_target_kind(target_kind)
    if target_kind == "desktop":
        cards = _DESKTOP_SKILL_CARDS
    elif target_kind in {"mobile", "game"}:
        cards = ()
    else:
        cards = _CORE_SKILL_CARDS

    registered = _registered_skill_names()
    if not registered:
        return cards
    return tuple(card for card in cards if card.name in registered)


def _registered_skill_names() -> set[str]:
    try:
        from vxis.agent.skills import SKILL_REGISTRY
    except Exception:
        return set()
    return set(SKILL_REGISTRY)


def _card_by_name(name: str, *, target_kind: str) -> SkillCard | None:
    normalized = str(name or "").strip()
    for card in _available_cards(target_kind):
        if card.name == normalized:
            return card
    return None


def _score_card(card: SkillCard, *, text: str, role: str, explicit: bool) -> int:
    if explicit:
        return 1_000 + (60 if role in card.roles else 0)
    content_score = 0
    broad_families = {"api", "surface", "recon", "data", "network", "desktop"}
    broad_triggers = {"api", "json", "rest", "route", "endpoint", "surface", "path", "desktop", "app"}
    if card.name in text:
        content_score += 80
    for family in card.families:
        if family.replace("_", " ") in text or family in text:
            content_score += 10 if family in broad_families else 25
    for trigger in card.triggers:
        if trigger in text:
            content_score += 10 if trigger in broad_triggers else 30
    if content_score <= 0:
        return 0
    score = content_score
    if role in card.roles:
        score += 60
    for default_name in _ROLE_DEFAULTS.get(role, ()):
        if default_name == card.name:
            score += 8
    return score


def _normalize_target_kind(value: Any) -> str:
    text = str(getattr(value, "value", value) or "web").strip().lower()
    if text in {"desktop", "macos", "windows"}:
        return "desktop"
    if text in {"mobile", "android", "ios"}:
        return "mobile"
    if text == "game":
        return "game"
    return "web"


__all__ = [
    "SkillCard",
    "recommend_skill_names",
    "render_skill_context",
    "select_skill_cards",
]
