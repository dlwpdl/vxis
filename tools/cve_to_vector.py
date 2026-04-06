"""CVE → AttackVector auto-converter.

Reads CVE candidates produced by tools/cve_watch (or upstream_watch growth loop),
asks the Brain LLM to synthesize an AttackVector definition for each high-severity
CVE, and appends them to src/vxis/scoring/vectors.py.

Usage:
    python tools/cve_to_vector.py [path/to/candidates.json]

Default candidates path: tools/cve_watch/growth_loop_candidates.json

Safety:
    - Backs up vectors.py to vectors.py.bak.<timestamp> before modification.
    - Skips CVEs whose ID already appears in vectors.py.
    - Gracefully handles a missing candidates file.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

# Make `tools.upstream_watch.llm` importable when run as a script.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from tools.upstream_watch.llm import chat as llm_chat  # type: ignore
except Exception as exc:  # pragma: no cover
    print(f"[!] Failed to import upstream_watch.llm: {exc}")
    llm_chat = None  # type: ignore

VECTORS_PATH = ROOT / "src" / "vxis" / "scoring" / "vectors.py"
DEFAULT_CANDIDATES = ROOT / "tools" / "cve_watch" / "growth_loop_candidates.json"

HIGH_SEVERITIES = {"CRITICAL", "HIGH"}

SYSTEM_PROMPT = (
    "You are a senior offensive-security engineer maintaining the VXIS attack "
    "vector registry. Given a CVE, output a single JSON object describing the "
    "AttackVector that VXIS should test to detect that vulnerability class. "
    "Respond with ONLY raw JSON — no markdown, no commentary."
)

USER_TEMPLATE = """\
CVE: {cve_id}
Affected product: {product}
Severity: {severity}
Description:
{description}

Produce a JSON object with EXACTLY these keys:
{{
  "id": "WEB-CVE-YYYY-NNNNN",
  "category": "injection|auth|misconfig|deserialization|ssrf|xss|rce|info_disclosure|crypto|access_control|supply_chain|other",
  "name_en": "Short English name (<= 80 chars)",
  "name_ko": "한국어 이름 (<= 80자)",
  "target_type": "web|game|mobile",
  "phase": "Phase N",
  "max_depth": 0-4,
  "owasp_id": "A0X:2021 or M0X"
}}

The id MUST encode the exact CVE year and number, e.g. CVE-2024-1234 -> WEB-CVE-2024-1234.
"""

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def load_candidates(path: Path) -> list[dict]:
    if not path.exists():
        print(f"[!] CVE candidates file not found: {path}")
        print("    Run the CVE watcher first, or pass an explicit path.")
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[!] Failed to parse {path}: {exc}")
        return []
    # Accept either a top-level list, or {"candidates": [...]}, or {"cves": [...]}
    if isinstance(data, dict):
        for key in ("candidates", "cves", "items", "results"):
            if key in data and isinstance(data[key], list):
                return data[key]
        return [data]
    if isinstance(data, list):
        return data
    return []


def normalize_cve(entry: dict) -> dict | None:
    """Pull out a uniform shape from a heterogeneous candidate entry."""
    cve_id = (
        entry.get("cve_id")
        or entry.get("id")
        or entry.get("CVE")
        or entry.get("name")
    )
    if not cve_id or not re.match(r"CVE-\d{4}-\d+", str(cve_id), re.I):
        return None
    severity = (
        entry.get("severity")
        or entry.get("cvss_severity")
        or entry.get("baseSeverity")
        or ""
    ).upper()
    description = (
        entry.get("description")
        or entry.get("summary")
        or entry.get("desc")
        or ""
    )
    product = (
        entry.get("product")
        or entry.get("affected_product")
        or entry.get("vendor")
        or "unknown"
    )
    return {
        "cve_id": str(cve_id).upper(),
        "severity": severity,
        "description": description,
        "product": product,
    }


def existing_cve_ids(vectors_text: str) -> set[str]:
    return set(m.group(0).upper() for m in re.finditer(r"CVE-\d{4}-\d+", vectors_text, re.I))


def call_llm(cve: dict) -> dict | None:
    if llm_chat is None:
        return None
    prompt = USER_TEMPLATE.format(
        cve_id=cve["cve_id"],
        product=cve["product"],
        severity=cve["severity"] or "UNKNOWN",
        description=cve["description"][:2000],
    )
    resp = llm_chat(SYSTEM_PROMPT, prompt, max_tokens=600)
    if resp is None or not getattr(resp, "text", None):
        return None
    text = resp.text.strip()
    # Strip code fences if any
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.MULTILINE).strip()
    # Extract first {...} block
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def render_vector(spec: dict) -> str:
    def esc(s: str) -> str:
        return str(s).replace("\\", "\\\\").replace('"', '\\"')

    return (
        "    AttackVector(\n"
        f'        id="{esc(spec["id"])}", category="{esc(spec["category"])}",\n'
        f'        name_en="{esc(spec["name_en"])}",\n'
        f'        name_ko="{esc(spec["name_ko"])}",\n'
        f'        target_types=("{esc(spec.get("target_type", "web"))}",),'
        f' phase="{esc(spec["phase"])}", max_depth={int(spec.get("max_depth", 2))},\n'
        f'        owasp_id="{esc(spec["owasp_id"])}",\n'
        "    ),\n"
    )


def insert_into_list(text: str, target_list: str, rendered: str) -> str:
    """Insert rendered vector(s) just before the closing `)` of the named tuple."""
    pattern = rf"({re.escape(target_list)}: tuple\[AttackVector, \.\.\.] = \([\s\S]*?)\n\)"
    m = re.search(pattern, text)
    if not m:
        raise RuntimeError(f"Could not locate {target_list} in vectors.py")
    head = m.group(1)
    new_block = head + "\n    # ── Auto-generated from CVE Watch ──\n" + rendered + ")"
    return text[: m.start()] + new_block + text[m.end():]


def list_for_target(target_type: str) -> str:
    return {
        "web": "WEB_VECTORS",
        "game": "GAME_VECTORS",
        "mobile": "MOBILE_VECTORS",
    }.get(target_type, "WEB_VECTORS")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main() -> int:
    candidates_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_CANDIDATES
    raw = load_candidates(candidates_path)
    if not raw:
        return 0

    cves: list[dict] = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        norm = normalize_cve(entry)
        if norm and norm["severity"] in HIGH_SEVERITIES:
            cves.append(norm)

    print(f"[i] Loaded {len(raw)} candidates, {len(cves)} high-severity CVEs")
    if not cves:
        print("[i] Nothing to convert.")
        return 0

    if not VECTORS_PATH.exists():
        print(f"[!] vectors.py not found at {VECTORS_PATH}")
        return 1

    vectors_text = VECTORS_PATH.read_text(encoding="utf-8")
    existing = existing_cve_ids(vectors_text)

    grouped: dict[str, list[str]] = {}
    added_cves: list[str] = []
    skipped = 0

    for cve in cves:
        if cve["cve_id"] in existing:
            skipped += 1
            continue
        if llm_chat is None:
            print("[!] LLM unavailable — cannot generate vectors")
            return 1
        spec = call_llm(cve)
        if not spec:
            print(f"[!] LLM produced no spec for {cve['cve_id']} — skipping")
            continue
        # Hard-guarantee the CVE id is encoded
        spec["id"] = re.sub(r"[^A-Z0-9\-]", "-", spec.get("id", "").upper()) or f"WEB-{cve['cve_id']}"
        if cve["cve_id"] not in spec["id"]:
            spec["id"] = f"WEB-{cve['cve_id']}"
        target = spec.get("target_type", "web")
        try:
            rendered = render_vector(spec)
        except Exception as exc:
            print(f"[!] Bad spec for {cve['cve_id']}: {exc}")
            continue
        grouped.setdefault(list_for_target(target), []).append(rendered)
        added_cves.append(cve["cve_id"])

    if not grouped:
        print(f"[i] Added 0 new vectors from {len(cves)} CVEs (skipped {skipped} duplicates)")
        return 0

    # Backup
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = VECTORS_PATH.with_suffix(f".py.bak.{ts}")
    shutil.copy2(VECTORS_PATH, backup)
    print(f"[i] Backed up vectors.py -> {backup.name}")

    # Insert per list
    new_text = vectors_text
    for list_name, blocks in grouped.items():
        new_text = insert_into_list(new_text, list_name, "".join(blocks))

    # Verify syntax before writing
    try:
        compile(new_text, str(VECTORS_PATH), "exec")
    except SyntaxError as exc:
        print(f"[!] Generated vectors.py would have syntax error: {exc}")
        print("    Aborting; backup preserved.")
        return 1

    VECTORS_PATH.write_text(new_text, encoding="utf-8")
    total_added = sum(len(b) for b in grouped.values())
    print(f"[+] Added {total_added} new vectors from {len(cves)} CVEs (skipped {skipped} duplicates)")
    for cid in added_cves:
        print(f"    + {cid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
