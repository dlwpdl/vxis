"""
Upstream Watch — VXIS codebase overlap detector.

Scans the VXIS source tree to build a capability inventory, then
compares upstream suggestions against it to prevent duplicate work
and highlight genuine gaps.

LLM-based semantic overlap detection is available when ANTHROPIC_API_KEY
is set in the environment. Falls back to keyword matching otherwise.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .analyzer import ActionItem

logger = logging.getLogger(__name__)

# ── VXIS Source Root ─────────────────────────────────────────────

VXIS_SRC = Path("src/vxis")


@dataclass
class VXISCapability:
    """A feature/capability detected in the VXIS codebase."""

    name: str
    category: str  # plugin, core, report, config, model
    file_path: str
    description: str
    keywords: list[str] = field(default_factory=list)


@dataclass
class OverlapResult:
    """Result of comparing an action item against VXIS capabilities."""

    item: ActionItem
    overlap_score: float  # 0.0 = no overlap, 1.0 = fully exists
    matching_capabilities: list[VXISCapability] = field(default_factory=list)
    verdict: str = ""  # "new", "partial_overlap", "already_exists", "enhancement"
    recommendation: str = ""


# ── Capability Inventory Builder ─────────────────────────────────


def _extract_classes(filepath: Path) -> list[tuple[str, str]]:
    """Extract class names and their docstrings from a Python file."""
    try:
        tree = ast.parse(filepath.read_text())
    except (SyntaxError, UnicodeDecodeError):
        return []

    classes = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            docstring = ast.get_docstring(node) or ""
            classes.append((node.name, docstring))
    return classes


def _extract_functions(filepath: Path) -> list[tuple[str, str]]:
    """Extract top-level and method function names and docstrings."""
    try:
        tree = ast.parse(filepath.read_text())
    except (SyntaxError, UnicodeDecodeError):
        return []

    functions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.name.startswith("_"):
                docstring = ast.get_docstring(node) or ""
                functions.append((node.name, docstring))
    return functions


def build_capability_inventory() -> list[VXISCapability]:
    """Scan VXIS source tree and build a capability inventory."""
    capabilities = []

    if not VXIS_SRC.exists():
        return capabilities

    for py_file in sorted(VXIS_SRC.rglob("*.py")):
        if py_file.name == "__init__.py":
            continue

        rel_path = str(py_file.relative_to(VXIS_SRC.parent.parent))
        parts = py_file.relative_to(VXIS_SRC).parts

        # Determine category
        if "plugins" in parts:
            category = "plugin"
        elif "core" in parts:
            category = "core"
        elif "report" in parts:
            category = "report"
        elif "config" in parts:
            category = "config"
        elif "models" in parts:
            category = "model"
        elif "dashboard" in parts:
            category = "dashboard"
        elif "cli" in parts:
            category = "cli"
        else:
            category = "other"

        # Extract module-level docstring
        try:
            tree = ast.parse(py_file.read_text())
            module_doc = ast.get_docstring(tree) or ""
        except (SyntaxError, UnicodeDecodeError):
            module_doc = ""

        # Build keywords from class/function names
        classes = _extract_classes(py_file)
        functions = _extract_functions(py_file)
        keywords = (
            [name.lower() for name, _ in classes]
            + [name.lower() for name, _ in functions]
            + [py_file.stem.lower().replace("_plugin", "").replace("_", " ")]
        )

        description = module_doc or f"{py_file.stem} module"
        if classes:
            description += f" (classes: {', '.join(n for n, _ in classes)})"

        capabilities.append(
            VXISCapability(
                name=py_file.stem,
                category=category,
                file_path=rel_path,
                description=description[:300],
                keywords=keywords,
            )
        )

    return capabilities


# ── Overlap Detection ────────────────────────────────────────────

# Keyword synonyms for fuzzy matching
SYNONYMS = {
    "dedup": ["deduplicate", "deduplication", "duplicate", "merge"],
    "vuln": ["vulnerability", "vulnerabilities", "finding", "cve"],
    "scan": ["scanner", "scanning", "probe", "enumerate"],
    "report": ["reporting", "export", "output", "pdf", "docx"],
    "agent": ["agents", "ai-agent", "autonomous"],
    "checkpoint": ["resume", "persist", "save-state", "recovery"],
    "browser": ["headless", "playwright", "selenium", "screenshot"],
    "knowledge": ["memory", "knowledge-graph", "learning", "history"],
    "mcp": ["model-context-protocol", "tool-server"],
    "rate-limit": ["throttle", "token-bucket", "rate-limiter"],
    "fp": ["false-positive", "false_positive", "confidence"],
    "enrich": ["enrichment", "cvss", "mitre", "compliance"],
    "nuclei": ["template", "nuclei-templates"],
    "nmap": ["port-scan", "service-detection"],
    "tls": ["ssl", "testssl", "certificate"],
    "dns": ["subdomain", "subfinder", "dnstwist"],
    "cloud": ["aws", "prowler", "s3", "azure", "gcp"],
    "container": ["docker", "kubernetes", "k8s", "trivy"],
    "secret": ["secrets", "trufflehog", "gitleaks", "credential"],
    "ad": ["active-directory", "bloodhound", "ldap", "kerberos"],
}


def _expand_keywords(text: str) -> set[str]:
    """Expand text into keyword set including synonyms."""
    words = set(re.findall(r'[a-z][a-z0-9_-]+', text.lower()))
    expanded = set(words)
    for word in words:
        for key, synonyms in SYNONYMS.items():
            if word == key or word in synonyms:
                expanded.add(key)
                expanded.update(synonyms)
    return expanded


def check_overlap(
    item: ActionItem,
    capabilities: list[VXISCapability],
) -> OverlapResult:
    """Check how much an action item overlaps with existing VXIS capabilities."""
    item_keywords = _expand_keywords(
        f"{item.title} {item.description} {item.category}"
    )

    matches = []
    for cap in capabilities:
        cap_keywords = _expand_keywords(
            " ".join(cap.keywords) + " " + cap.description + " " + cap.name
        )
        overlap = item_keywords & cap_keywords
        if len(overlap) >= 2:  # At least 2 keyword matches
            score = len(overlap) / max(len(item_keywords), 1)
            matches.append((cap, score))

    matches.sort(key=lambda x: x[1], reverse=True)

    if not matches:
        return OverlapResult(
            item=item,
            overlap_score=0.0,
            verdict="new",
            recommendation=f"New capability — not found in VXIS. Safe to implement.",
        )

    top_score = matches[0][1]
    matching_caps = [cap for cap, _ in matches[:5]]

    if top_score >= 0.6:
        verdict = "already_exists"
        files = ", ".join(c.file_path for c in matching_caps[:3])
        recommendation = (
            f"High overlap with existing code ({files}). "
            f"Check if this is an enhancement to existing functionality."
        )
    elif top_score >= 0.3:
        verdict = "enhancement"
        files = ", ".join(c.file_path for c in matching_caps[:3])
        recommendation = (
            f"Partial overlap — may enhance existing code ({files}). "
            f"Review to ensure no duplication."
        )
    else:
        verdict = "partial_overlap"
        recommendation = (
            f"Minor overlap detected but mostly new functionality. "
            f"Proceed with awareness of related modules."
        )

    return OverlapResult(
        item=item,
        overlap_score=top_score,
        matching_capabilities=matching_caps,
        verdict=verdict,
        recommendation=recommendation,
    )


_LLM_OVERLAP_PROMPT = """\
You are a senior software architect reviewing whether a proposed feature already
exists in the VXIS platform or is genuinely new work.

VXIS is an AI-powered security automation platform that orchestrates 35+ \
open-source security tools, analyzes results with multi-model AI, and generates \
NCC Group-grade consulting reports.

You will be given:
1. A proposed action item (title + description + category).
2. A concise summary of VXIS capabilities (class names, descriptions, file paths).

Your task:
- Judge whether the action item is already covered, partially covered, or new.
- Be precise: a plugin named "nmap_plugin" does NOT mean nmap scanning is fully covered
  unless its description confirms the specific proposed feature.

Return ONLY valid JSON, no markdown, no explanation:
{
  "overlap_score": <float 0.0-1.0>,
  "verdict": "<new|enhancement|already_exists|partial_overlap>",
  "recommendation": "<1-2 sentences on what to do>"
}

Verdict guide:
- "new"            — Not covered at all. Safe to implement fresh.
- "enhancement"    — Related code exists but the specific feature is missing.
- "partial_overlap"— Some overlap; proceed with care to avoid duplication.
- "already_exists" — Functionally equivalent code already exists.\
"""

# Maximum capabilities to include in the LLM prompt (token budget)
_MAX_CAPS_IN_PROMPT = 40


def _build_capability_summary(capabilities: list[VXISCapability]) -> str:
    """Format capability list into a concise token-efficient summary."""
    lines = []
    for cap in capabilities[:_MAX_CAPS_IN_PROMPT]:
        # One line per capability: category | name | description[:120] | path
        desc_short = cap.description[:120].replace("\n", " ")
        lines.append(f"[{cap.category}] {cap.name} — {desc_short} ({cap.file_path})")
    if len(capabilities) > _MAX_CAPS_IN_PROMPT:
        lines.append(
            f"... and {len(capabilities) - _MAX_CAPS_IN_PROMPT} more modules (omitted for brevity)"
        )
    return "\n".join(lines)


def check_overlap_with_llm(
    item: ActionItem,
    capabilities: list[VXISCapability],
) -> OverlapResult | None:
    """
    Use the configured LLM provider to semantically compare an action item
    against the VXIS capability inventory.

    Returns None when no API key is available or the call fails, allowing
    the caller to fall back to keyword-based detection.
    """
    from .llm import chat as llm_chat, is_available as llm_is_available

    if not llm_is_available():
        return None

    capability_summary = _build_capability_summary(capabilities)

    user_message = (
        f"## Proposed Action Item\n"
        f"**Title:** {item.title}\n"
        f"**Category:** {item.category}\n"
        f"**Description:** {item.description}\n\n"
        f"## VXIS Capability Inventory\n"
        f"{capability_summary}\n\n"
        f"Does this action item already exist in VXIS? Return JSON only."
    )

    try:
        response = llm_chat(
            system_prompt=_LLM_OVERLAP_PROMPT,
            user_prompt=user_message,
            max_tokens=256,
        )
        if response is None:
            return None

        raw_text = response.text.strip()

        # Strip optional markdown fences before parsing
        if raw_text.startswith("```"):
            raw_text = raw_text.split("```")[1]
            if raw_text.startswith("json"):
                raw_text = raw_text[4:]
        raw_text = raw_text.strip()

        data = json.loads(raw_text)

        overlap_score = float(data.get("overlap_score", 0.0))
        verdict = str(data.get("verdict", "new"))
        recommendation = str(data.get("recommendation", ""))

        # Validate verdict enum — reject malformed responses
        valid_verdicts = {"new", "enhancement", "already_exists", "partial_overlap"}
        if verdict not in valid_verdicts:
            logger.warning("LLM returned unknown verdict %r; falling back", verdict)
            return None

        # Attach matching capabilities from keyword scan
        keyword_result = check_overlap(item, capabilities)
        matching_caps = keyword_result.matching_capabilities

        return OverlapResult(
            item=item,
            overlap_score=overlap_score,
            matching_capabilities=matching_caps,
            verdict=verdict,
            recommendation=recommendation,
        )

    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        logger.warning("LLM overlap parse error for %r: %s", item.title, exc)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("LLM overlap API error for %r: %s", item.title, exc)
        return None


def check_all_overlaps(
    items: list[ActionItem],
) -> list[OverlapResult]:
    """
    Check overlap for all action items against the VXIS codebase.

    Uses LLM semantic analysis when ANTHROPIC_API_KEY is set; falls back
    to keyword matching per item when the LLM is unavailable or returns
    an error.
    """
    capabilities = build_capability_inventory()
    results = []
    for item in items:
        # Try LLM first; fall back to keyword matching on None
        result = check_overlap_with_llm(item, capabilities)
        if result is None:
            result = check_overlap(item, capabilities)
        results.append(result)
    return results


def format_overlap_report(results: list[OverlapResult]) -> str:
    """Format overlap results as readable markdown."""
    lines = ["## VXIS Overlap Analysis", ""]

    for r in results:
        icon = {
            "new": "[NEW]",
            "enhancement": "[ENH]",
            "partial_overlap": "[~]",
            "already_exists": "[DUP]",
        }.get(r.verdict, "[?]")

        lines.append(f"### {icon} {r.item.title}")
        lines.append(f"- **Verdict:** {r.verdict} (overlap: {r.overlap_score:.0%})")
        lines.append(f"- **Recommendation:** {r.recommendation}")
        if r.matching_capabilities:
            lines.append("- **Related VXIS files:**")
            for cap in r.matching_capabilities[:3]:
                lines.append(f"  - `{cap.file_path}` — {cap.description[:100]}")
        lines.append("")

    return "\n".join(lines)
