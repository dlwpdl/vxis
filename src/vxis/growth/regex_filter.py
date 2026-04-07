"""Regex pre-filter before LLM calls|||LLM 호출 전 정규식 사전 필터."""

from __future__ import annotations

import json
import re
from pathlib import Path

TECH_KEYWORDS: list[str] = [
    "react",
    "nextjs",
    "next.js",
    "nodejs",
    "node.js",
    "python",
    "django",
    "flask",
    "laravel",
    "rails",
    "spring",
    "struts",
    "wordpress",
    "drupal",
    "nginx",
    "apache",
    "postgresql",
    "mysql",
    "mongodb",
    "redis",
    "kubernetes",
    "docker",
    "aws",
    "gcp",
    "azure",
    "graphql",
    "rest api",
]

THREAT_INDICATORS: list[str] = [
    "zero-day",
    "0-day",
    "rce",
    "remote code execution",
    "sql injection",
    "xss",
    "csrf",
    "ssrf",
    "xxe",
    "privilege escalation",
    "authentication bypass",
    "deserialization",
    "prototype pollution",
]


def is_relevant(signal_body: str, signal_title: str = "") -> dict:
    """Quick regex relevance check|||빠른 정규식 관련성 검사.

    Returns a dict with ``relevant`` boolean and supporting evidence.
    """
    text = f"{signal_title} {signal_body}".lower()

    cves = re.findall(
        r"CVE-\d{4}-\d{4,7}",
        f"{signal_body} {signal_title}",
        re.IGNORECASE,
    )

    matched_tech = [t for t in TECH_KEYWORDS if t in text]
    matched_threats = [t for t in THREAT_INDICATORS if t in text]

    reasons: list[str] = []
    if cves:
        reasons.append(f"cve_found: {len(cves)}")
    if matched_tech:
        reasons.append(f"tech_match: {','.join(matched_tech[:3])}")
    if matched_threats:
        reasons.append(f"threat_indicator: {','.join(matched_threats[:3])}")

    return {
        "relevant": bool(cves or matched_tech or matched_threats),
        "reasons": reasons,
        "cves": cves,
        "keywords": matched_tech + matched_threats,
    }


def load_agent_memory_keywords() -> list[str]:
    """Load extra keywords from agent_memory.json|||에이전트 메모리에서 키워드 로드."""
    try:
        memory_path = Path("src/vxis/data/agent_memory.json")
        if not memory_path.exists():
            return []
        data = json.loads(memory_path.read_text(encoding="utf-8"))
        keywords: list[str] = []
        for target_info in data.get("targets", {}).values():
            if isinstance(target_info, dict):
                keywords.extend(target_info.get("technologies", []))
                keywords.extend(target_info.get("keywords", []))
        return [k.lower() for k in keywords if isinstance(k, str)]
    except Exception:
        return []
