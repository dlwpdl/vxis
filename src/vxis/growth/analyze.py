"""LLM-based structured extraction|||LLM 기반 구조화 추출."""

from __future__ import annotations

import dataclasses as dc
import json
import logging
import re

from vxis.growth.cache import ExtractionCache
from vxis.growth.config import load_bootstrap_config
from vxis.growth.regex_filter import is_relevant
from vxis.growth.schemas import NewsIntelligence, RawSignal

logger = logging.getLogger(__name__)

EXTRACTION_PROMPT = """You are a threat intelligence analyst. Extract structured data from this security article.

Return ONLY a JSON object (no markdown, no explanation) with these fields:
{{
  "cves": ["CVE-YYYY-NNNNN", ...],
  "threat_actors": ["lazarus", "kimsuky", ...],
  "malware_families": ["xenorat", ...],
  "ttps": [{{"mitre_id": "T1566.001", "description": "..."}}],
  "attack_chain": ["phishing", "powershell", "c2"],
  "target_industries": ["south_korean_enterprises"],
  "target_technologies": ["windows", "react"],
  "proposed_vectors": [
    {{"id": "WEB-PHISH-XXX", "name_en": "...", "name_ko": "...", "phase": "P4_cpr", "risk": "low"}}
  ],
  "proposed_phase_updates": [
    {{"phase_id": "P4_cpr", "field": "strategic_advice_ko", "append": "..."}}
  ],
  "proposed_kb_patterns": [
    {{
      "technique": "sqli|xss|rce|ssrf|path_traversal|auth_bypass|idor|cmdi|xxe",
      "payload": "the actual attack payload string (e.g. ' OR 1=1--, <script>alert(1)</script>)",
      "detect": ["signature strings to detect success in HTTP response"],
      "description": "what this payload tests",
      "severity": "critical|high|medium|low"
    }}
  ]
}}

Article:
Title: {title}
Body: {body}
Source: {source}
"""


def _parse_llm_json(response: str) -> dict:
    """Robust JSON extraction from LLM response|||LLM 응답에서 JSON 추출."""
    cleaned = re.sub(r"```(?:json)?\n?", "", response)
    cleaned = re.sub(r"```\n?", "", cleaned)
    cleaned = cleaned.strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1:
        return {}

    try:
        parsed = json.loads(cleaned[start : end + 1])
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        return {}


def analyze_signal(
    signal: RawSignal, dry_run: bool = True
) -> NewsIntelligence | None:
    """Extract structured intelligence|||구조화 인텔리전스 추출.

    Pipeline:
    1) cache → 2) regex pre-filter → 3) trust threshold →
    4) LLM extraction → 5) cache store.
    """
    config = load_bootstrap_config()
    cache = ExtractionCache(ttl_days=config["cache"]["extraction_ttl_days"])

    # Step 1: cache check
    cached = cache.get(signal.signal_id)
    if cached:
        try:
            return NewsIntelligence(**cached)
        except TypeError:
            # schema drift — ignore stale cache
            pass

    # Step 2: regex pre-filter
    if config["filtering"]["regex_prefilter_enabled"]:
        relevance = is_relevant(signal.body, signal.title)
        if not relevance["relevant"]:
            return None
    else:
        relevance = {"cves": [], "keywords": []}

    # Step 3: trust threshold
    trust_threshold = float(config["filtering"]["trust_threshold_for_llm"])
    if signal.source.trust_score < trust_threshold:
        intel = NewsIntelligence(
            signal_id=signal.signal_id,
            source_name=signal.source.name,
            article_url=signal.url,
            article_title=signal.title,
            pub_date=signal.timestamp,
            trust_score=signal.source.trust_score,
            cves=list(relevance.get("cves", [])),
        )
        cache.set(signal.signal_id, dc.asdict(intel))
        return intel

    # Step 4: LLM extraction
    try:
        from vxis.agent.brain import AgentBrain

        brain = AgentBrain()
        # Use body if available, fall back to metadata description
        body_text = signal.body
        if not body_text or len(body_text) < 50:
            body_text = signal.metadata.get("description", "") if signal.metadata else ""
        prompt = EXTRACTION_PROMPT.format(
            title=signal.title,
            body=body_text[:3000],
            source=signal.source.name,
        )

        response: str | None = None
        caller = getattr(brain, "_call_llm_with_fallback", None)
        if callable(caller):
            try:
                response = caller(
                    "You are a threat intelligence analyst.",
                    prompt,
                    max_retries=1,
                )
            except TypeError:
                response = caller(
                    "You are a threat intelligence analyst.",
                    prompt,
                )
        if not response:
            return None

        extracted = _parse_llm_json(response)
        if not extracted:
            return None

        intel = NewsIntelligence(
            signal_id=signal.signal_id,
            source_name=signal.source.name,
            article_url=signal.url,
            article_title=signal.title,
            pub_date=signal.timestamp,
            trust_score=signal.source.trust_score,
            cves=extracted.get("cves", []) or list(relevance.get("cves", [])),
            threat_actors=extracted.get("threat_actors", []),
            malware_families=extracted.get("malware_families", []),
            ttps=extracted.get("ttps", []),
            attack_chain=extracted.get("attack_chain", []),
            target_industries=extracted.get("target_industries", []),
            target_technologies=extracted.get("target_technologies", []),
            proposed_vectors=extracted.get("proposed_vectors", []),
            proposed_phase_updates=extracted.get("proposed_phase_updates", []),
            proposed_kb_patterns=extracted.get("proposed_kb_patterns", []),
        )
        cache.set(signal.signal_id, dc.asdict(intel))
        return intel

    except Exception as exc:
        logger.warning(
            "[growth/analyze] LLM extraction failed for %s: %s",
            signal.signal_id,
            exc,
        )
        return None


def analyze_batch(
    signals: list[RawSignal], dry_run: bool = True
) -> list[NewsIntelligence]:
    """Analyze multiple signals respecting batch size|||배치 크기 기반 분석."""
    config = load_bootstrap_config()
    batch_size = int(config["filtering"]["batch_size"])

    results: list[NewsIntelligence] = []
    for signal in signals[:batch_size]:
        intel = analyze_signal(signal, dry_run=dry_run)
        if intel:
            results.append(intel)
    return results
