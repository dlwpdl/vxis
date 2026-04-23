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

EXTRACTION_PROMPT = """You are a threat intelligence analyst specializing in web application security.

PHASE 1 — Extract what the article describes:
Read the article and identify any web attack techniques, vulnerabilities, or bypass methods.

PHASE 2 — Design concrete payloads:
For each technique found, DESIGN actual testable payloads that a pentester could use.
Do NOT just copy text from the article. THINK about how the technique works and
create payloads that exploit it.

Example: if the article says "Unicode normalization bypass for WAF evasion",
you should design: payload = "＇ OR 1=1--" (fullwidth apostrophe U+FF07)
and detect = ["sql", "syntax error"] because NFKC normalization converts it to a real quote.

Return ONLY a JSON object:
{{
  "cves": ["CVE-YYYY-NNNNN"],
  "threat_actors": [],
  "malware_families": [],
  "ttps": [{{"mitre_id": "T1190", "description": "..."}}],
  "attack_chain": [],
  "target_industries": [],
  "target_technologies": ["express", "angular", "spring", ...],
  "proposed_vectors": [
    {{"id": "WEB-XXX", "name_en": "...", "name_ko": "...", "phase": "P4_cpr", "risk": "low"}}
  ],
  "proposed_phase_updates": [],
  "proposed_kb_patterns": [
    {{
      "technique": "sqli|xss|rce|ssrf|path_traversal|auth_bypass|idor|cmdi|xxe|csrf|jwt|ssti|nosql",
      "attack_description": "HOW the attack works — the mechanism, not just the name",
      "payload": "CONCRETE testable payload string YOU designed based on the technique",
      "detect": ["response signatures that indicate the payload worked"],
      "affected_tech": ["express", "angular", "mysql", ...],
      "severity": "critical|high|medium|low"
    }}
  ]
}}

IMPORTANT: proposed_kb_patterns should contain payloads YOU DESIGNED, not quoted from the article.
If the article describes a technique but no specific exploit, design one yourself.
If the article is not about web vulnerabilities, return empty proposed_kb_patterns.

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

    # Step 3.5: Fetch full article body if we only have a short summary.
    # RSS feeds typically give 200-400 char descriptions. The actual article
    # has the technical details needed for payload design.
    body_text = signal.body
    if not body_text or len(body_text) < 200:
        body_text = signal.metadata.get("description", "") if signal.metadata else ""
    if len(body_text) < 500 and signal.url and signal.url.startswith("http"):
        try:
            import re
            import urllib.request
            req = urllib.request.Request(
                signal.url,
                headers={"User-Agent": "VXIS-Growth/1.0"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                raw_bytes: bytes = resp.read(1_000_000)  # cap at 1MB
            raw_html = raw_bytes.decode("utf-8", errors="replace")
            if resp.status == 200 and len(raw_html) > 500:
                # Extract text from HTML — simple approach
                html = raw_html
                # Remove script/style tags
                html = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.DOTALL | re.I)
                # Remove HTML tags
                text = re.sub(r"<[^>]+>", " ", html)
                # Collapse whitespace
                text = re.sub(r"\s+", " ", text).strip()
                if len(text) > len(body_text):
                    body_text = text
                    logger.info("Fetched article body: %d chars from %s", len(text), signal.url)
        except Exception as e:
            logger.debug("Article fetch failed for %s: %s", signal.url, e)

    # Step 4: LLM extraction — Phase 1 (understand) + Phase 2 (design payloads)
    try:
        from vxis.agent.brain import AgentBrain

        brain = AgentBrain()
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
