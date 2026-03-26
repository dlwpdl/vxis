"""Domain Intelligence — Signal Collectors.

보안 도메인 전체를 감시하는 5개 시그널 수집기.
전부 무료 API, 외부 패키지 제로 (urllib/json stdlib만).

각 Collector는 같은 인터페이스:
    collect() → list[Signal]
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

_UA = "VXIS-DomainIntel/1.0 (security research)"


@dataclass
class Signal:
    """하나의 인텔리전스 시그널."""

    source: str          # github_pulse, research_pulse, community_pulse, cve_pulse, cisa_kev
    category: str        # tool, paper, discussion, cve_trend, exploit, supply_chain
    title: str
    url: str = ""
    description: str = ""
    relevance_tags: list[str] = field(default_factory=list)  # 관련 키워드
    score: float = 0.0   # 중요도 (stars, points, citations 등)
    timestamp: str = ""  # ISO 8601
    metadata: dict = field(default_factory=dict)


def _http_get(url: str, headers: dict | None = None, timeout: int = 30) -> dict | str | None:
    """범용 HTTP GET — JSON이면 파싱, 아니면 텍스트 반환."""
    hdrs = {"User-Agent": _UA, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, headers=hdrs, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return raw
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError) as e:
        logger.warning("[DomainIntel] HTTP error %s: %s", url[:80], e)
        return None


def _gh_api(endpoint: str) -> dict | list | None:
    """GitHub API 호출 — gh CLI 또는 urllib."""
    token = os.environ.get("GITHUB_TOKEN", "")

    # gh CLI 사용 가능하면 우선
    if shutil.which("gh"):
        try:
            proc = subprocess.run(
                ["gh", "api", endpoint, "--paginate"],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0:
                return json.loads(proc.stdout)
        except Exception:
            pass

    # urllib 폴백
    url = f"https://api.github.com/{endpoint.lstrip('/')}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return _http_get(url, headers=headers)


# ── 1. GitHub Pulse ──────────────────────────────────────────────


def collect_github_pulse() -> list[Signal]:
    """GitHub에서 보안 도구 트렌드 수집.

    - 최근 생성된 보안 관련 레포 (stars 기준 정렬)
    - 검색 쿼리 4개: AI pentest, exploit, vuln scanner, supply chain
    - 무료: 30 req/min (인증), 10 req/min (비인증)
    """
    signals: list[Signal] = []
    since = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")

    queries = [
        ("AI pentest", f"AI+pentest+language:python+created:>{since}+stars:>20"),
        ("exploit tool", f"exploit+tool+language:python+created:>{since}+stars:>30"),
        ("vulnerability scanner", f"vulnerability+scanner+created:>{since}+stars:>50"),
        ("supply chain security", f"supply+chain+security+created:>{since}+stars:>20"),
        ("browser automation security", f"browser+automation+security+created:>{since}+stars:>20"),
    ]

    seen_repos: set[str] = set()

    for label, query in queries:
        encoded = urllib.parse.quote(query)
        data = _gh_api(f"search/repositories?q={encoded}&sort=stars&order=desc&per_page=10")
        if not data or not isinstance(data, dict):
            continue

        items = data.get("items", [])
        for repo in items[:10]:
            full_name = repo.get("full_name", "")
            if full_name in seen_repos:
                continue
            seen_repos.add(full_name)

            signals.append(Signal(
                source="github_pulse",
                category="tool",
                title=f"[New Repo] {full_name}",
                url=repo.get("html_url", ""),
                description=repo.get("description", "") or "",
                relevance_tags=_extract_tags(repo.get("description", "") + " " + label),
                score=float(repo.get("stargazers_count", 0)),
                timestamp=repo.get("created_at", ""),
                metadata={
                    "stars": repo.get("stargazers_count", 0),
                    "language": repo.get("language", ""),
                    "topics": repo.get("topics", []),
                    "query": label,
                },
            ))

        # Rate limit 존중
        time.sleep(2)

    logger.info("[GitHub Pulse] %d signals collected", len(signals))
    return signals


# ── 2. Research Pulse (arXiv) ────────────────────────────────────


def collect_research_pulse() -> list[Signal]:
    """arXiv에서 보안 관련 최신 논문 수집.

    - cs.CR (Cryptography and Security) 카테고리
    - 무료, API 키 불필요, 무제한
    """
    signals: list[Signal] = []

    queries = [
        "LLM+security+vulnerability",
        "AI+penetration+testing",
        "supply+chain+attack+detection",
        "fuzzing+zero+day",
        "automated+exploit+generation",
    ]

    seen_ids: set[str] = set()

    for query in queries:
        # arXiv API — Atom XML 반환이지만, 간단히 파싱
        url = (
            f"http://export.arxiv.org/api/query?"
            f"search_query=all:{urllib.parse.quote(query)}+AND+cat:cs.CR"
            f"&start=0&max_results=5&sortBy=submittedDate&sortOrder=descending"
        )
        raw = _http_get(url, timeout=15)
        if not raw or not isinstance(raw, str):
            continue

        # 간단한 XML 파싱 (외부 패키지 없이)
        entries = raw.split("<entry>")[1:]  # 첫 번째는 feed 메타
        for entry_xml in entries[:5]:
            arxiv_id = _xml_extract(entry_xml, "id")
            if not arxiv_id or arxiv_id in seen_ids:
                continue
            seen_ids.add(arxiv_id)

            title = _xml_extract(entry_xml, "title").replace("\n", " ").strip()
            summary = _xml_extract(entry_xml, "summary")[:500].replace("\n", " ").strip()
            published = _xml_extract(entry_xml, "published")

            signals.append(Signal(
                source="research_pulse",
                category="paper",
                title=f"[Paper] {title}",
                url=arxiv_id,
                description=summary,
                relevance_tags=_extract_tags(title + " " + summary),
                score=0.0,  # arXiv에는 citation count가 바로 안 나옴
                timestamp=published,
                metadata={"query": query},
            ))

        time.sleep(3)  # arXiv rate limit 존중

    logger.info("[Research Pulse] %d signals collected", len(signals))
    return signals


# ── 3. Community Pulse (HackerNews + Reddit) ─────────────────────


def collect_community_pulse() -> list[Signal]:
    """HackerNews + Reddit에서 보안 커뮤니티 화제 수집.

    - HN Algolia API: 무료, 무제한, 키 불필요
    - Reddit: JSON endpoint, 무료
    """
    signals: list[Signal] = []

    # ── HackerNews ──
    hn_queries = ["security vulnerability", "zero day exploit", "supply chain attack", "AI pentesting"]

    for query in hn_queries:
        url = (
            f"https://hn.algolia.com/api/v1/search_by_date?"
            f"query={urllib.parse.quote(query)}"
            f"&tags=story&hitsPerPage=5"
        )
        data = _http_get(url)
        if not data or not isinstance(data, dict):
            continue

        for hit in data.get("hits", [])[:5]:
            title = hit.get("title", "")
            if not title:
                continue
            points = hit.get("points", 0) or 0
            if points < 10:  # 최소 10 포인트
                continue

            signals.append(Signal(
                source="community_pulse",
                category="discussion",
                title=f"[HN] {title}",
                url=hit.get("url", f"https://news.ycombinator.com/item?id={hit.get('objectID', '')}"),
                description="",
                relevance_tags=_extract_tags(title),
                score=float(points),
                timestamp=hit.get("created_at", ""),
                metadata={"source": "hackernews", "points": points, "comments": hit.get("num_comments", 0)},
            ))
        time.sleep(1)

    # ── Reddit r/netsec ──
    reddit_url = "https://www.reddit.com/r/netsec/top/.json?t=week&limit=10"
    data = _http_get(reddit_url, headers={"User-Agent": _UA})
    if data and isinstance(data, dict):
        for child in data.get("data", {}).get("children", [])[:10]:
            post = child.get("data", {})
            title = post.get("title", "")
            ups = post.get("ups", 0)
            if ups < 20:
                continue

            signals.append(Signal(
                source="community_pulse",
                category="discussion",
                title=f"[Reddit] {title}",
                url=f"https://reddit.com{post.get('permalink', '')}",
                description=post.get("selftext", "")[:300],
                relevance_tags=_extract_tags(title),
                score=float(ups),
                timestamp=datetime.fromtimestamp(post.get("created_utc", 0), tz=timezone.utc).isoformat(),
                metadata={"source": "reddit", "subreddit": "netsec", "ups": ups},
            ))

    logger.info("[Community Pulse] %d signals collected", len(signals))
    return signals


# ── 4. CISA KEV (Known Exploited Vulnerabilities) ────────────────


def collect_cisa_kev() -> list[Signal]:
    """CISA KEV — 실제 공격에 사용된 CVE 목록.

    - JSON feed, 무료, 키 불필요
    - 가장 신뢰도 높은 "이건 진짜 공격당하고 있다" 시그널
    """
    signals: list[Signal] = []
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    data = _http_get(url, timeout=30)
    if not data or not isinstance(data, dict):
        logger.warning("[CISA KEV] Failed to fetch")
        return signals

    # 최근 7일 이내 추가된 것만
    cutoff = (datetime.now(timezone.utc) - timedelta(days=7)).strftime("%Y-%m-%d")

    for vuln in data.get("vulnerabilities", []):
        date_added = vuln.get("dateAdded", "")
        if date_added < cutoff:
            continue

        cve_id = vuln.get("cveID", "")
        product = vuln.get("product", "")
        vendor = vuln.get("vendorProject", "")

        signals.append(Signal(
            source="cisa_kev",
            category="exploit",
            title=f"[CISA KEV] {cve_id} — {vendor} {product}",
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            description=vuln.get("shortDescription", ""),
            relevance_tags=[
                cve_id.lower(), vendor.lower(), product.lower(),
                vuln.get("vulnerabilityName", "").lower(),
            ],
            score=10.0,  # CISA KEV = 최고 중요도
            timestamp=date_added,
            metadata={
                "cve_id": cve_id,
                "vendor": vendor,
                "product": product,
                "action": vuln.get("requiredAction", ""),
                "due_date": vuln.get("dueDate", ""),
                "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
            },
        ))

    logger.info("[CISA KEV] %d recent signals", len(signals))
    return signals


# ── 5. CVE Trend Pulse (기존 데이터 분석) ────────────────────────


def collect_cve_trends(state_file: str = "") -> list[Signal]:
    """기존 CVE 데이터에서 패턴/트렌드 추출.

    NVD/OSV 데이터를 분석해서:
    - 특정 벤더/제품의 CVE 급증
    - 특정 CWE 유형 증가
    - 고위험 CVE 패턴
    """
    signals: list[Signal] = []

    # .cve_watch_state.json에서 최근 통계 로드
    from pathlib import Path
    state_path = Path(state_file) if state_file else Path(__file__).parent.parent.parent / ".cve_watch_state.json"

    if not state_path.exists():
        logger.info("[CVE Trends] No state file — skipping trend analysis")
        return signals

    try:
        state = json.loads(state_path.read_text())
        stats = state.get("stats", {})

        # 기본 통계 시그널
        total = stats.get("total_fetched", 0)
        matched = stats.get("total_matched", 0)
        exploitable = stats.get("total_exploitable", 0)

        if total > 0:
            signals.append(Signal(
                source="cve_pulse",
                category="cve_trend",
                title=f"[CVE Stats] 누적: {total} 수집, {matched} 매칭, {exploitable} 취약 확인",
                description=f"마지막 실행: {stats.get('last_run_duration_sec', 0):.1f}초",
                relevance_tags=["cve", "statistics"],
                score=float(exploitable * 10),
                timestamp=state.get("last_checked", ""),
                metadata=stats,
            ))
    except Exception as exc:
        logger.warning("[CVE Trends] State parse error: %s", exc)

    return signals


# ── Utilities ────────────────────────────────────────────────────


_SECURITY_KEYWORDS = {
    "rce", "xss", "sqli", "ssrf", "csrf", "lfi", "rfi", "xxe",
    "deserialization", "injection", "overflow", "bypass", "privilege",
    "escalation", "zero-day", "0day", "exploit", "vulnerability",
    "fuzzing", "pentest", "pentesting", "scanner", "reconnaissance",
    "brute-force", "credential", "authentication", "authorization",
    "supply-chain", "typosquatting", "malware", "ransomware",
    "phishing", "backdoor", "rootkit", "c2", "lateral", "exfiltration",
    "ai", "llm", "agent", "automation", "mcp", "playwright",
    "nuclei", "burp", "metasploit", "nmap", "docker", "kubernetes",
    "cloud", "aws", "azure", "gcp", "api", "graphql", "websocket",
    "waf", "cdn", "tls", "ssl", "certificate", "dns", "http3", "quic",
}


def _extract_tags(text: str) -> list[str]:
    """텍스트에서 보안 관련 키워드 추출."""
    words = set(re.findall(r"[a-z][a-z0-9\-]{2,}", text.lower()))
    return sorted(words & _SECURITY_KEYWORDS)


def _xml_extract(xml: str, tag: str) -> str:
    """간단한 XML 태그 내용 추출 (외부 패키지 없이)."""
    pattern = f"<{tag}[^>]*>(.*?)</{tag}>"
    match = re.search(pattern, xml, re.DOTALL)
    return match.group(1).strip() if match else ""


# ── Master Collector ─────────────────────────────────────────────


def collect_all() -> list[Signal]:
    """모든 시그널 수집."""
    all_signals: list[Signal] = []

    collectors = [
        ("GitHub Pulse", collect_github_pulse),
        ("Research Pulse", collect_research_pulse),
        ("Community Pulse", collect_community_pulse),
        ("CISA KEV", collect_cisa_kev),
        ("CVE Trends", collect_cve_trends),
    ]

    for name, fn in collectors:
        try:
            signals = fn()
            all_signals.extend(signals)
            logger.info("[DomainIntel] %s: %d signals", name, len(signals))
        except Exception as exc:
            logger.error("[DomainIntel] %s failed: %s", name, exc)

    # 중요도 기준 정렬
    all_signals.sort(key=lambda s: s.score, reverse=True)

    logger.info("[DomainIntel] Total: %d signals collected", len(all_signals))
    return all_signals
