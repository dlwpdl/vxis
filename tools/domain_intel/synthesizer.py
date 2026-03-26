"""Domain Intelligence — Trend Synthesizer.

수집된 시그널을 LLM으로 종합 분석:
1. 이번 주 보안 트렌드 3~5가지 도출
2. 각 트렌드가 VXIS에 미치는 영향 평가
3. 적용 옵션 (도입/어댑터/컨셉/무시) 제시
4. CVE Watcher/Upstream Watch 연동 제안

LLM 호출은 주 1회만 — 비용 ~$0.02/주 (Together Kimi K2.5 기준)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .signals import Signal

# upstream_watch의 LLM 모듈 재사용 (같은 프로젝트 내 tools/)
try:
    from tools.upstream_watch.llm import chat as llm_chat, is_available as llm_is_available
except ImportError:
    # 폴백: 직접 경로로 시도
    import importlib.util, os
    _llm_path = os.path.join(os.path.dirname(__file__), "..", "upstream_watch", "llm.py")
    _spec = importlib.util.spec_from_file_location("upstream_watch_llm", _llm_path)
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
    llm_chat = _mod.chat
    llm_is_available = _mod.is_available

logger = logging.getLogger(__name__)


@dataclass
class TrendItem:
    """하나의 트렌드 + VXIS 영향 분석."""

    title: str
    description: str
    evidence: list[str]         # 근거 시그널 URL/제목
    vxis_impact: str            # VXIS에 미치는 영향
    options: list[dict]         # 적용 옵션 [{label, description, effort, risk}]
    recommendation: str         # 추천 옵션
    priority: str               # critical, high, medium, low
    related_tags: list[str] = field(default_factory=list)


@dataclass
class WeeklyReport:
    """주간 도메인 인텔리전스 리포트."""

    generated_at: str
    total_signals: int
    trends: list[TrendItem]
    cisa_kev_alerts: list[dict]  # 이번 주 CISA KEV 추가분
    raw_signal_summary: dict     # 소스별 시그널 수


SYNTHESIZER_SYSTEM_PROMPT = """\
You are a senior security intelligence analyst for VXIS, an AI-powered \
autonomous penetration testing platform.

Your job:
1. Analyze the collected security domain signals (new tools, papers, \
community discussions, CVE trends, CISA KEV alerts).
2. Identify 3-5 major trends of this week.
3. For each trend, assess impact on VXIS and suggest action options.

VXIS context:
- AI-driven autonomous pentesting engine with 57+ specialized agents
- Has CPR (Cognitive Pentesting Runtime): Hands (httpx), Eyes (Playwright), X-Ray (mitmproxy)
- Watches upstream repos (nuclei, strix, pentagi, etc.)
- Has CVE Watch Daemon with 11 threat intelligence watchers
- Currently building Domain Intelligence Engine (this system)

Output valid JSON:
{
  "trends": [
    {
      "title": "한국어 제목 (5-10단어)",
      "description": "한국어 설명 (2-3문장, 무슨 일이 일어나고 있는지)",
      "evidence": ["시그널 제목/URL 1", "시그널 제목/URL 2"],
      "vxis_impact": "VXIS에 어떤 영향이 있는지 (한국어 2-3문장)",
      "options": [
        {"label": "옵션명", "description": "설명", "effort": "1일|3일|1주|2주", "risk": "low|medium|high"}
      ],
      "recommendation": "추천 옵션 (한국어)",
      "priority": "critical|high|medium|low",
      "related_tags": ["keyword1", "keyword2"]
    }
  ]
}

Rules:
- ALL text in Korean (한국어)
- Be specific about VXIS files/modules that would be affected
- Focus on ACTIONABLE intelligence, not general news
- Prioritize: new attack techniques > new tools > research > community buzz
- If a CISA KEV entry matches VXIS's target stack, mark as critical
"""


def _format_signals_for_llm(signals: list[Signal], max_signals: int = 60) -> str:
    """시그널을 LLM 프롬프트용으로 포맷."""
    parts: list[str] = []

    # 소스별 그룹핑
    by_source: dict[str, list[Signal]] = {}
    for s in signals[:max_signals]:
        by_source.setdefault(s.source, []).append(s)

    for source, source_signals in by_source.items():
        parts.append(f"\n## {source} ({len(source_signals)} signals)")
        for s in source_signals[:15]:
            meta_str = ""
            if s.metadata:
                meta_parts = []
                for k in ("stars", "points", "ups", "vendor", "product", "known_ransomware"):
                    if k in s.metadata:
                        meta_parts.append(f"{k}={s.metadata[k]}")
                if meta_parts:
                    meta_str = f" [{', '.join(meta_parts)}]"

            tags_str = f" tags:{','.join(s.relevance_tags)}" if s.relevance_tags else ""
            parts.append(f"- {s.title}{meta_str}{tags_str}")
            if s.description:
                parts.append(f"  {s.description[:200]}")

    return "\n".join(parts)


def synthesize(signals: list[Signal]) -> WeeklyReport:
    """시그널을 종합 분석하여 주간 리포트 생성."""
    now = datetime.now(timezone.utc).isoformat()

    # 소스별 요약
    source_counts: dict[str, int] = {}
    for s in signals:
        source_counts[s.source] = source_counts.get(s.source, 0) + 1

    # CISA KEV 별도 추출
    kev_alerts = [
        {"title": s.title, "url": s.url, "metadata": s.metadata}
        for s in signals if s.source == "cisa_kev"
    ]

    # LLM 분석
    trends: list[TrendItem] = []

    if llm_is_available() and signals:
        formatted = _format_signals_for_llm(signals)
        user_prompt = f"""\
이번 주 수집된 보안 도메인 시그널입니다:

{formatted}

---

위 시그널을 분석하여 이번 주의 주요 보안 트렌드 3~5개를 도출하고,
각 트렌드가 VXIS에 미치는 영향과 적용 옵션을 JSON으로 반환하세요.\
"""

        response = llm_chat(
            system_prompt=SYNTHESIZER_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            max_tokens=3000,
        )

        if response:
            trends = _parse_trends(response.text)
        else:
            logger.warning("[Synthesizer] LLM 분석 실패")
    else:
        logger.info("[Synthesizer] LLM 미설정 — 시그널 수집만 완료")

    return WeeklyReport(
        generated_at=now,
        total_signals=len(signals),
        trends=trends,
        cisa_kev_alerts=kev_alerts,
        raw_signal_summary=source_counts,
    )


def _parse_trends(raw_text: str) -> list[TrendItem]:
    """LLM 응답에서 트렌드 파싱."""
    try:
        json_str = raw_text
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0]
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0]

        data = json.loads(json_str.strip())
        items = data.get("trends", [])

        return [
            TrendItem(
                title=t.get("title", ""),
                description=t.get("description", ""),
                evidence=t.get("evidence", []),
                vxis_impact=t.get("vxis_impact", ""),
                options=t.get("options", []),
                recommendation=t.get("recommendation", ""),
                priority=t.get("priority", "medium"),
                related_tags=t.get("related_tags", []),
            )
            for t in items
        ]
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.warning("[Synthesizer] 트렌드 파싱 실패: %s", e)
        return []


def format_report_markdown(report: WeeklyReport) -> str:
    """주간 리포트를 마크다운으로 포맷."""
    lines = [
        f"# VXIS Domain Intelligence — Weekly Report",
        f"**Generated:** {report.generated_at}",
        f"**Total Signals:** {report.total_signals}",
        "",
        "## Signal Summary",
        "",
        "| Source | Count |",
        "|--------|-------|",
    ]

    for src, cnt in sorted(report.raw_signal_summary.items()):
        lines.append(f"| {src} | {cnt} |")

    # CISA KEV
    if report.cisa_kev_alerts:
        lines.extend(["", "## CISA KEV Alerts (이번 주)", ""])
        for alert in report.cisa_kev_alerts:
            meta = alert.get("metadata", {})
            ransomware = meta.get("known_ransomware", "Unknown")
            lines.append(
                f"- **{meta.get('cve_id', '')}** — {meta.get('vendor', '')} {meta.get('product', '')}"
                f" (랜섬웨어: {ransomware})"
            )

    # Trends
    if report.trends:
        lines.extend(["", "## Trends", ""])
        for i, trend in enumerate(report.trends, 1):
            priority_icon = {"critical": "🚨", "high": "🔶", "medium": "💡", "low": "📌"}.get(
                trend.priority, "📌"
            )
            lines.extend([
                f"### {priority_icon} Trend {i}: {trend.title}",
                "",
                trend.description,
                "",
                "**근거:**",
            ])
            for ev in trend.evidence[:5]:
                lines.append(f"- {ev}")

            lines.extend(["", f"**VXIS 영향:** {trend.vxis_impact}", "", "**옵션:**"])
            for opt in trend.options:
                risk_icon = {"low": "🟢", "medium": "🟡", "high": "🔴"}.get(opt.get("risk", ""), "⚪")
                lines.append(
                    f"- {opt.get('label', '')} — {opt.get('description', '')} "
                    f"(소요: {opt.get('effort', '?')}, 위험: {risk_icon})"
                )

            lines.extend([f"", f"**추천:** {trend.recommendation}", ""])

    return "\n".join(lines)
