"""산업 리스크 히트맵 — 기업 간 보안 등급 비교 리포트.

두 가지 출력 포맷을 제공합니다:
  * :func:`generate_heatmap_report` — Markdown 리포트 (한국어)
  * :func:`generate_heatmap_html` — 독립형 HTML + 인라인 CSS 히트맵
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vxis.industry.scanner import IndustryScanResult

from vxis.industry.discovery import CompanyProfile

# ---------------------------------------------------------------------------
# 등급별 색상 팔레트
# ---------------------------------------------------------------------------

_GRADE_COLORS_HEX: dict[str, str] = {
    "A": "#2ecc71",   # 초록
    "B": "#3498db",   # 파랑
    "C": "#e67e22",   # 주황
    "D": "#c0392b",   # 빨강
    "F": "#7b2c34",   # 진한 빨강
    "": "#95a5a6",    # 실패 / 등급 없음 (회색)
    "N/A": "#95a5a6",
}

_GRADE_LABELS_KR: dict[str, str] = {
    "A": "우수 (A)",
    "B": "양호 (B)",
    "C": "주의 (C)",
    "D": "위험 (D)",
    "F": "심각 (F)",
    "": "미완료",
    "N/A": "해당없음",
}

_GRADE_RECOMMENDATIONS: dict[str, str] = {
    "A": (
        "현재 보안 수준이 우수합니다. "
        "정기적인 모니터링과 연간 재검진을 권장합니다."
    ),
    "B": (
        "일부 고위험 취약점이 존재합니다. "
        "30일 이내 High 취약점을 우선 패치하세요."
    ),
    "C": (
        "다수의 고위험 취약점 또는 Critical 1건이 발견되었습니다. "
        "즉시 취약점 분류 및 긴급 패치 계획 수립을 권장합니다."
    ),
    "D": (
        "Critical 취약점이 다수입니다. "
        "즉각적인 사고 대응 및 격리 조치가 필요합니다."
    ),
    "F": (
        "치명적 취약점이 4건 이상입니다. "
        "즉시 외부 전문가 투입 및 비상 대응 체계를 가동하세요."
    ),
}


# ---------------------------------------------------------------------------
# Markdown 리포트
# ---------------------------------------------------------------------------


def generate_heatmap_report(result: "IndustryScanResult") -> str:
    """산업 리스크 히트맵 Markdown 리포트를 생성합니다 (한국어).

    Args:
        result: :class:`~vxis.industry.scanner.IndustryScanResult` 집계 결과.

    Returns:
        Markdown 형식의 문자열.
    """
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y년 %m월 %d일 %H:%M UTC")

    # ── 제목 & 메타 ──────────────────────────────────────────────────────
    lines.append("# 산업 보안 리스크 히트맵 리포트")
    lines.append("")
    lines.append(f"> 생성 일시: {now}")
    lines.append(f"> 스캔 기간: {result.started_at} ~ {result.completed_at}")
    lines.append("")

    # ── 1. 산업 개요 ─────────────────────────────────────────────────────
    lines.append("## 1. 산업 보안 개요")
    lines.append("")

    total_findings = sum(result.industry_findings.values())

    lines.append("| 항목 | 수치 |")
    lines.append("|------|------|")
    lines.append(f"| 전체 기업 수 | {result.total_companies:,}개 |")
    lines.append(f"| 스캔 완료 | {result.scanned_companies:,}개 |")
    lines.append(f"| 스캔 실패 | {result.failed_companies:,}개 |")
    lines.append(f"| 평균 보안 등급 | **{result.average_grade}** |")
    lines.append(f"| 총 취약점 수 | {total_findings:,}건 |")
    lines.append(
        f"| Critical | {result.industry_findings.get('critical', 0):,}건 |"
    )
    lines.append(f"| High | {result.industry_findings.get('high', 0):,}건 |")
    lines.append(
        f"| 스캔 소요 시간 | {result.scan_duration:.0f}초 ({result.scan_duration / 60:.1f}분) |"
    )
    lines.append("")

    # ── 2. 등급 분포 ─────────────────────────────────────────────────────
    lines.append("## 2. 보안 등급 분포")
    lines.append("")
    lines.append("| 등급 | 기업 수 | 비율 | 상태 |")
    lines.append("|------|---------|------|------|")

    total_graded = sum(result.grade_distribution.values())
    for grade in ["A", "B", "C", "D", "F"]:
        count = result.grade_distribution.get(grade, 0)
        ratio = (count / total_graded * 100) if total_graded > 0 else 0.0
        label = _GRADE_LABELS_KR.get(grade, grade)
        bar = "█" * min(int(ratio / 5), 20)
        lines.append(f"| {grade} | {count:,}개 | {ratio:.1f}% | {bar} |")

    lines.append("")

    # ── 3. 취약 기업 Top 10 ───────────────────────────────────────────────
    lines.append("## 3. 가장 취약한 기업 Top 10")
    lines.append("")

    vulnerable_sorted = sorted(
        [c for c in result.companies if c.security_grade],
        key=lambda c: (
            -c.critical_count,
            -c.high_count,
            -c.findings_count,
        ),
    )

    lines.append("| 순위 | 기업명 | 도메인 | 등급 | Critical | High | 총 취약점 |")
    lines.append("|------|--------|--------|------|----------|------|----------|")

    for rank, company in enumerate(vulnerable_sorted[:10], 1):
        lines.append(
            f"| {rank} | {company.name} | {company.domain} "
            f"| **{company.security_grade}** "
            f"| {company.critical_count} "
            f"| {company.high_count} "
            f"| {company.findings_count} |"
        )

    lines.append("")

    # ── 4. 안전한 기업 Top 10 ────────────────────────────────────────────
    lines.append("## 4. 가장 안전한 기업 Top 10")
    lines.append("")

    secure_sorted = sorted(
        [c for c in result.companies if c.security_grade == "A"],
        key=lambda c: c.findings_count,
    )

    if secure_sorted:
        lines.append("| 순위 | 기업명 | 도메인 | 총 취약점 |")
        lines.append("|------|--------|--------|----------|")
        for rank, company in enumerate(secure_sorted[:10], 1):
            lines.append(
                f"| {rank} | {company.name} | {company.domain} "
                f"| {company.findings_count} |"
            )
    else:
        lines.append("_A등급 기업이 없습니다._")

    lines.append("")

    # ── 5. 가장 흔한 취약점 유형 ─────────────────────────────────────────
    lines.append("## 5. 가장 빈번한 취약점 유형 (산업 전체)")
    lines.append("")

    if result.most_common_vulns:
        lines.append("| 순위 | 취약점 유형 | 발견 횟수 |")
        lines.append("|------|-------------|----------|")
        for rank, (vuln_type, count) in enumerate(result.most_common_vulns[:15], 1):
            lines.append(f"| {rank} | {vuln_type} | {count:,}건 |")
    else:
        lines.append("_취약점 유형 데이터가 없습니다._")

    lines.append("")

    # ── 6. 등급별 권고 사항 ──────────────────────────────────────────────
    lines.append("## 6. 등급별 권고 사항")
    lines.append("")

    for grade in ["F", "D", "C", "B", "A"]:
        count = result.grade_distribution.get(grade, 0)
        if count == 0:
            continue
        rec = _GRADE_RECOMMENDATIONS.get(grade, "")
        label = _GRADE_LABELS_KR.get(grade, grade)
        lines.append(f"### 등급 {label} ({count}개 기업)")
        lines.append("")
        lines.append(rec)
        lines.append("")

    # ── 푸터 ─────────────────────────────────────────────────────────────
    lines.append("---")
    lines.append("")
    lines.append(
        "_본 리포트는 VXIS 자율 보안 스캔 플랫폼에 의해 자동 생성되었습니다._"
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML 리포트
# ---------------------------------------------------------------------------

_HTML_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f1923;
    color: #e0e6ef;
    line-height: 1.6;
}
.container { max-width: 1200px; margin: 0 auto; padding: 24px; }
h1 { font-size: 2rem; color: #64c8ff; margin-bottom: 8px; }
h2 { font-size: 1.3rem; color: #a0bcd8; margin: 32px 0 12px; border-bottom: 1px solid #1e3a5f; padding-bottom: 6px; }
.meta { font-size: 0.85rem; color: #607080; margin-bottom: 32px; }

/* 통계 카드 */
.stat-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px; margin-bottom: 32px; }
.stat-card { background: #1a2d42; border-radius: 8px; padding: 16px; text-align: center; }
.stat-card .val { font-size: 2rem; font-weight: 700; color: #64c8ff; }
.stat-card .lbl { font-size: 0.8rem; color: #607080; margin-top: 4px; }

/* 등급 분포 */
.grade-bar-row { display: flex; align-items: center; margin-bottom: 10px; }
.grade-label { width: 100px; font-weight: 600; }
.grade-bar-bg { flex: 1; background: #1a2d42; border-radius: 4px; height: 22px; overflow: hidden; }
.grade-bar-fill { height: 100%; border-radius: 4px; transition: width 0.3s; display: flex; align-items: center; padding: 0 8px; font-size: 0.8rem; font-weight: 600; color: #fff; }
.grade-count { width: 80px; text-align: right; color: #a0bcd8; font-size: 0.9rem; }

/* 히트맵 그리드 */
.heatmap-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 12px; margin-top: 16px; }
.company-card {
    border-radius: 8px;
    padding: 14px;
    color: #fff;
    font-size: 0.85rem;
    position: relative;
    overflow: hidden;
}
.company-card .company-name { font-weight: 700; font-size: 0.95rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.company-card .company-domain { font-size: 0.75rem; opacity: 0.8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.company-card .grade-badge {
    position: absolute; top: 8px; right: 10px;
    font-size: 1.4rem; font-weight: 900; opacity: 0.9;
}
.company-card .finding-row { margin-top: 8px; font-size: 0.78rem; opacity: 0.9; }

/* 테이블 */
table { width: 100%; border-collapse: collapse; font-size: 0.9rem; }
th { background: #1e3a5f; padding: 10px 12px; text-align: left; color: #a0c8e8; }
td { padding: 9px 12px; border-bottom: 1px solid #1a2d42; }
tr:hover td { background: #162233; }
.grade-chip { display: inline-block; padding: 2px 10px; border-radius: 12px; font-weight: 700; font-size: 0.85rem; }

/* 취약점 바 차트 */
.vuln-bar-row { display: flex; align-items: center; margin-bottom: 8px; }
.vuln-label { width: 250px; font-size: 0.82rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.vuln-bar-bg { flex: 1; background: #1a2d42; border-radius: 3px; height: 16px; overflow: hidden; }
.vuln-bar-fill { height: 100%; background: #3498db; border-radius: 3px; }
.vuln-count { width: 60px; text-align: right; font-size: 0.82rem; color: #a0bcd8; }

/* 권고 사항 */
.rec-card { background: #1a2d42; border-left: 4px solid; border-radius: 0 8px 8px 0; padding: 14px 16px; margin-bottom: 12px; }
.rec-title { font-weight: 700; margin-bottom: 6px; }
.rec-body { font-size: 0.9rem; color: #a0bcd8; }

footer { margin-top: 48px; font-size: 0.8rem; color: #405060; text-align: center; }
"""


def generate_heatmap_html(result: "IndustryScanResult") -> str:
    """독립형 HTML 히트맵 리포트를 생성합니다.

    인라인 CSS 포함 완전 독립형으로, 별도 라이브러리 없이 브라우저에서 바로 열 수 있습니다.

    Args:
        result: :class:`~vxis.industry.scanner.IndustryScanResult` 집계 결과.

    Returns:
        완전한 HTML 문서 문자열.
    """
    now = datetime.now(timezone.utc).strftime("%Y년 %m월 %d일 %H:%M UTC")
    total_findings = sum(result.industry_findings.values())

    # ── 통계 카드 ────────────────────────────────────────────────────────
    stat_cards_html = _make_stat_cards(result, total_findings)

    # ── 등급 분포 바 차트 ────────────────────────────────────────────────
    grade_bar_html = _make_grade_bars(result)

    # ── 히트맵 그리드 ────────────────────────────────────────────────────
    heatmap_grid_html = _make_heatmap_grid(result.companies)

    # ── 취약 기업 Top 10 테이블 ──────────────────────────────────────────
    top_vuln_table_html = _make_top_vulnerable_table(result.companies)

    # ── 취약점 유형 바 차트 ──────────────────────────────────────────────
    vuln_bar_html = _make_vuln_bars(result.most_common_vulns)

    # ── 권고 사항 ────────────────────────────────────────────────────────
    rec_html = _make_recommendations(result.grade_distribution)

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VXIS 산업 보안 히트맵 리포트</title>
<style>{_HTML_CSS}</style>
</head>
<body>
<div class="container">
  <h1>산업 보안 리스크 히트맵</h1>
  <p class="meta">
    생성 일시: {html.escape(now)} &nbsp;|&nbsp;
    스캔 기간: {html.escape(result.started_at)} ~ {html.escape(result.completed_at)} &nbsp;|&nbsp;
    소요 시간: {result.scan_duration:.0f}초
  </p>

  {stat_cards_html}

  <h2>보안 등급 분포</h2>
  {grade_bar_html}

  <h2>전체 기업 히트맵</h2>
  {heatmap_grid_html}

  <h2>가장 취약한 기업 Top 10</h2>
  {top_vuln_table_html}

  <h2>가장 빈번한 취약점 유형 (Top 15)</h2>
  {vuln_bar_html}

  <h2>등급별 보안 권고 사항</h2>
  {rec_html}

  <footer>
    본 리포트는 VXIS 자율 보안 스캔 플랫폼에 의해 자동 생성되었습니다.
    외부 공개 시 민감 정보 포함 여부를 반드시 확인하세요.
  </footer>
</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# HTML 내부 섹션 빌더
# ---------------------------------------------------------------------------


def _make_stat_cards(result: "IndustryScanResult", total_findings: int) -> str:
    cards = [
        (str(result.total_companies), "전체 기업"),
        (str(result.scanned_companies), "스캔 완료"),
        (str(result.failed_companies), "스캔 실패"),
        (result.average_grade, "평균 등급"),
        (f"{total_findings:,}", "총 취약점"),
        (str(result.industry_findings.get("critical", 0)), "Critical"),
        (str(result.industry_findings.get("high", 0)), "High"),
    ]
    items = "".join(
        f'<div class="stat-card"><div class="val">{html.escape(v)}</div>'
        f'<div class="lbl">{html.escape(l)}</div></div>'
        for v, l in cards
    )
    return f'<div class="stat-grid">{items}</div>'


def _make_grade_bars(result: "IndustryScanResult") -> str:
    total = sum(result.grade_distribution.values()) or 1
    rows = []
    for grade in ["A", "B", "C", "D", "F"]:
        count = result.grade_distribution.get(grade, 0)
        pct = count / total * 100
        color = _GRADE_COLORS_HEX.get(grade, "#95a5a6")
        label = _GRADE_LABELS_KR.get(grade, grade)
        rows.append(
            f'<div class="grade-bar-row">'
            f'  <div class="grade-label">{html.escape(label)}</div>'
            f'  <div class="grade-bar-bg">'
            f'    <div class="grade-bar-fill" style="width:{pct:.1f}%;background:{color}">'
            f'      {pct:.1f}%'
            f'    </div>'
            f'  </div>'
            f'  <div class="grade-count">{count}개</div>'
            f'</div>'
        )
    return "\n".join(rows)


def _make_heatmap_grid(companies: list[CompanyProfile]) -> str:
    """등급별로 정렬된 기업 카드 그리드."""
    grade_order = {"F": 0, "D": 1, "C": 2, "B": 3, "A": 4, "": 5}
    sorted_companies = sorted(
        companies,
        key=lambda c: grade_order.get(c.security_grade, 5),
    )

    cards = []
    for company in sorted_companies:
        color = _GRADE_COLORS_HEX.get(company.security_grade, "#95a5a6")
        grade_display = html.escape(company.security_grade or "?")
        name = html.escape(company.name[:30])
        domain = html.escape(company.domain[:35])
        cards.append(
            f'<div class="company-card" style="background:{color}22;border:1px solid {color}55">'
            f'  <div class="grade-badge" style="color:{color}">{grade_display}</div>'
            f'  <div class="company-name">{name}</div>'
            f'  <div class="company-domain">{domain}</div>'
            f'  <div class="finding-row">'
            f'    Critical: {company.critical_count} &nbsp; High: {company.high_count} &nbsp; 총: {company.findings_count}'
            f'  </div>'
            f'</div>'
        )

    grid = "\n".join(cards)
    return f'<div class="heatmap-grid">{grid}</div>'


def _make_top_vulnerable_table(companies: list[CompanyProfile]) -> str:
    sorted_top = sorted(
        [c for c in companies if c.security_grade],
        key=lambda c: (-c.critical_count, -c.high_count, -c.findings_count),
    )[:10]

    rows = []
    for rank, company in enumerate(sorted_top, 1):
        color = _GRADE_COLORS_HEX.get(company.security_grade, "#95a5a6")
        rows.append(
            f"<tr>"
            f"  <td>{rank}</td>"
            f"  <td>{html.escape(company.name)}</td>"
            f"  <td>{html.escape(company.domain)}</td>"
            f'  <td><span class="grade-chip" style="background:{color}33;color:{color}">'
            f"      {html.escape(company.security_grade)}</span></td>"
            f"  <td>{company.critical_count}</td>"
            f"  <td>{company.high_count}</td>"
            f"  <td>{company.findings_count}</td>"
            f"</tr>"
        )

    rows_html = "\n".join(rows) if rows else "<tr><td colspan='7'>데이터 없음</td></tr>"

    return f"""<table>
<thead>
  <tr>
    <th>순위</th><th>기업명</th><th>도메인</th>
    <th>등급</th><th>Critical</th><th>High</th><th>총 취약점</th>
  </tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>"""


def _make_vuln_bars(most_common_vulns: list[tuple[str, int]]) -> str:
    top15 = most_common_vulns[:15]
    if not top15:
        return "<p><em>취약점 유형 데이터가 없습니다.</em></p>"

    max_count = top15[0][1] if top15 else 1

    rows = []
    for vuln_type, count in top15:
        pct = count / max_count * 100
        rows.append(
            f'<div class="vuln-bar-row">'
            f'  <div class="vuln-label">{html.escape(vuln_type)}</div>'
            f'  <div class="vuln-bar-bg">'
            f'    <div class="vuln-bar-fill" style="width:{pct:.1f}%"></div>'
            f'  </div>'
            f'  <div class="vuln-count">{count:,}건</div>'
            f'</div>'
        )
    return "\n".join(rows)


def _make_recommendations(grade_distribution: dict[str, int]) -> str:
    cards = []
    border_colors = {
        "F": "#7b2c34",
        "D": "#c0392b",
        "C": "#e67e22",
        "B": "#3498db",
        "A": "#2ecc71",
    }
    for grade in ["F", "D", "C", "B", "A"]:
        count = grade_distribution.get(grade, 0)
        if count == 0:
            continue
        rec = _GRADE_RECOMMENDATIONS.get(grade, "")
        label = _GRADE_LABELS_KR.get(grade, grade)
        color = border_colors.get(grade, "#607080")
        cards.append(
            f'<div class="rec-card" style="border-color:{color}">'
            f'  <div class="rec-title" style="color:{color}">'
            f"    등급 {html.escape(label)} ({count}개 기업)"
            f"  </div>"
            f'  <div class="rec-body">{html.escape(rec)}</div>'
            f"</div>"
        )
    return "\n".join(cards) if cards else "<p>권고 사항이 없습니다.</p>"
