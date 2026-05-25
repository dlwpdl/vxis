"""리포트 생성 + 리뷰 큐 — 직접 발송하지 않음, 사람 승인 필수.

:class:`OutreachQueue` 는 기업별 HTML 리포트를 생성하고
``~/.vxis/outreach/queue.json`` 에 저장합니다.

**절대로 자동 발송하지 않습니다.** 모든 발송은 사람이 큐를 검토하고
:meth:`OutreachQueue.approve` 를 호출한 뒤 별도 클라이언트가 처리해야 합니다.

사용 예::

    from vxis.industry import IndustryScanResult, OutreachQueue

    queue = OutreachQueue()
    items = [queue.generate_company_report(company, result) for company in companies]
    queue.save_queue(items)

    # 나중에 검토
    pending = queue.get_pending()
    queue.approve(pending[0].item_id, notes="CISO 검토 완료, 발송 승인")
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from vxis.industry.scanner import IndustryScanResult

from vxis.industry.discovery import CompanyProfile

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 기본 경로
# ---------------------------------------------------------------------------

_DEFAULT_QUEUE_DIR = Path.home() / ".vxis" / "outreach"
_QUEUE_FILE = "queue.json"
_REPORTS_SUBDIR = "reports"

# ---------------------------------------------------------------------------
# OutreachItem
# ---------------------------------------------------------------------------

_VALID_STATUSES = {"pending", "approved", "rejected", "sent"}


@dataclass
class OutreachItem:
    """아웃리치 큐의 개별 항목.

    Attributes:
        item_id: UUID v4 기반 고유 식별자.
        company: 대상 기업 프로필.
        report_path: 생성된 HTML 리포트 파일 절대 경로.
        status: 'pending' | 'approved' | 'rejected' | 'sent'.
        reviewer_notes: 검토자 메모.
        created_at: 생성 시각 (ISO 8601).
        reviewed_at: 검토 완료 시각 (ISO 8601).
    """

    item_id: str
    company: CompanyProfile
    report_path: str
    status: str = "pending"
    reviewer_notes: str = ""
    created_at: str = ""
    reviewed_at: str = ""

    def __post_init__(self) -> None:
        if self.status not in _VALID_STATUSES:
            raise ValueError(
                f"유효하지 않은 상태: {self.status!r}. 허용 값: {sorted(_VALID_STATUSES)}"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "item_id": self.item_id,
            "company": self.company.to_dict(),
            "report_path": self.report_path,
            "status": self.status,
            "reviewer_notes": self.reviewer_notes,
            "created_at": self.created_at,
            "reviewed_at": self.reviewed_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> "OutreachItem":
        return cls(
            item_id=str(data["item_id"]),
            company=CompanyProfile.from_dict(data["company"]),  # type: ignore[arg-type]
            report_path=str(data["report_path"]),
            status=str(data.get("status", "pending")),
            reviewer_notes=str(data.get("reviewer_notes", "")),
            created_at=str(data.get("created_at", "")),
            reviewed_at=str(data.get("reviewed_at", "")),
        )


# ---------------------------------------------------------------------------
# OutreachQueue
# ---------------------------------------------------------------------------


class OutreachQueue:
    """아웃리치 리뷰 큐 관리자.

    모든 상태 변경은 ``queue_dir / queue.json`` 에 지속됩니다.
    발송 로직은 포함하지 않습니다 — 사람이 승인해야만 합니다.

    Args:
        queue_dir: 큐 저장 경로 (기본: ``~/.vxis/outreach/``).
    """

    def __init__(self, queue_dir: Path | str | None = None) -> None:
        self._queue_dir = Path(queue_dir) if queue_dir else _DEFAULT_QUEUE_DIR
        self._queue_dir.mkdir(parents=True, exist_ok=True)
        self._reports_dir = self._queue_dir / _REPORTS_SUBDIR
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        self._queue_path = self._queue_dir / _QUEUE_FILE

    # ------------------------------------------------------------------
    # 리포트 생성
    # ------------------------------------------------------------------

    def generate_company_report(
        self,
        company: CompanyProfile,
        industry_result: "IndustryScanResult | None" = None,
    ) -> "OutreachItem":
        """개별 기업용 HTML 리포트를 생성하고 OutreachItem을 반환합니다.

        보안 등급, 취약점 통계, 산업 비교 데이터를 포함한 HTML 리포트를
        ``queue_dir/reports/<domain>_<uuid>.html`` 에 저장합니다.

        **자동 발송 금지** — 반환된 item은 status='pending' 상태입니다.

        Args:
            company: 대상 기업 프로필 (보안 등급이 채워진 상태여야 합니다).
            industry_result: 산업 전체 결과 (비교 데이터에 사용). None 이면 생략.

        Returns:
            status='pending' 상태의 :class:`OutreachItem`.
        """
        item_id = str(uuid.uuid4())
        now_ts = datetime.now(timezone.utc).isoformat()

        # 산업 비교 텍스트 계산
        comparison_html = self._build_comparison_html(company, industry_result)

        # HTML 리포트 렌더링
        report_html = self._render_company_html(company, comparison_html, now_ts)

        # 저장
        safe_domain = company.domain.replace(".", "_").replace("/", "_")
        report_filename = f"{safe_domain}_{item_id[:8]}.html"
        report_path = self._reports_dir / report_filename

        report_path.write_text(report_html, encoding="utf-8")
        logger.info("리포트 생성됨: %s → %s", company.name, report_path)

        return OutreachItem(
            item_id=item_id,
            company=company,
            report_path=str(report_path),
            status="pending",
            created_at=now_ts,
        )

    # ------------------------------------------------------------------
    # 큐 영속화
    # ------------------------------------------------------------------

    def save_queue(self, items: list[OutreachItem]) -> None:
        """항목 목록을 큐 파일에 저장합니다. 기존 큐에 병합합니다.

        동일 item_id는 덮어씁니다.

        Args:
            items: 저장할 :class:`OutreachItem` 목록.
        """
        existing = self._load_raw()
        existing_map = {r["item_id"]: r for r in existing}

        for item in items:
            existing_map[item.item_id] = item.to_dict()

        self._queue_path.write_text(
            json.dumps(list(existing_map.values()), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("큐 저장됨: %d개 항목 → %s", len(existing_map), self._queue_path)

    def get_pending(self) -> list[OutreachItem]:
        """'pending' 상태의 항목 목록을 반환합니다.

        Returns:
            승인 대기 중인 :class:`OutreachItem` 목록.
        """
        return [OutreachItem.from_dict(r) for r in self._load_raw() if r.get("status") == "pending"]

    def get_all(self) -> list[OutreachItem]:
        """전체 큐 항목을 반환합니다."""
        return [OutreachItem.from_dict(r) for r in self._load_raw()]

    # ------------------------------------------------------------------
    # 상태 변경
    # ------------------------------------------------------------------

    def approve(self, item_id: str, notes: str = "") -> OutreachItem:
        """항목을 'approved' 상태로 변경합니다.

        승인 후 실제 발송은 외부에서 처리해야 합니다.
        이 메서드는 절대로 이메일을 발송하지 않습니다.

        Args:
            item_id: 승인할 항목의 UUID.
            notes: 검토자 메모.

        Returns:
            업데이트된 :class:`OutreachItem`.

        Raises:
            KeyError: item_id를 찾을 수 없을 때.
        """
        return self._update_status(item_id, "approved", notes)

    def reject(self, item_id: str, reason: str = "") -> OutreachItem:
        """항목을 'rejected' 상태로 변경합니다.

        Args:
            item_id: 거절할 항목의 UUID.
            reason: 거절 사유.

        Returns:
            업데이트된 :class:`OutreachItem`.

        Raises:
            KeyError: item_id를 찾을 수 없을 때.
        """
        return self._update_status(item_id, "rejected", reason)

    def mark_sent(self, item_id: str, notes: str = "") -> OutreachItem:
        """항목을 'sent' 상태로 변경합니다.

        발송 확인 후 외부에서 호출합니다.

        Args:
            item_id: 발송된 항목의 UUID.
            notes: 발송 메모 (예: 발송 채널, 담당자).

        Returns:
            업데이트된 :class:`OutreachItem`.

        Raises:
            KeyError: item_id를 찾을 수 없을 때.
            ValueError: 'approved' 상태가 아닌 항목을 발송 처리하려 할 때.
        """
        raw_list = self._load_raw()
        target = next((r for r in raw_list if r["item_id"] == item_id), None)
        if target is None:
            raise KeyError(f"항목을 찾을 수 없습니다: {item_id}")
        if target.get("status") != "approved":
            raise ValueError(
                f"발송 처리는 'approved' 상태만 가능합니다. 현재 상태: {target.get('status')!r}"
            )
        return self._update_status(item_id, "sent", notes)

    # ------------------------------------------------------------------
    # 내부 헬퍼
    # ------------------------------------------------------------------

    def _update_status(self, item_id: str, new_status: str, notes: str) -> OutreachItem:
        """큐 파일에서 특정 항목의 상태를 업데이트합니다."""
        raw_list = self._load_raw()
        updated: dict | None = None

        for entry in raw_list:
            if entry["item_id"] == item_id:
                entry["status"] = new_status
                entry["reviewer_notes"] = notes
                entry["reviewed_at"] = datetime.now(timezone.utc).isoformat()
                updated = entry
                break

        if updated is None:
            raise KeyError(f"항목을 찾을 수 없습니다: {item_id}")

        self._queue_path.write_text(
            json.dumps(raw_list, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        logger.info("큐 상태 변경: %s → %s (notes=%r)", item_id[:8], new_status, notes[:50])
        return OutreachItem.from_dict(updated)

    def _load_raw(self) -> list[dict]:
        """큐 파일에서 raw dict 목록을 로드합니다. 파일 없으면 빈 리스트."""
        if not self._queue_path.exists():
            return []
        try:
            data = json.loads(self._queue_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("큐 파일 로드 실패: %s", exc)
        return []

    # ------------------------------------------------------------------
    # HTML 렌더링
    # ------------------------------------------------------------------

    @staticmethod
    def _build_comparison_html(
        company: CompanyProfile,
        industry_result: "IndustryScanResult | None",
    ) -> str:
        """산업 비교 섹션 HTML을 빌드합니다."""
        import html as _html

        if industry_result is None or not industry_result.companies:
            return "<p>산업 비교 데이터가 없습니다.</p>"

        total = len(industry_result.companies)
        worse_than = sum(
            1 for c in industry_result.companies if c.findings_count > company.findings_count
        )
        percentile = int((worse_than / total) * 100) if total > 0 else 0
        inverse_pct = 100 - percentile  # 하위 X%

        avg_grade = industry_result.average_grade
        grade_label = {
            "A": "우수",
            "B": "양호",
            "C": "주의",
            "D": "위험",
            "F": "심각",
        }.get(company.security_grade, "미평가")

        return f"""
<div style="background:#1a2d42;border-radius:8px;padding:16px;margin:16px 0">
  <h3 style="color:#64c8ff;margin-bottom:12px">산업 비교 분석</h3>
  <p>
    귀사의 보안 등급은 <strong style="color:#e0e6ef">{_html.escape(company.security_grade)} ({grade_label})</strong>이며,
    동종 업계 평균 등급 <strong>{_html.escape(avg_grade)}</strong> 대비
    귀사는 업계 <strong style="color:#e74c3c">하위 {inverse_pct}%</strong>에 위치합니다.
  </p>
  <p style="margin-top:8px;font-size:0.9em;color:#a0bcd8">
    분석 대상 {total}개 기업 중 {worse_than}개 기업이 귀사보다 더 많은 취약점을 보유합니다.
  </p>
</div>"""

    @staticmethod
    def _render_company_html(
        company: CompanyProfile,
        comparison_html: str,
        generated_at: str,
    ) -> str:
        """개별 기업 HTML 리포트를 렌더링합니다."""
        import html as _html

        grade_colors = {
            "A": "#2ecc71",
            "B": "#3498db",
            "C": "#e67e22",
            "D": "#c0392b",
            "F": "#7b2c34",
        }
        grade_color = grade_colors.get(company.security_grade, "#95a5a6")
        grade = _html.escape(company.security_grade or "N/A")
        name = _html.escape(company.name)
        domain = _html.escape(company.domain)
        industry = _html.escape(company.industry or "")
        last_scanned = _html.escape(company.last_scanned or "-")

        severity_rows = "\n".join(
            [
                f"<tr><td>Critical</td><td style='color:#c0392b;font-weight:700'>{company.critical_count}</td></tr>",
                f"<tr><td>High</td><td style='color:#e67e22;font-weight:700'>{company.high_count}</td></tr>",
                f"<tr><td>총 취약점</td><td>{company.findings_count}</td></tr>",
            ]
        )

        tech_stack_html = (
            " ".join(
                f'<span style="background:#1e3a5f;padding:2px 8px;border-radius:4px;font-size:0.8em">'
                f"{_html.escape(t)}</span>"
                for t in (company.tech_stack or [])
            )
            or "<em>정보 없음</em>"
        )

        return f"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VXIS 보안 리포트 — {name}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: #0f1923; color: #e0e6ef; line-height: 1.6; padding: 32px; }}
  .header {{ display: flex; align-items: center; gap: 24px; margin-bottom: 32px; }}
  .grade-badge {{ font-size: 4rem; font-weight: 900; color: {grade_color}; }}
  h1 {{ font-size: 1.8rem; color: #64c8ff; }}
  .subtitle {{ color: #607080; font-size: 0.9rem; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
  th {{ background: #1e3a5f; padding: 8px 12px; text-align: left; color: #a0c8e8; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #1a2d42; }}
  h2 {{ font-size: 1.1rem; color: #a0bcd8; margin: 28px 0 8px;
        border-bottom: 1px solid #1e3a5f; padding-bottom: 4px; }}
  .notice {{ background: #2d1a1a; border-left: 4px solid #c0392b;
             padding: 12px 16px; border-radius: 0 8px 8px 0; margin-top: 32px;
             font-size: 0.85rem; color: #e0a0a0; }}
  footer {{ margin-top: 48px; font-size: 0.8rem; color: #405060; }}
</style>
</head>
<body>

<div class="header">
  <div class="grade-badge">{grade}</div>
  <div>
    <h1>{name} 보안 진단 리포트</h1>
    <div class="subtitle">
      도메인: {domain} &nbsp;|&nbsp; 산업: {industry} &nbsp;|&nbsp;
      스캔 일시: {last_scanned}
    </div>
  </div>
</div>

<h2>취약점 요약</h2>
<table>
  <thead><tr><th>항목</th><th>수치</th></tr></thead>
  <tbody>
    {severity_rows}
  </tbody>
</table>

<h2>탐지된 기술 스택</h2>
<p style="margin-top:8px">{tech_stack_html}</p>

{comparison_html}

<div class="notice">
  <strong>주의:</strong>
  본 리포트는 외부 노출 없이 수신자만 열람해야 합니다.
  취약점 정보는 악용될 수 있으므로 내부 보안팀에 즉시 전달해 주세요.
</div>

<footer>
  생성 일시: {_html.escape(generated_at)} &nbsp;|&nbsp;
  VXIS 자율 보안 스캔 플랫폼 &nbsp;|&nbsp;
  본 메시지는 자동 발송이 아닙니다. 승인된 담당자가 발송합니다.
</footer>

</body>
</html>"""
