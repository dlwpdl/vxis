"""VXIS Brain — 자동 중간/최종 리포트 작성기.

Brain이 스캔 중 매 스텝마다 호출하여 진행 상황을 기록하고,
최종 완료 시 전체 리포트를 마크다운으로 출력한다.

Usage:
    writer = ReportWriter(target="https://target.com", output_dir="/tmp/vxis_reports")
    writer.step_report(step=1, title="Initial Recon", findings=[...], notes="...")
    writer.step_report(step=2, title="API Probing", findings=[...], notes="...")
    writer.finalize()  # 최종 리포트 생성
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Finding:
    """발견된 취약점/이슈."""

    id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    detail: str = ""
    impact: str = ""
    recommendation: str = ""
    evidence: str = ""  # 증거 (요청/응답 등)


@dataclass
class StepReport:
    """한 스텝의 리포트."""

    step: int
    title: str
    timestamp: str
    findings: list[Finding]
    notes: str = ""
    tools_used: list[str] = field(default_factory=list)
    duration_ms: float = 0


class ReportWriter:
    """스캔 중간/최종 리포트를 자동 생성."""

    def __init__(
        self,
        target: str,
        output_dir: str | Path = "/tmp/vxis_reports",
    ) -> None:
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._steps: list[StepReport] = []
        self._all_findings: list[Finding] = []
        self._good_items: list[str] = []
        self._start_time = datetime.now(timezone.utc)
        self._target_info: dict[str, Any] = {}

        # 타깃 이름으로 안전한 파일명
        safe_name = target.replace("https://", "").replace("http://", "").replace("/", "_").rstrip("_")
        self._safe_name = safe_name
        self._report_path = self.output_dir / f"report_{safe_name}.md"
        self._progress_path = self.output_dir / f"progress_{safe_name}.md"

        logger.info("ReportWriter initialized: %s → %s", target, self._report_path)

    def set_target_info(self, info: dict[str, Any]) -> None:
        """타깃 기본 정보 설정 (서버, 기술 스택 등)."""
        self._target_info = info

    def add_good_item(self, description: str) -> None:
        """양호 항목 추가."""
        self._good_items.append(description)

    def step_report(
        self,
        step: int,
        title: str,
        findings: list[Finding] | list[dict[str, str]] | None = None,
        notes: str = "",
        tools_used: list[str] | None = None,
        duration_ms: float = 0,
    ) -> str:
        """한 스텝 완료 후 중간 리포트 작성. 파일에 저장하고 마크다운 반환."""
        parsed_findings: list[Finding] = []
        if findings:
            for f in findings:
                if isinstance(f, Finding):
                    parsed_findings.append(f)
                elif isinstance(f, dict):
                    parsed_findings.append(Finding(
                        id=f.get("id", f"V-{len(self._all_findings) + len(parsed_findings) + 1:03d}"),
                        severity=f.get("severity", "INFO"),
                        title=f.get("title", "Unknown"),
                        detail=f.get("detail", ""),
                        impact=f.get("impact", ""),
                        recommendation=f.get("recommendation", ""),
                        evidence=f.get("evidence", ""),
                    ))

        sr = StepReport(
            step=step,
            title=title,
            timestamp=datetime.now(timezone.utc).isoformat(),
            findings=parsed_findings,
            notes=notes,
            tools_used=tools_used or [],
            duration_ms=duration_ms,
        )
        self._steps.append(sr)
        self._all_findings.extend(parsed_findings)

        # 중간 진행 리포트 갱신
        progress_md = self._render_progress()
        self._progress_path.write_text(progress_md, encoding="utf-8")

        logger.info(
            "Step %d [%s]: %d findings — %s",
            step, title, len(parsed_findings), self._progress_path,
        )

        return progress_md

    def finalize(self) -> Path:
        """최종 리포트 생성. 파일 경로 반환."""
        report_md = self._render_final()
        self._report_path.write_text(report_md, encoding="utf-8")

        # JSON 형태도 함께 저장
        json_path = self.output_dir / f"report_{self._safe_name}.json"
        json_data = {
            "target": self.target,
            "scan_date": self._start_time.isoformat(),
            "duration_seconds": (datetime.now(timezone.utc) - self._start_time).total_seconds(),
            "target_info": self._target_info,
            "summary": {
                "total_findings": len(self._all_findings),
                "critical": sum(1 for f in self._all_findings if f.severity == "CRITICAL"),
                "high": sum(1 for f in self._all_findings if f.severity == "HIGH"),
                "medium": sum(1 for f in self._all_findings if f.severity == "MEDIUM"),
                "low": sum(1 for f in self._all_findings if f.severity == "LOW"),
                "info": sum(1 for f in self._all_findings if f.severity == "INFO"),
            },
            "findings": [
                {
                    "id": f.id,
                    "severity": f.severity,
                    "title": f.title,
                    "detail": f.detail,
                    "impact": f.impact,
                    "recommendation": f.recommendation,
                }
                for f in self._all_findings
            ],
            "good_items": self._good_items,
            "steps": [
                {
                    "step": s.step,
                    "title": s.title,
                    "timestamp": s.timestamp,
                    "findings_count": len(s.findings),
                    "tools_used": s.tools_used,
                    "notes": s.notes,
                }
                for s in self._steps
            ],
        }
        json_path.write_text(json.dumps(json_data, indent=2, ensure_ascii=False), encoding="utf-8")

        logger.info("Final report: %s", self._report_path)
        logger.info("JSON report: %s", json_path)

        return self._report_path

    # ── Rendering ─────────────────────────────────────────────

    def _severity_icon(self, sev: str) -> str:
        return {
            "CRITICAL": "[C]",
            "HIGH": "[H]",
            "MEDIUM": "[M]",
            "LOW": "[L]",
            "INFO": "[I]",
        }.get(sev.upper(), "[?]")

    def _render_progress(self) -> str:
        """중간 진행 리포트 렌더링."""
        lines = [
            f"# VXIS Scan Progress — {self.target}",
            f"_Updated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}_\n",
            f"## Summary So Far",
            f"- Steps completed: {len(self._steps)}",
            f"- Findings: {len(self._all_findings)} "
            f"(H:{sum(1 for f in self._all_findings if f.severity=='HIGH')} "
            f"M:{sum(1 for f in self._all_findings if f.severity=='MEDIUM')} "
            f"L:{sum(1 for f in self._all_findings if f.severity=='LOW')} "
            f"I:{sum(1 for f in self._all_findings if f.severity=='INFO')})\n",
        ]

        for sr in self._steps:
            lines.append(f"### Step {sr.step}: {sr.title}")
            if sr.tools_used:
                lines.append(f"Tools: {', '.join(sr.tools_used)}")
            if sr.findings:
                for f in sr.findings:
                    lines.append(f"- {self._severity_icon(f.severity)} **{f.title}**")
            if sr.notes:
                lines.append(f"\n_{sr.notes}_")
            lines.append("")

        return "\n".join(lines)

    def _render_final(self) -> str:
        """최종 리포트 렌더링."""
        duration = (datetime.now(timezone.utc) - self._start_time).total_seconds()

        lines = [
            f"# VXIS Penetration Test Report",
            f"## Target: {self.target}",
            f"- Date: {self._start_time.strftime('%Y-%m-%d')}",
            f"- Duration: {duration:.0f}s",
            f"- Steps: {len(self._steps)}",
            f"- Total Findings: {len(self._all_findings)}",
        ]

        if self._target_info:
            lines.append("\n## Target Information")
            for k, v in self._target_info.items():
                lines.append(f"- {k}: {v}")

        # 요약 테이블
        lines.append("\n## Finding Summary")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            cnt = sum(1 for f in self._all_findings if f.severity == sev)
            if cnt:
                lines.append(f"| {sev} | {cnt} |")

        # 발견 항목 상세
        lines.append("\n## Findings\n")
        sorted_findings = sorted(
            self._all_findings,
            key=lambda f: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(f.severity, 99),
        )
        for f in sorted_findings:
            lines.append(f"### {self._severity_icon(f.severity)} {f.id}: {f.title}")
            lines.append(f"**Severity:** {f.severity}\n")
            if f.detail:
                lines.append(f"**Detail:** {f.detail}\n")
            if f.impact:
                lines.append(f"**Impact:** {f.impact}\n")
            if f.recommendation:
                lines.append(f"**Recommendation:** {f.recommendation}\n")
            if f.evidence:
                lines.append(f"**Evidence:**\n```\n{f.evidence}\n```\n")

        # 양호 항목
        if self._good_items:
            lines.append("\n## Good Practices Observed\n")
            for g in self._good_items:
                lines.append(f"- {g}")

        # 스텝별 실행 로그
        lines.append("\n## Execution Log\n")
        for sr in self._steps:
            lines.append(f"### Step {sr.step}: {sr.title} ({sr.timestamp})")
            if sr.tools_used:
                lines.append(f"- Tools: {', '.join(sr.tools_used)}")
            lines.append(f"- Findings: {len(sr.findings)}")
            if sr.notes:
                lines.append(f"- Notes: {sr.notes}")
            lines.append("")

        lines.append(f"\n---\n_Generated by VXIS Cognitive Pentesting Runtime_")
        return "\n".join(lines)
