"""ScanContext — Phase 간 공유 상태 + Deferred Action Queue."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vxis.models.finding import Finding
from vxis.scoring.tracker import ScoreTracker

logger = logging.getLogger(__name__)


@dataclass
class DeferredAction:
    """데이터 변조 작업 — 마지막에 승인 후 실행."""

    id: int
    phase: str
    description_en: str
    description_ko: str
    method: str  # POST, PATCH, DELETE, PUT
    url: str
    data: dict[str, Any] | None = None
    risk: str = "low"  # low, medium, high
    approved: bool = False
    executed: bool = False
    result: str = ""


@dataclass
class ScanContext:
    """모든 Phase가 공유하는 스캔 상태.

    Phase 간 데이터 전달, 발견 누적, 변조 작업 대기열을 관리.
    """

    target: str
    target_type: str = "web"  # "web" | "game" | "mobile"
    app_context_en: str = ""
    app_context_ko: str = ""
    scan_id: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Capability Scoring ──
    score_tracker: ScoreTracker = field(init=False)

    # ── 수집된 정보 ──
    tech_stack: list[str] = field(default_factory=list)
    subdomains: list[dict[str, Any]] = field(default_factory=list)
    api_endpoints: list[dict[str, Any]] = field(default_factory=list)
    js_bundles: list[str] = field(default_factory=list)
    tls_info: dict[str, Any] = field(default_factory=dict)
    target_profile: dict[str, Any] = field(default_factory=dict)

    # ── Attack Graph ──
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)
    chain_mutations: list[dict[str, Any]] = field(default_factory=list)

    # ── CVE / Forecast ──
    matched_cves: list[dict[str, Any]] = field(default_factory=list)
    forecast_90d: list[dict[str, Any]] = field(default_factory=list)

    # ── Digital Twin ──
    twin_results: dict[str, Any] = field(default_factory=dict)

    # ── Biometrics ──
    biometrics: dict[str, Any] = field(default_factory=dict)

    # ── Findings ──
    findings: list[Finding] = field(default_factory=list)
    finding_counter: int = 0

    # ── Red vs Blue ──
    defense_rules: list[dict[str, Any]] = field(default_factory=list)

    # ── Ghost Mode ──
    ghost_active: bool = False

    # ── Deferred Actions (데이터 변조 대기열) ──
    deferred_actions: list[DeferredAction] = field(default_factory=list)
    _deferred_counter: int = 0

    # ── Phase 실행 추적 ──
    phases_completed: list[str] = field(default_factory=list)
    phase_logs: list[dict[str, Any]] = field(default_factory=list)

    # ── X-Ray 플로우 ──
    xray_flows: int = 0
    xray_vulns: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        """ScoreTracker를 target_type에 맞게 초기화한다."""
        object.__setattr__(self, "score_tracker", ScoreTracker(target_type=self.target_type))

    def add_finding(self, **kwargs: Any) -> Finding:
        """Finding 추가."""
        from vxis.models.finding import Finding as F
        self.finding_counter += 1
        kwargs.setdefault("id", f"VXIS-{self.finding_counter:03d}")
        kwargs.setdefault("scan_id", self.scan_id)
        kwargs.setdefault("source_plugin", "vxis-pipeline")
        f = F(**kwargs)
        self.findings.append(f)
        logger.info("[%s] %s: %s", f.severity.value.upper(), f.id, f.title.split("|||")[0])
        return f

    def defer_action(
        self,
        phase: str,
        description_en: str,
        description_ko: str,
        method: str,
        url: str,
        data: dict[str, Any] | None = None,
        risk: str = "low",
    ) -> DeferredAction:
        """데이터 변조 작업을 대기열에 추가. 마지막에 승인 후 실행."""
        self._deferred_counter += 1
        action = DeferredAction(
            id=self._deferred_counter,
            phase=phase,
            description_en=description_en,
            description_ko=description_ko,
            method=method,
            url=url,
            data=data,
            risk=risk,
        )
        self.deferred_actions.append(action)
        logger.info("[DEFERRED #%d] %s %s — %s", action.id, method, url, description_en[:60])
        return action

    def log_phase(self, phase_name: str, duration_ms: float = 0, findings_count: int = 0, notes: str = "") -> None:
        """Phase 실행 기록."""
        self.phases_completed.append(phase_name)
        self.phase_logs.append({
            "phase": phase_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_ms": duration_ms,
            "findings_count": findings_count,
            "notes": notes,
        })
        logger.info("[PHASE DONE] %s — %d findings, %s", phase_name, findings_count, notes[:80])

    @property
    def duration_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.started_at).total_seconds()

    # ── Checkpoint: 실패 지점에서 재시도 ──

    def save_checkpoint(self, path: Path | None = None) -> Path:
        """현재 스캔 상태를 JSON 체크포인트로 저장."""
        if path is None:
            path = Path(f"tools/benchmark/.brain/{self.scan_id}-checkpoint.json")
        path.parent.mkdir(parents=True, exist_ok=True)

        checkpoint = {
            "scan_id": self.scan_id,
            "target": self.target,
            "target_type": self.target_type,
            "phases_completed": self.phases_completed,
            "finding_count": self.finding_counter,
            "vectors_attempted": sorted(self.score_tracker.vectors_attempted),
            "vectors_found": sorted(self.score_tracker.vectors_found),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        path.write_text(json.dumps(checkpoint, indent=2, ensure_ascii=False))
        logger.info("[CHECKPOINT] Saved to %s (%d phases, %d findings)",
                    path, len(self.phases_completed), self.finding_counter)
        return path

    @staticmethod
    def load_checkpoint(path: Path) -> dict[str, Any]:
        """체크포인트 파일에서 이전 스캔 상태 로드."""
        data = json.loads(path.read_text())
        logger.info("[CHECKPOINT] Loaded %s — %d phases completed",
                    path, len(data.get("phases_completed", [])))
        return data
