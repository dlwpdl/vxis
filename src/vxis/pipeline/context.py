"""ScanContext — Phase 간 공유 상태 + Deferred Action Queue."""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from vxis.agent.policy.scan_policy import ScanPolicy

from vxis.interaction.surface import TargetKind
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
    kind: TargetKind = TargetKind.WEB  # web | desktop | mobile | game
    app_context_en: str = ""
    app_context_ko: str = ""
    scan_id: str = ""
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # ── Component P: resolved scan policy (None = fail-closed at chokepoints) ──
    policy: "ScanPolicy | None" = None

    # ── Capability Scoring ──
    score_tracker: ScoreTracker = field(init=False)

    # ── 수집된 정보 ──
    tech_stack: list[str] = field(default_factory=list)
    subdomains: list[dict[str, Any]] = field(default_factory=list)
    api_endpoints: list[dict[str, Any]] = field(default_factory=list)
    js_bundles: list[str] = field(default_factory=list)
    tls_info: dict[str, Any] = field(default_factory=dict)
    target_profile: dict[str, Any] = field(default_factory=dict)

    # ── Threat Model (STRIDE) ──
    threat_model: dict[str, Any] = field(default_factory=dict)

    # ── Attack Graph ──
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    attack_chains: list[dict[str, Any]] = field(default_factory=list)

    # ── CVE ──
    matched_cves: list[dict[str, Any]] = field(default_factory=list)

    # ── Findings ──
    findings: list[Finding] = field(default_factory=list)
    finding_counter: int = 0

    # ── Ghost Mode ──
    ghost_active: bool = False
    ghost_verified_ip: str | None = None  # 실제 노출 IP (None = 검증 안됨)

    # ── Deferred Actions (데이터 변조 대기열) ──
    deferred_actions: list[DeferredAction] = field(default_factory=list)
    _deferred_counter: int = 0

    # ── Phase 실행 추적 ──
    phases_completed: list[str] = field(default_factory=list)
    phase_logs: list[dict[str, Any]] = field(default_factory=list)

    # ── Screenshots (Phase 4 Eyes) ──
    screenshots: dict[str, str] = field(default_factory=dict)

    # ── X-Ray 플로우 ──
    xray_flows: int = 0
    xray_vulns: list[dict[str, Any]] = field(default_factory=list)

    # ── Chain recursion budget (LLM 호출 폭증 방지) ──
    _chain_llm_count: int = 0

    # ── Benchmark instrumentation: peak in-memory state size ──
    # Sampled at phase boundaries via update_peak_size(). Used by Task 14
    # to compare old-pipeline context growth vs new ScanAgentLoop.
    peak_context_bytes: int = 0

    def __post_init__(self) -> None:
        """ScoreTracker를 kind에 맞게 초기화한다."""
        object.__setattr__(self, "score_tracker", ScoreTracker(target_type=self.kind.value))
        object.__setattr__(self, "_lock", threading.Lock())

    @property
    def target_type(self) -> str:
        """Backward-compat shim — legacy callers expected `target_type: str`.

        Surface ABC migration replaced the bare string with `kind: TargetKind`.
        Existing `ctx.target_type` reads still resolve to the kind's string value,
        so ScoreTracker / to_dict / report headers stay source-compatible.
        """
        return self.kind.value

    # findings 무제한 증가 방지 — 메모리 상한
    MAX_FINDINGS: int = 500
    MAX_ATTACK_CHAINS: int = 100

    def add_finding(self, **kwargs: Any) -> Finding:
        """Finding 추가 (메모리 상한 적용)."""
        from vxis.models.finding import Finding as F

        with self._lock:
            self.finding_counter += 1
            kwargs.setdefault("id", f"VXIS-{self.finding_counter:03d}")
            kwargs.setdefault("scan_id", self.scan_id)
            kwargs.setdefault("source_plugin", "vxis-pipeline")
            f = F(**kwargs)
            self.findings.append(f)

            # 메모리 상한 초과 → 오래된 informational/low부터 제거
            if len(self.findings) > self.MAX_FINDINGS:
                from vxis.models.finding import Severity

                # informational 우선 제거, 그 다음 low, 그 다음 오래된 순
                removable_idx = [
                    i
                    for i, fnd in enumerate(self.findings)
                    if fnd.severity == Severity.informational
                ] or [i for i, fnd in enumerate(self.findings) if fnd.severity == Severity.low]
                if removable_idx:
                    del self.findings[removable_idx[0]]
                else:
                    # 오래된 것 제거 (첫 번째)
                    del self.findings[0]
                logger.debug(
                    "[MEMORY] findings cap hit (%d), evicted old finding", self.MAX_FINDINGS
                )
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

    def log_phase(
        self, phase_name: str, duration_ms: float = 0, findings_count: int = 0, notes: str = ""
    ) -> None:
        """Phase 실행 기록."""
        with self._lock:
            self.phases_completed.append(phase_name)
            self.phase_logs.append(
                {
                    "phase": phase_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "duration_ms": duration_ms,
                    "findings_count": findings_count,
                    "notes": notes,
                }
            )
            logger.info("[PHASE DONE] %s — %d findings, %s", phase_name, findings_count, notes[:80])

    def update_peak_size(self) -> int:
        """Sample the current in-memory state size and update peak_context_bytes.

        Called at phase boundaries (not in hot loops) so Task 14 can compare
        benchmark runs apples-to-apples. Uses json.dumps(default=str) length as
        a simple, deterministic byte-size proxy across runs.
        Returns the current size.
        """
        snapshot = {
            "tech_stack": self.tech_stack,
            "subdomains": self.subdomains,
            "api_endpoints": self.api_endpoints,
            "js_bundles": self.js_bundles,
            "tls_info": self.tls_info,
            "target_profile": self.target_profile,
            "threat_model": self.threat_model,
            "hypotheses": self.hypotheses,
            "attack_chains": self.attack_chains,
            "matched_cves": self.matched_cves,
            "findings_count": len(self.findings),
            "xray_vulns": self.xray_vulns,
            "phase_logs": self.phase_logs,
            "screenshots_keys": list(self.screenshots.keys()),
        }
        try:
            current = len(json.dumps(snapshot, default=str, ensure_ascii=False))
        except Exception:
            current = 0
        if current > self.peak_context_bytes:
            self.peak_context_bytes = current
        return current

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
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(checkpoint, indent=2, ensure_ascii=False))
        os.replace(tmp, path)
        logger.info(
            "[CHECKPOINT] Saved to %s (%d phases, %d findings)",
            path,
            len(self.phases_completed),
            self.finding_counter,
        )
        return path

    @staticmethod
    def load_checkpoint(path: Path) -> dict[str, Any]:
        """체크포인트 파일에서 이전 스캔 상태 로드."""
        data = json.loads(path.read_text())
        logger.info(
            "[CHECKPOINT] Loaded %s — %d phases completed",
            path,
            len(data.get("phases_completed", [])),
        )
        return data
