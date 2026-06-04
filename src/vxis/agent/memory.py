"""VXIS Agent Memory — 과거 스캔에서 학습하는 지식 시스템.

에이전트가 "이전에 비슷한 타겟에서 뭘 찾았는지" 기억하고,
그 경험을 바탕으로 더 효과적인 전략을 선택할 수 있게 합니다.

Storage: ~/.vxis/agent_memory.json (JSON 파일, 외부 의존성 없음)

Architecture:
    ScanMemory      — 단일 스캔의 요약 (타겟, 기술스택, 발견사항, 도구 효과)
    AgentMemory     — 영구 저장소 + 쿼리 인터페이스
    format_memory_context() — LLM 프롬프트용 텍스트 포맷터
"""

from __future__ import annotations

import json
import logging
import os
import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Default storage path ─────────────────────────────────────────

_DEFAULT_DB_PATH = "~/.vxis/agent_memory.json"

# 저장 가능한 최대 메모리 항목 수 (파일 비대화 방지)
_MAX_MEMORIES = 500


# ── Data model ──────────────────────────────────────────────────

@dataclass
class ScanMemory:
    """단일 스캔 세션에서 추출한 기억 단위.

    Args:
        target: 스캔한 타겟 (도메인 또는 IP).
        tech_stack: 탐지된 기술 스택 목록 (e.g. ["Next.js", "Vercel", "nginx"]).
        findings_summary: 발견 취약점 요약 목록.
            각 항목: {"severity": str, "type": str, "title": str}
        effective_tools: 실제로 발견을 낸 도구 이름 목록.
        ineffective_tools: 아무것도 찾지 못한 도구 이름 목록.
        scan_date: ISO 8601 형식의 스캔 날짜/시각.
        total_findings: 발견된 전체 취약점 수.
    """

    target: str
    tech_stack: list[str] = field(default_factory=list)
    findings_summary: list[dict[str, str]] = field(default_factory=list)
    effective_tools: list[str] = field(default_factory=list)
    ineffective_tools: list[str] = field(default_factory=list)
    scan_date: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    total_findings: int = 0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanMemory":
        """딕셔너리에서 ScanMemory 인스턴스를 복원한다."""
        return cls(
            target=data.get("target", ""),
            tech_stack=data.get("tech_stack", []),
            findings_summary=data.get("findings_summary", []),
            effective_tools=data.get("effective_tools", []),
            ineffective_tools=data.get("ineffective_tools", []),
            scan_date=data.get("scan_date", ""),
            total_findings=data.get("total_findings", 0),
        )


# ── Main memory class ────────────────────────────────────────────

class AgentMemory:
    """에이전트의 영구 기억 저장소.

    JSON 파일 기반 저장소로, 외부 데이터베이스 없이 동작합니다.
    스캔 기록을 저장하고, 유사한 타겟/기술스택에 대한 과거 경험을
    조회하여 LLM 에이전트에게 컨텍스트를 제공합니다.

    Thread-safety: 단일 프로세스 내에서 순차 접근을 가정합니다.
    동시 다중 에이전트 환경에서는 파일 잠금이 필요합니다.
    """

    def __init__(self, db_path: str = _DEFAULT_DB_PATH) -> None:
        self._path = Path(os.path.expanduser(db_path)).resolve()
        self._memories: list[ScanMemory] = []
        self._load()

    # ── Public API ───────────────────────────────────────────────

    def remember_scan(self, memory: ScanMemory) -> None:
        """스캔 결과를 메모리에 저장한다.

        Args:
            memory: 저장할 ScanMemory 인스턴스.

        동일 타겟에 대한 기록이 이미 있어도 추가 저장합니다.
        (시간별 변화를 추적하기 위함)
        총 항목 수가 _MAX_MEMORIES를 초과하면 가장 오래된 항목을 제거합니다.
        """
        self._memories.append(memory)

        # 최대 크기 초과 시 오래된 항목 제거 (FIFO)
        if len(self._memories) > _MAX_MEMORIES:
            removed = len(self._memories) - _MAX_MEMORIES
            self._memories = self._memories[removed:]
            logger.debug("메모리 정리: %d개 오래된 항목 제거", removed)

        self._save()
        logger.info(
            "스캔 기억 저장: %s (%d건 발견, 총 %d개 기억)",
            memory.target,
            memory.total_findings,
            len(self._memories),
        )

    def recall_similar(
        self,
        target: str,
        tech_stack: list[str] | None = None,
    ) -> list[ScanMemory]:
        """과거 스캔 중 유사한 특성을 가진 기록을 반환한다.

        유사성 판단 기준 (우선순위 순):
        1. 동일 루트 도메인 (e.g. "api.example.com" == "example.com")
        2. 기술 스택 겹침 (1개 이상 공통 기술)
        3. 그 외: 제외

        Args:
            target: 조회 기준 타겟 (도메인 또는 IP).
            tech_stack: 조회 기준 기술 스택. None이면 도메인 매칭만 사용.

        Returns:
            관련도 높은 순으로 정렬된 ScanMemory 목록 (최대 10개).
        """
        if not self._memories:
            return []

        root_domain = _extract_root_domain(target)
        query_tech = {t.lower() for t in (tech_stack or [])}

        scored: list[tuple[int, ScanMemory]] = []

        for mem in self._memories:
            score = 0

            # 동일 루트 도메인
            if root_domain and _extract_root_domain(mem.target) == root_domain:
                score += 10

            # 기술 스택 겹침
            if query_tech:
                mem_tech = {t.lower() for t in mem.tech_stack}
                overlap = len(query_tech & mem_tech)
                score += overlap * 3

            if score > 0:
                scored.append((score, mem))

        # 점수 내림차순, 동점 시 최신 스캔 우선
        scored.sort(key=lambda x: (x[0], x[1].scan_date), reverse=True)

        return [mem for _, mem in scored[:10]]

    def get_effective_strategy(self, tech_stack: list[str]) -> dict[str, Any]:
        """유사 기술 스택에서의 과거 경험을 바탕으로 도구 우선순위를 추천한다.

        Args:
            tech_stack: 현재 타겟의 기술 스택.

        Returns:
            추천 전략 딕셔너리:
            {
                "prioritize": list[str],   — 우선 실행 도구 (효과 높음)
                "deprioritize": list[str], — 후순위 도구 (효과 낮음)
                "skip": list[str],         — 건너뛸 도구 (거의 효과 없음)
                "sample_size": int,        — 분석에 사용된 과거 스캔 수
                "confidence": str,         — "high" / "medium" / "low"
            }
        """
        relevant = self.recall_similar(target="", tech_stack=tech_stack)

        if not relevant:
            return {
                "prioritize": [],
                "deprioritize": [],
                "skip": [],
                "sample_size": 0,
                "confidence": "low",
            }

        # 도구별 효과 카운트
        effective_counts: dict[str, int] = defaultdict(int)
        ineffective_counts: dict[str, int] = defaultdict(int)

        for mem in relevant:
            for tool in mem.effective_tools:
                effective_counts[tool] += 1
            for tool in mem.ineffective_tools:
                ineffective_counts[tool] += 1

        n = len(relevant)
        prioritize: list[str] = []
        deprioritize: list[str] = []
        skip: list[str] = []

        all_tools = set(effective_counts) | set(ineffective_counts)
        for tool in all_tools:
            eff = effective_counts[tool]
            ineff = ineffective_counts[tool]
            total = eff + ineff
            if total == 0:
                continue

            hit_rate = eff / total

            if hit_rate >= 0.6:
                prioritize.append(tool)
            elif hit_rate <= 0.15 and ineff >= 3:
                # 3회 이상 시도에서 15% 미만 성공 → 거의 효과 없음
                skip.append(tool)
            else:
                deprioritize.append(tool)

        # 효과 높은 순으로 정렬
        prioritize.sort(key=lambda t: effective_counts[t], reverse=True)
        skip.sort(key=lambda t: ineffective_counts[t], reverse=True)

        confidence = "high" if n >= 5 else ("medium" if n >= 2 else "low")

        return {
            "prioritize": prioritize,
            "deprioritize": deprioritize,
            "skip": skip,
            "sample_size": n,
            "confidence": confidence,
        }

    def get_stats(self) -> dict[str, Any]:
        """전체 메모리 통계를 반환한다.

        Returns:
            {
                "total_scans": int,
                "unique_targets": int,
                "total_findings": int,
                "most_effective_tools": list[str],  — 발견율 상위 5개 도구
                "most_common_findings": list[str],  — 가장 자주 발견된 취약점 유형
                "avg_findings_per_scan": float,
                "tech_stack_frequency": dict[str, int],  — 기술별 등장 횟수
            }
        """
        if not self._memories:
            return {
                "total_scans": 0,
                "unique_targets": 0,
                "total_findings": 0,
                "most_effective_tools": [],
                "most_common_findings": [],
                "avg_findings_per_scan": 0.0,
                "tech_stack_frequency": {},
            }

        unique_targets = len({_extract_root_domain(m.target) for m in self._memories})
        total_findings = sum(m.total_findings for m in self._memories)

        # 도구별 누적 효과 집계
        tool_effective: dict[str, int] = defaultdict(int)
        for mem in self._memories:
            for tool in mem.effective_tools:
                tool_effective[tool] += 1

        top_tools = sorted(tool_effective, key=tool_effective.get, reverse=True)[:5]  # type: ignore[arg-type]

        # 취약점 유형 빈도
        finding_types: dict[str, int] = defaultdict(int)
        for mem in self._memories:
            for finding in mem.findings_summary:
                ftype = finding.get("type", finding.get("title", "unknown"))
                finding_types[ftype] += 1

        top_findings = sorted(finding_types, key=finding_types.get, reverse=True)[:10]  # type: ignore[arg-type]

        # 기술 스택 빈도
        tech_freq: dict[str, int] = defaultdict(int)
        for mem in self._memories:
            for tech in mem.tech_stack:
                tech_freq[tech] += 1

        return {
            "total_scans": len(self._memories),
            "unique_targets": unique_targets,
            "total_findings": total_findings,
            "most_effective_tools": top_tools,
            "most_common_findings": top_findings,
            "avg_findings_per_scan": (
                round(total_findings / len(self._memories), 2)
                if self._memories
                else 0.0
            ),
            "tech_stack_frequency": dict(
                sorted(tech_freq.items(), key=lambda x: x[1], reverse=True)
            ),
        }

    # ── Persistence ──────────────────────────────────────────────

    def _load(self) -> None:
        """JSON 파일에서 메모리를 불러온다. 파일이 없으면 빈 상태로 시작."""
        if not self._path.exists():
            logger.debug("메모리 파일 없음, 새로 시작: %s", self._path)
            return

        try:
            raw = self._path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if not isinstance(data, list):
                logger.warning("메모리 파일 형식 오류, 무시하고 새로 시작")
                return
            self._memories = [ScanMemory.from_dict(item) for item in data]
            logger.debug("메모리 로드: %d개 항목 (%s)", len(self._memories), self._path)
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("메모리 파일 로드 실패: %s — 새로 시작", exc)
            self._memories = []

    def _save(self) -> None:
        """현재 메모리를 JSON 파일에 저장한다."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps(
                [asdict(m) for m in self._memories],
                ensure_ascii=False,
                indent=2,
            )
            self._path.write_text(payload, encoding="utf-8")
        except OSError as exc:
            logger.error("메모리 파일 저장 실패: %s", exc)


# ── Formatter ────────────────────────────────────────────────────

def format_memory_context(memories: list[ScanMemory]) -> str:
    """과거 스캔 기억을 LLM 프롬프트용 텍스트로 포맷한다.

    이 텍스트는 에이전트의 observation prompt에 삽입되어, LLM이
    과거 경험을 참조하여 더 나은 도구 선택을 할 수 있게 합니다.

    Args:
        memories: recall_similar()가 반환한 관련 스캔 기억 목록.

    Returns:
        포맷된 마크다운 문자열. memories가 비어 있으면 빈 문자열 반환.

    Example output:
        ## 과거 스캔 경험

        비슷한 타겟 (Next.js, Vercel) 스캔 3회:
        - nuclei: 평균 2.0건 발견 (XSS, 설정오류)
        - testssl: 평균 1.0건 발견 (TLS 설정)
        - nmap: 주로 발견 없음
        → 추천: nuclei, testssl 우선 실행 / nmap은 top-100으로 빠르게
    """
    if not memories:
        return ""

    lines: list[str] = ["## 과거 스캔 경험\n"]

    # 대표 기술 스택 수집 (등장 빈도 상위 4개)
    tech_freq: dict[str, int] = defaultdict(int)
    for mem in memories:
        for tech in mem.tech_stack:
            tech_freq[tech] += 1
    top_tech = sorted(tech_freq, key=tech_freq.get, reverse=True)[:4]  # type: ignore[arg-type]
    tech_label = ", ".join(top_tech) if top_tech else "유사 환경"

    lines.append(f"비슷한 타겟 ({tech_label}) 스캔 {len(memories)}회:\n")

    # 도구별 평균 발견 수 및 대표 발견 유형 집계
    tool_finds: dict[str, list[int]] = defaultdict(list)  # tool → [finding counts]
    tool_examples: dict[str, list[str]] = defaultdict(list)  # tool → [finding titles]

    for mem in memories:
        # 효과적이었던 도구의 발견 수 추산
        # (상세 per-tool count가 없으므로 findings_summary의 type을 도구별로 연결)
        for tool in mem.effective_tools:
            # 대략적인 기여 발견 수: total / effective_tool_count
            if mem.effective_tools:
                approx = max(1, round(mem.total_findings / len(mem.effective_tools)))
            else:
                approx = 0
            tool_finds[tool].append(approx)

        for tool in mem.ineffective_tools:
            tool_finds[tool].append(0)

        # 발견 유형 샘플 (최대 3개)
        for finding in mem.findings_summary[:3]:
            ftype = finding.get("type") or finding.get("title", "")
            if ftype:
                # 발견을 낸 도구들에게 해당 유형 연결
                for tool in mem.effective_tools[:2]:
                    if ftype not in tool_examples[tool]:
                        tool_examples[tool].append(ftype)

    # 발견율 기준으로 도구 분류
    effective_tools: list[str] = []
    weak_tools: list[str] = []

    for tool, counts in sorted(tool_finds.items()):
        avg = sum(counts) / len(counts) if counts else 0
        if avg >= 0.5:
            effective_tools.append(tool)
        else:
            weak_tools.append(tool)

    # 효과적인 도구 출력
    for tool in effective_tools:
        counts = tool_finds[tool]
        avg = round(sum(counts) / len(counts), 1)
        examples = tool_examples.get(tool, [])[:2]
        example_str = f" ({', '.join(examples)})" if examples else ""
        lines.append(f"- {tool}: 평균 {avg}건 발견{example_str}")

    # 효과 낮은 도구 출력
    for tool in weak_tools:
        lines.append(f"- {tool}: 주로 발견 없음")

    # 추천 전략 요약
    if effective_tools or weak_tools:
        lines.append("")
        recommend_parts: list[str] = []
        if effective_tools:
            recommend_parts.append(f"{', '.join(effective_tools[:3])} 우선 실행")
        if weak_tools:
            skip_hint = weak_tools[0]
            recommend_parts.append(f"{skip_hint}은 top-100으로 빠르게")
        lines.append("→ 추천: " + " / ".join(recommend_parts))

    return "\n".join(lines)


def dual_write_scan(memory: AgentMemory, scan: ScanMemory) -> None:
    """Write legacy AgentMemory and optionally shadow the same summary into PTI.

    VXIS_V3_MEMORY defaults off, so the legacy path remains a real rollback.
    ScanMemory stores finding summaries only; raw PoC bodies and secrets are
    not part of this dual-write contract.
    """
    memory.remember_scan(scan)
    if os.environ.get("VXIS_V3_MEMORY", "0") in {"", "0", "false", "False", "no", "off"}:
        return
    try:
        from vxis.pti.memory_bridge import persist_scan_memory_to_pti

        persist_scan_memory_to_pti(scan, scan_id=_scan_memory_id(scan))
    except Exception as exc:  # noqa: BLE001 - rollback path must never fail on PTI
        logger.warning("PTI memory shadow write failed; legacy memory kept: %s", exc)


# ── Helpers ──────────────────────────────────────────────────────

def _scan_memory_id(scan: ScanMemory) -> str:
    raw = f"legacy-{scan.scan_date}-{scan.target}"
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip(".-")[:120] or "legacy-import"


def _extract_root_domain(target: str) -> str:
    """타겟에서 루트 도메인을 추출한다.

    Examples:
        "api.example.com"  → "example.com"
        "https://example.com/path" → "example.com"
        "192.168.1.1"      → "192.168.1.1"  (IP는 그대로)

    Args:
        target: 도메인 또는 IP 문자열.

    Returns:
        루트 도메인 문자열. 추출 불가 시 원본 반환.
    """
    if not target:
        return ""

    # URL 스킴 제거
    cleaned = re.sub(r"^https?://", "", target.strip())
    # 경로/쿼리 제거
    cleaned = cleaned.split("/")[0].split("?")[0].split("#")[0]
    # 포트 제거
    cleaned = cleaned.split(":")[0]

    # IP 주소 패턴이면 그대로 반환
    ip_pattern = re.compile(
        r"^(\d{1,3}\.){3}\d{1,3}$"
    )
    if ip_pattern.match(cleaned):
        return cleaned

    # 서브도메인 제거 → 루트 도메인 추출
    parts = cleaned.lower().split(".")
    if len(parts) >= 2:
        # known multi-part TLD 처리 (co.kr, co.uk 등)
        if len(parts) >= 3 and parts[-2] in {"co", "com", "net", "org", "gov", "ac"}:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])

    return cleaned
