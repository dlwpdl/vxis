#!/usr/bin/env python3
"""Phase/architecture sync check.

Legacy VXIS used ``pipeline.py`` with hardcoded ``_run_phase`` calls. Current
VXIS uses ``scan_pipeline_v2.py`` as a thin shim over ``ScanAgentLoop``. This
script supports both layouts so CI catches stale docs without failing just
because the legacy pipeline has been removed.

Usage:
    python scripts/check_phase_sync.py

Exit codes:
    0 = 동기화 완료
    1 = 불일치 발견
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIPELINE_PY = ROOT / "src" / "vxis" / "pipeline" / "pipeline.py"
PIPELINE_V2_PY = ROOT / "src" / "vxis" / "pipeline" / "scan_pipeline_v2.py"
CLAUDE_MD = ROOT / "CLAUDE.md"
ARCHITECTURE_MD = ROOT / "ARCHITECTURE.md"


def extract_pipeline_phases() -> list[str]:
    """pipeline.py에서 실제 _run_phase 호출을 추출."""
    code = PIPELINE_PY.read_text(encoding="utf-8")

    # run() 메서드 내의 _run_phase 호출만 추출 (메서드 정의 아님)
    # 패턴: await self._run_phase("Phase N: ...", self._phaseN_xxx, ctx)
    pattern = re.compile(r'await self\._run_phase\("(Phase \d+:[^"]+)"')
    phases = pattern.findall(code)

    # run() 메서드 범위만 필터 (async def run 이후, async def _run_phase 이전)
    run_start = code.find("async def run(")
    run_phase_def = code.find("async def _run_phase(")
    if run_start >= 0 and run_phase_def > run_start:
        run_body = code[run_start:run_phase_def]
        phases = re.compile(r'await self\._run_phase\("(Phase \d+:[^"]+)"').findall(run_body)

    return phases


def extract_claude_md_phases() -> list[str]:
    """CLAUDE.md에서 Phase 목록 추출."""
    if not CLAUDE_MD.exists():
        return []

    text = CLAUDE_MD.read_text(encoding="utf-8")

    # "## 파이프라인 Phase 구조" 섹션에서 P번호 추출
    section_match = re.search(r"## 파이프라인 Phase 구조.*?```(.*?)```", text, re.DOTALL)
    if not section_match:
        return []

    block = section_match.group(1)
    # P0, P1, P4, ... 형태 추출
    p_numbers = re.findall(r"P(\d+)", block)
    return sorted(set(p_numbers), key=int)


def extract_pipeline_phase_numbers(phases: list[str]) -> list[str]:
    """Phase 문자열에서 번호만 추출."""
    numbers = []
    for p in phases:
        m = re.match(r"Phase (\d+):", p)
        if m:
            numbers.append(m.group(1))
    return sorted(set(numbers), key=int)


def main() -> int:
    if not PIPELINE_PY.exists():
        return check_single_loop_architecture()

    errors: list[str] = []

    # 1. pipeline.py에서 실제 Phase 추출
    pipeline_phases = extract_pipeline_phases()
    if not pipeline_phases:
        errors.append("pipeline.py에서 _run_phase 호출을 찾을 수 없음")
        for e in errors:
            print(f"❌ {e}", file=sys.stderr)
        return 1

    pipeline_numbers = extract_pipeline_phase_numbers(pipeline_phases)
    print(f"📋 pipeline.py: {len(pipeline_phases)} phases → {pipeline_numbers}")

    # 2. CLAUDE.md와 비교
    claude_numbers = extract_claude_md_phases()
    if claude_numbers:
        print(f"📋 CLAUDE.md:    {len(claude_numbers)} phases → {claude_numbers}")
        if set(pipeline_numbers) != set(claude_numbers):
            only_pipeline = set(pipeline_numbers) - set(claude_numbers)
            only_claude = set(claude_numbers) - set(pipeline_numbers)
            if only_pipeline:
                errors.append(
                    f"pipeline.py에만 있는 Phase: P{', P'.join(sorted(only_pipeline, key=int))}"
                )
            if only_claude:
                errors.append(
                    f"CLAUDE.md에만 있는 Phase: P{', P'.join(sorted(only_claude, key=int))}"
                )
    else:
        errors.append("CLAUDE.md에서 Phase 목록을 찾을 수 없음")

    # 3. docstring의 phase count 검증
    code = PIPELINE_PY.read_text(encoding="utf-8")
    count_match = re.search(r"(\d+) active phases", code)
    if count_match:
        doc_count = int(count_match.group(1))
        actual_count = len(pipeline_phases)
        if doc_count != actual_count:
            errors.append(
                f"docstring phase count 불일치: "
                f"'{doc_count} active phases' vs 실제 {actual_count}개"
            )
        else:
            print(f"✅ docstring phase count: {doc_count} == 실제 {actual_count}")

    # 4. CLAUDE.md의 "(N active)" 검증
    claude_text = CLAUDE_MD.read_text(encoding="utf-8") if CLAUDE_MD.exists() else ""
    claude_count_match = re.search(r"\((\d+) active\)", claude_text)
    if claude_count_match:
        claude_count = int(claude_count_match.group(1))
        actual_count = len(pipeline_phases)
        if claude_count != actual_count:
            errors.append(
                f"CLAUDE.md phase count 불일치: '({claude_count} active)' vs 실제 {actual_count}개"
            )
        else:
            print(f"✅ CLAUDE.md phase count: {claude_count} == 실제 {actual_count}")

    # 결과
    if errors:
        print(f"\n❌ {len(errors)}개 불일치 발견:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        print("\n💡 pipeline.py 수정 후 CLAUDE.md도 함께 업데이트하세요.", file=sys.stderr)
        return 1

    print("\n✅ Phase 동기화 확인 완료 — pipeline.py ↔ CLAUDE.md 일치")
    return 0


def check_single_loop_architecture() -> int:
    """Validate the post-Phase-A Brain-first architecture contract."""
    errors: list[str] = []

    if not PIPELINE_V2_PY.exists():
        errors.append(f"scan_pipeline_v2.py missing: {PIPELINE_V2_PY}")
    else:
        code = PIPELINE_V2_PY.read_text(encoding="utf-8")
        required_terms = [
            "ScanAgentLoop",
            "build_default_registry",
            "_get_findings",
            "_get_chains",
            "ReportGenerator",
            "brain_decision_count",
        ]
        missing = [term for term in required_terms if term not in code]
        if missing:
            errors.append(f"scan_pipeline_v2.py missing contract term(s): {', '.join(missing)}")

    if not ARCHITECTURE_MD.exists():
        errors.append("ARCHITECTURE.md missing")
    else:
        arch = ARCHITECTURE_MD.read_text(encoding="utf-8")
        required_docs = [
            "Brain-First Single-Loop",
            "ScanPipeline (v2)",
            "ScanAgentLoop",
            "AgentBrain",
            "1 tool per message",
        ]
        missing_docs = [term for term in required_docs if term not in arch]
        if missing_docs:
            errors.append(f"ARCHITECTURE.md missing contract term(s): {', '.join(missing_docs)}")

    if errors:
        print(f"\n❌ {len(errors)}개 architecture sync issue(s):", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1

    print("✅ Brain-first v2 architecture sync 확인 완료")
    return 0


if __name__ == "__main__":
    sys.exit(main())
