"""VXIS FileBasedBrain — Claude Code가 파일 프로토콜로 Brain 역할을 수행.

Protocol:
    파이프라인 → observation.json 작성 + status.json="waiting_for_brain"
    Claude Code → observation.json 읽고 → decision.json 작성
    파이프라인 → decision.json 읽고 실행 → result.json 작성
    반복...
    파이프라인 → status.json="done"

Usage:
    # 파이프라인 쪽 (백그라운드 프로세스)
    brain = FileBasedBrain(brain_dir="tools/benchmark/.brain")
    pipeline = ScanPipeline(brain=brain)
    await pipeline.run(target="http://localhost:8081")

    # Claude Code 쪽 (메인 프로세스)
    # Read(status.json) → Write(decision.json) 루프
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Any

logger = logging.getLogger(__name__)


# ── 상태 상수 ────────────────────────────────────────────────────

STATE_INITIALIZING = "initializing"
STATE_WAITING_FOR_BRAIN = "waiting_for_brain"
STATE_EXECUTING = "executing"
STATE_DONE = "done"
STATE_ERROR = "error"


# ── 원자적 파일 쓰기 ─────────────────────────────────────────────


def atomic_write(path: str, data: dict[str, Any]) -> None:
    """원자적 JSON 파일 쓰기. 읽는 쪽이 깨진 파일을 볼 일 없음.

    임시 파일에 먼저 쓴 뒤 os.replace()로 원자적 교체.
    실패 시 임시 파일을 정리하여 깨진 파일이 남지 않도록 보장.
    """
    dir_path = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_path, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
        os.replace(tmp_path, path)  # atomic on POSIX
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
