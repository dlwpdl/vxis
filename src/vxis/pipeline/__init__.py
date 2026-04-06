"""VXIS ScanPipeline — Brain-First 통합 오케스트레이터.

하나의 파이프라인, Brain만 갈아끼움.
모든 Phase를 순서대로 실행하며, 데이터 변조는 마지막에 승인 후 실행.
GH Actions 담당 Phase(CVE Watch, Forecast, Industry Intel)는 파이프라인 외부.

Usage:
    # LLM API Brain
    pipeline = ScanPipeline(brain=AgentBrain(), config=VXISConfig())
    result = await pipeline.run("https://target.com")

    # Claude Code Brain
    pipeline = ScanPipeline(brain=InteractiveBrain(), config=VXISConfig())
    result = await pipeline.run("https://target.com")

    # CLI
    vxis scan https://target.com --brain=auto
    vxis scan https://target.com --brain=claude-code
"""

from vxis.pipeline.context import ScanContext, DeferredAction
from vxis.pipeline.pipeline import ScanPipeline

__all__ = ["ScanPipeline", "ScanContext", "DeferredAction"]
