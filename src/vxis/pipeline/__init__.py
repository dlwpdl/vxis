"""VXIS ScanPipeline — Brain-First 단일 루프 오케스트레이터.

Phase A (2026-04): Strix-parity single-loop migration.
ScanPipeline is now a thin shim over ScanAgentLoop. The Brain owns the entire
scan end-to-end via AgentBrain.think_in_loop + the 11-tool ToolRegistry.

Usage:
    from vxis.pipeline import ScanPipeline
    from vxis.agent.brain import AgentBrain
    pipeline = ScanPipeline(brain=AgentBrain())
    ctx = await pipeline.run("https://target.com")

CLI:
    vxis scan https://target.com --profile standard
"""

from vxis.pipeline.context import ScanContext, DeferredAction
from vxis.pipeline.scan_pipeline_v2 import ScanPipeline

__all__ = ["ScanPipeline", "ScanContext", "DeferredAction"]
