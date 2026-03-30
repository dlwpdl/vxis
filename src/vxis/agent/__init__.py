"""VXIS Agent — autonomous pentesting engine with Docker sandbox isolation."""

from vxis.agent.brain_filebased import FileBasedBrain
from vxis.agent.brain_interactive import InteractiveBrain
from vxis.agent.evidence import (
    EvidenceBundle,
    EvidenceCollector,
    check_security_headers,
)
from vxis.agent.executor import AgentExecutor, AgentScanResult
from vxis.agent.memory import AgentMemory, ScanMemory, format_memory_context
from vxis.agent.sandbox import DockerSandbox, SandboxManager, get_sandbox_manager

__all__ = [
    "AgentExecutor",
    "AgentScanResult",
    "FileBasedBrain",
    "InteractiveBrain",
    "AgentMemory",
    "ScanMemory",
    "format_memory_context",
    "DockerSandbox",
    "SandboxManager",
    "get_sandbox_manager",
    "EvidenceBundle",
    "EvidenceCollector",
    "check_security_headers",
]
