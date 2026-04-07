"""VXIS Primitives — pure tool functions with zero LLM calls.

Primitives are the "hands and eyes" exposed to the Brain (Claude Code external
or AgentBrain internal). Each function is a thin wrapper around an existing
VXIS module (interaction/knowledge/scoring/ghost/report) that performs a
single, well-defined action. Primitives NEVER reason — they execute.

Groups:
    sensing     — HTTP / browser / traffic observation primitives
    patterns    — rule-based pattern detection (regex only, no LLM)
    knowledge   — knowledge base, vectors, CVE lookups
    session     — authenticated session lifecycle
    ghost       — anonymity layer control
    chain       — algorithmic attack chain graph building
    output      — finding storage, scoring, report generation
"""

from vxis.primitives import (
    chain,
    ghost,
    knowledge,
    output,
    patterns,
    sensing,
    session,
)

__all__ = [
    "sensing",
    "patterns",
    "knowledge",
    "session",
    "ghost",
    "chain",
    "output",
]
