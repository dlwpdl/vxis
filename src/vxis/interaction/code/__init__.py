"""Code surface — static-analysis hypothesis generator.

This surface is a read-only reconnaissance layer. It NEVER calls
report_finding. All output is fed as unverified Hypothesis objects
into the P3 Hypothesis queue; a dynamic surface (web/desktop) must
confirm or refute each hypothesis before it can influence the score.

The four roles:
    CodeHands  — file I/O: read / grep / glob
    CodeEyes   — Python AST walk: imports / functions / classes / calls
    CodeXRay   — git history: log / blame / diff
    CodeRecon  — manifest / Dockerfile / OpenAPI / .env.example detection
"""

from vxis.interaction.code.code_hands import CodeHands
from vxis.interaction.code.code_eyes import CodeEyes
from vxis.interaction.code.code_xray import CodeXRay
from vxis.interaction.code.code_recon import CodeRecon

__all__ = ["CodeHands", "CodeEyes", "CodeXRay", "CodeRecon"]
