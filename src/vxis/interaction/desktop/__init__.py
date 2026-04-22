"""Desktop surface namespace — phase-I (macOS) lands first.

Windows-specific impls (DesktopHands/WinDivertCapture/ETWConsumer) wait for
phase-C/D/E once the SCFW-blocked Windows deps (pywin32/frida/pydivert/etw)
get user pre-approval. Linux is explicitly out-of-scope per the universal
pentesting plan and raises phase-linux-impl-pending in the factory.

macOS adapter wraps native CLI tools (otool/codesign/dtrace) — no third-party
binary deps — so it works on any macOS host without extra installs.
"""
from vxis.interaction.desktop.dtrace_xray import MacOSXRay
from vxis.interaction.desktop.macos_hands import MacOSHands
from vxis.interaction.desktop.recon_macho import MacOSRecon

__all__ = ["MacOSHands", "MacOSRecon", "MacOSXRay"]
