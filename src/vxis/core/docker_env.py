"""Single source for Docker environment probes.

CLI presence, daemon readiness, and sandbox-image availability used to be
duplicated across ``cli/preflight.py`` and the agent sandbox tooling (three
near-copies with subtly different semantics). This module is the one place each
check lives. Only stdlib deps so it stays cheap to import anywhere.
"""

from __future__ import annotations

import shutil
import subprocess

# The purpose-built scanner sandbox image (built from ``docker/sandbox/``).
DEFAULT_SANDBOX_IMAGE = "vxis/sandbox:latest"


def docker_cli_present() -> bool:
    """True if the ``docker`` CLI is on PATH. Does NOT check the daemon."""
    return shutil.which("docker") is not None


def docker_daemon_ready(timeout: float = 3.0) -> bool:
    """True if the Docker daemon answers ``docker info`` within ``timeout``."""
    if not docker_cli_present():
        return False
    try:
        return (
            subprocess.run(["docker", "info"], capture_output=True, timeout=timeout).returncode == 0
        )
    except Exception:
        return False


def sandbox_image_present(image: str = DEFAULT_SANDBOX_IMAGE, timeout: float = 5.0) -> bool:
    """True if the sandbox image is already built/pulled locally.

    Fast (a metadata lookup, no container start) and returns False rather than
    raising when the CLI/daemon is unavailable.
    """
    if not docker_cli_present():
        return False
    try:
        return (
            subprocess.run(
                ["docker", "image", "inspect", image], capture_output=True, timeout=timeout
            ).returncode
            == 0
        )
    except Exception:
        return False


__all__ = [
    "DEFAULT_SANDBOX_IMAGE",
    "docker_cli_present",
    "docker_daemon_ready",
    "sandbox_image_present",
]
