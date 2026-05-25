"""BasePlugin ABC — interface contract for all VXIS plugins."""

from __future__ import annotations

import re
import shutil
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from vxis.core.context import DAGContext, PluginOutput


@dataclass(frozen=True)
class PluginMeta:
    """Plugin metadata — declared at class definition time."""

    name: str
    version: str
    tool_binary: str
    category: str  # "recon", "scan", "vuln", "crypto", "secrets"
    tier: int = 1  # 1 = recon (zero-touch), 2 = breach (cooperative)
    depends_on: tuple[str, ...] = ()
    optional_depends: tuple[str, ...] = ()
    timeout_seconds: int = 600
    produces: tuple[str, ...] = ()


class BasePlugin(ABC):
    """All plugins must inherit from this and implement the abstract methods."""

    @property
    @abstractmethod
    def meta(self) -> PluginMeta: ...

    @abstractmethod
    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        """Build the CLI command string to execute."""
        ...

    @abstractmethod
    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        """Parse raw tool output into structured PluginOutput."""
        ...

    def validate_environment(self) -> bool:
        """Check if the tool binary is available on the system."""
        return shutil.which(self.meta.tool_binary) is not None

    def detect_version(self) -> str:
        """Detect installed tool version at runtime.

        Tries `tool --version`, `tool -v`, `tool version` and extracts
        the first version-like string (e.g. 1.2.3).
        Returns "—" if not installed or detection fails.
        """
        import re
        import subprocess

        binary = self.meta.tool_binary
        if not shutil.which(binary):
            return "—"

        for flag in ["--version", "-v", "version", "-V"]:
            try:
                result = subprocess.run(
                    [binary, flag],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                output = (result.stdout + result.stderr).strip()
                # 버전 패턴: 1.2.3, v1.2.3, 1.2.3-beta 등
                match = re.search(r"v?(\d+\.\d+[\.\d]*[-\w]*)", output)
                if match:
                    return match.group(1)
            except Exception:
                continue
        return "?"

    def get_timeout(self, scan_profile: str) -> int:
        """Get timeout adjusted for scan profile."""
        multipliers = {
            "passive": 1.0,
            "stealth": 2.0,
            "standard": 1.0,
            "aggressive": 0.5,
        }
        mult = multipliers.get(scan_profile, 1.0)
        return max(30, int(self.meta.timeout_seconds * mult))

    def validate_flags(self) -> list[str]:
        """Check that CLI flags used in build_command exist in the tool's --help output.

        Returns a list of warning strings for flags that were NOT found in --help.
        Empty list = all flags valid.
        """
        binary = shutil.which(self.meta.tool_binary)
        if binary is None:
            return [f"{self.meta.tool_binary} not installed"]

        # Get --help output
        help_text = ""
        for flag in ("--help", "-h", "-help"):
            try:
                result = subprocess.run(
                    [binary, flag],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                help_text = result.stdout + result.stderr
                if help_text.strip():
                    break
            except (subprocess.TimeoutExpired, OSError):
                continue

        if not help_text:
            return [f"Could not get help output from {self.meta.tool_binary}"]

        # Build a sample command to extract flags
        try:
            dummy_ctx = DAGContext(target="example.com", scan_profile="standard")
            cmd = self.build_command("example.com", "standard", dummy_ctx, {})
        except Exception:
            return []  # Can't build command without context — skip validation

        # Extract flags from command string (--flag, -f patterns)
        flags_in_cmd = re.findall(r"(?:^|\s)(--?[a-zA-Z][\w-]*)", cmd)

        # Check each flag against help text
        warnings = []
        # Flags that are part of the binary name or target, not actual flags
        skip = {self.meta.tool_binary, "-"}
        for flag in flags_in_cmd:
            if flag in skip:
                continue
            # Check if the flag appears in help text
            if flag not in help_text:
                warnings.append(
                    f"{self.meta.name}: flag '{flag}' not found in {self.meta.tool_binary} --help"
                )

        return warnings

    def get_tool_version(self) -> str:
        """Detect the installed tool's actual version string."""
        binary = shutil.which(self.meta.tool_binary)
        if binary is None:
            return "not installed"

        for flag in ("--version", "-version", "version", "-V"):
            try:
                result = subprocess.run(
                    [binary, flag],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                output = (result.stdout + result.stderr).strip()
                if output:
                    # Extract version-like pattern
                    match = re.search(r"(\d+\.\d+[\.\d]*)", output)
                    if match:
                        return match.group(1)
                    # Return first non-empty line if no version pattern
                    first_line = output.splitlines()[0][:50]
                    if first_line:
                        return first_line
            except (subprocess.TimeoutExpired, OSError):
                continue

        return "unknown"
