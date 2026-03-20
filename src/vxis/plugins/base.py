"""BasePlugin ABC — interface contract for all VXIS plugins."""

from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
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
    def meta(self) -> PluginMeta:
        ...

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
