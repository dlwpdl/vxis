"""DAGContext — typed data flow between plugins in the scan DAG."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PluginOutput:
    """Standardized output from a plugin execution."""

    plugin_name: str
    raw_output: str = ""
    raw_output_path: str | None = None
    parsed_data: dict[str, Any] = field(default_factory=dict)
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_data(self) -> bool:
        return bool(self.parsed_data) or bool(self.findings)


@dataclass
class DAGContext:
    """
    Carries typed results between DAG nodes.

    Each plugin writes its output here after execution.
    Downstream plugins read upstream results via get().
    """

    _results: dict[str, PluginOutput] = field(default_factory=dict)
    target: str = ""
    scan_profile: str = "standard"

    def set(self, plugin_name: str, output: PluginOutput) -> None:
        self._results[plugin_name] = output

    def get(self, plugin_name: str) -> PluginOutput | None:
        return self._results.get(plugin_name)

    def has(self, plugin_name: str) -> bool:
        return plugin_name in self._results

    def get_data(self, plugin_name: str, key: str, default: Any = None) -> Any:
        """Convenience: get a specific data key from a plugin's parsed_data."""
        output = self._results.get(plugin_name)
        if output is None:
            return default
        return output.parsed_data.get(key, default)

    def all_results(self) -> dict[str, PluginOutput]:
        return dict(self._results)
