"""Confused plugin — dependency confusion vulnerability detection."""

from __future__ import annotations

from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# Default package manifest files to check if none specified in tool_config
_DEFAULT_PACKAGE_FILES: tuple[str, ...] = (
    "package.json",
    "requirements.txt",
    "Gemfile",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "composer.json",
)


class ConfusedPlugin(BasePlugin):
    """Detect dependency confusion vulnerabilities using the 'confused' tool.

    Dependency confusion (also called namespace confusion) is a supply chain
    attack where a public package registry hosts a package with the same name
    as an internal/private package. If a build system resolves the public
    package first, it may install malicious code.
    """

    _meta = PluginMeta(
        name="confused",
        version="1.0.0",
        tool_binary="confused",
        category="supply_chain",
        depends_on=(),
        produces=("dependency_confusion",),
        timeout_seconds=300,
    )

    @property
    def meta(self) -> PluginMeta:
        return self._meta

    def build_command(
        self,
        target: str,
        scan_profile: str,
        ctx: DAGContext,
        tool_config: dict[str, Any],
    ) -> str:
        package_file = tool_config.get("package_file", "")
        if not package_file:
            # Default: check package.json (most common web target)
            package_file = _DEFAULT_PACKAGE_FILES[0]

        return f"confused -l {package_file}"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        confused_packages: list[str] = []

        if not raw_stdout.strip():
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data={
                    "dependency_confusion": {
                        "vulnerable_packages": [],
                        "total_found": 0,
                    }
                },
            )

        for line in raw_stdout.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # confused outputs lines like: "FOUND on npm: internal-utils"
            if stripped.upper().startswith("FOUND"):
                # Extract package name and registry info
                # Typical format: "FOUND on <registry>: <package-name>"
                parts = stripped.split(":", 1)
                if len(parts) == 2:
                    package_name = parts[1].strip()
                    registry_part = parts[0]  # e.g. "FOUND on npm"
                else:
                    package_name = stripped
                    registry_part = "unknown registry"

                confused_packages.append(package_name)

                findings.append({
                    "type": "dependency_confusion",
                    "severity": "high",
                    "title": f"Dependency Confusion: {package_name}",
                    "description": (
                        f"The internal package '{package_name}' was found on a public registry "
                        f"({registry_part.replace('FOUND on ', '').strip()}). "
                        "An attacker could upload a malicious package with this name to the public "
                        "registry with a higher version number, causing build systems to pull the "
                        "malicious version instead of the internal one. "
                        "This is a high-severity supply chain attack vector (CVE category: "
                        "dependency confusion / namespace confusion)."
                    ),
                    "package_name": package_name,
                    "registry_info": registry_part,
                    "raw_line": stripped,
                })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={
                "dependency_confusion": {
                    "vulnerable_packages": confused_packages,
                    "total_found": len(confused_packages),
                }
            },
            findings=findings,
        )
