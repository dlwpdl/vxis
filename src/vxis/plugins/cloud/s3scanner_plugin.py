"""S3Scanner plugin — enumerate and check S3 bucket permissions."""

from __future__ import annotations

import json
import re
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.plugins.base import BasePlugin, PluginMeta

# Common permutations appended to the company name to guess bucket names.
_BUCKET_SUFFIXES: tuple[str, ...] = (
    "",
    "-backup",
    "-backups",
    "-data",
    "-assets",
    "-static",
    "-logs",
    "-dev",
    "-staging",
    "-prod",
    "-production",
    "-public",
    "-private",
    "-internal",
    "-uploads",
    "-media",
)


def _derive_company_name(domain: str) -> str:
    """Strip TLD and subdomains to get the likely company/product name."""
    # Remove protocol if present
    domain = re.sub(r"^https?://", "", domain)
    # Take the second-to-last label (e.g. "example" from "www.example.com")
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return parts[0]


class S3ScannerPlugin(BasePlugin):
    """Scan S3 bucket names derived from the target domain for public access."""

    _meta = PluginMeta(
        name="s3scanner",
        version="1.0.0",
        tool_binary="s3scanner",
        category="cloud",
        depends_on=(),
        produces=("public_buckets",),
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
        company = _derive_company_name(target)
        bucket_names = [f"{company}{suffix}" for suffix in _BUCKET_SUFFIXES]
        # s3scanner supports scanning a single bucket; join multiple names with
        # newlines via a file when orchestrating, but for a single command we
        # build a space-separated list using --bucket for each name.
        bucket_args = " ".join(
            f"--bucket {name}" for name in bucket_names
        )
        return f"s3scanner --json scan {bucket_args}"

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        parsed_data: dict[str, Any] = {"public_buckets": []}

        raw_stdout = raw_stdout.strip()
        if not raw_stdout:
            return PluginOutput(
                plugin_name=self.meta.name,
                raw_output=raw_stdout,
                parsed_data=parsed_data,
                findings=findings,
            )

        public_buckets: list[dict[str, Any]] = []

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            exists = record.get("exists", False)
            public_read = record.get("public_read", False)
            public_write = record.get("public_write", False)

            if not exists:
                continue

            if public_read or public_write:
                bucket_info: dict[str, Any] = {
                    "bucket": record.get("bucket", record.get("name", "")),
                    "exists": True,
                    "public_read": public_read,
                    "public_write": public_write,
                }
                public_buckets.append(bucket_info)
                findings.append(bucket_info)

        parsed_data["public_buckets"] = public_buckets

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
