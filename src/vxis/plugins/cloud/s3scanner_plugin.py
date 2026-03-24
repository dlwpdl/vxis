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
    # Remove path/query/fragment
    domain = domain.split("/")[0]
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
        tier=2,
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
        # Allow explicit bucket list override via tool_config
        buckets: list[str] | None = tool_config.get("buckets")
        if not buckets:
            company = _derive_company_name(target)
            buckets = [f"{company}{suffix}" for suffix in _BUCKET_SUFFIXES]

        # s3scanner v2+ CLI:
        #   s3scanner scan --bucket NAME --json          (single bucket)
        #   s3scanner scan --bucket-file FILE --json     (multi-bucket file)
        #
        # For multiple buckets we write a bucket-file via process substitution
        # so a single invocation handles all names.  The bucket list is joined
        # with newlines and fed through bash process substitution.
        bucket_list = "\n".join(buckets)
        # Shell command: create a temp file, write bucket names, scan, clean up
        return (
            f"bash -c 'TMP=$(mktemp); printf \"{bucket_list}\" > \"$TMP\"; "
            f"s3scanner scan --bucket-file \"$TMP\" --json; rm -f \"$TMP\"'"
        )

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

            # s3scanner JSON output fields vary by version:
            # v1: "exists", "public_read", "public_write"
            # v2: "name"/"bucket", "AllUsers_read", "AllUsers_write",
            #     "AuthUsers_read", "AuthUsers_write"
            exists: bool = record.get("exists", True)  # v2 always exists if returned
            bucket_name: str = record.get("name", record.get("bucket", ""))

            # Support both v1 and v2 field naming
            public_read: bool = bool(
                record.get("public_read", False)
                or record.get("AllUsers_read", False)
            )
            public_write: bool = bool(
                record.get("public_write", False)
                or record.get("AllUsers_write", False)
            )
            # AuthUsers = any AWS-authenticated user — also a finding
            auth_read: bool = bool(record.get("AuthUsers_read", False))
            auth_write: bool = bool(record.get("AuthUsers_write", False))

            if not exists:
                continue

            if public_read or public_write or auth_read or auth_write:
                severity = "critical" if public_write or auth_write else "high"
                bucket_info: dict[str, Any] = {
                    "bucket": bucket_name,
                    "exists": True,
                    "public_read": public_read,
                    "public_write": public_write,
                    "auth_read": auth_read,
                    "auth_write": auth_write,
                    "severity": severity,
                }
                public_buckets.append(bucket_info)
                findings.append({
                    "type": "public_s3_bucket",
                    "severity": severity,
                    "title": f"Publicly Accessible S3 Bucket: {bucket_name}",
                    "description": (
                        f"S3 bucket '{bucket_name}' is publicly accessible. "
                        f"Public read: {public_read}, Public write: {public_write}, "
                        f"Auth read: {auth_read}, Auth write: {auth_write}."
                    ),
                    "bucket": bucket_name,
                    "public_read": public_read,
                    "public_write": public_write,
                    "auth_read": auth_read,
                    "auth_write": auth_write,
                })

        parsed_data["public_buckets"] = public_buckets

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data=parsed_data,
            findings=findings,
        )
