"""trufflehog plugin — exposed secrets detection in GitHub repositories."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from vxis.core.context import DAGContext, PluginOutput
from vxis.models.evidence import mask_secret
from vxis.plugins.base import BasePlugin, PluginMeta


def _derive_org(target: str) -> str:
    """Extract the GitHub organization name from the target domain.

    Strips common prefixes/suffixes (www., .com, .io, etc.) to infer the
    org slug.  This is a best-effort heuristic; callers may override via
    tool_config["github_org"].

    Examples:
        "acme.com"     -> "acme"
        "www.acme.io"  -> "acme"
        "acme.co.uk"   -> "acme"
    """
    hostname = target.lower().strip()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    # Take the first label (the part before any dots).
    org = hostname.split(".")[0]
    return org or target


class TrufflehogPlugin(BasePlugin):
    """Scan GitHub org repositories for exposed secrets using trufflehog."""

    _meta = PluginMeta(
        name="trufflehog",
        version="1.0.0",
        tool_binary="trufflehog",
        category="secrets",
        depends_on=(),
        produces=("exposed_secrets",),
        timeout_seconds=3600,
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
        # If explicit github_org is provided, scan that org
        org = tool_config.get("github_org", "")

        if org:
            cmd = (
                f"trufflehog github --org={org}"
                f" --json --no-verification --concurrency 5"
            )
            github_token: str | None = tool_config.get("github_token")
            if github_token:
                cmd += f" --token {github_token}"
        else:
            # For domain targets, scan the target's web pages for exposed secrets
            # Use the git scanner against the target to find .git exposure,
            # or fall back to a simple verification of the domain
            live_urls: list[str] = ctx.get_data("httpx", "live_urls", [])
            if live_urls:
                url = live_urls[0]
            else:
                url = f"https://{target}"
            # Try to find exposed .git repos or leaked secrets in page source
            cmd = (
                f"trufflehog git {url}"
                f" --json --no-verification --concurrency 5"
                f" --max-depth 3"
            )

        return cmd

    def parse_output(self, raw_stdout: str, raw_stderr: str) -> PluginOutput:
        findings: list[dict[str, Any]] = []
        seen_hashes: set[str] = set()

        for line in raw_stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            raw_secret: str = record.get("Raw", "")

            # Deduplicate by the SHA-256 of the raw secret value.
            secret_hash = hashlib.sha256(raw_secret.encode()).hexdigest()
            if secret_hash in seen_hashes:
                continue
            seen_hashes.add(secret_hash)

            # Mask sensitive value before storing in findings.
            masked_raw = mask_secret(raw_secret) if raw_secret else ""

            source_metadata: dict[str, Any] = record.get("SourceMetadata", {})

            findings.append({
                "detector_name": record.get("DetectorName", ""),
                "verified": record.get("Verified", False),
                "raw_masked": masked_raw,
                "secret_hash": secret_hash,
                "source_metadata": source_metadata,
            })

        return PluginOutput(
            plugin_name=self.meta.name,
            raw_output=raw_stdout,
            parsed_data={"exposed_secrets": findings},
            findings=findings,
        )
