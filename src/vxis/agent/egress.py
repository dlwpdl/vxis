"""Enterprise egress filter — Phase C guardrail.

Blocks tool dispatches whose command/args reference hosts outside the
scan target's allowlist. Enterprise scans must not touch third-party
infrastructure, even accidentally (e.g. a typo routing traffic to a
live production host the Brain found in a config file).

Contract:
- Allowlist is derived from the scan target + VXIS_EGRESS_ALLOWLIST env
  (comma-separated hostnames). Enabled only when VXIS_EGRESS_STRICT=1.
- Strict mode OFF = permissive (return []); used for lab/benchmark runs.
- Strict mode ON = any extracted host not in allowlist → violation.

The filter is intentionally simple text extraction — not a packet-level
firewall. It's a "don't pipe credentials to attacker-controlled domain"
check, not a malware sandbox.
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlparse

# Extract http(s) URLs and bare host:port references from shell/python blobs.
_URL_RE = re.compile(r"https?://([A-Za-z0-9._\-]+)(?::\d+)?", re.IGNORECASE)
# Bare hostname patterns in curl/wget/nc/ssh style invocations.
_HOST_FLAG_RE = re.compile(
    r"(?:curl|wget|nc|ncat|ssh|sshpass|ffuf|gobuster|nuclei|sqlmap|nmap)[^\n;]*?\s(?:-u\s+)?([a-zA-Z0-9._\-]+\.[a-zA-Z]{2,})",
)

# Loopback + RFC1918 + lab shortcuts that are always allowed.
_ALWAYS_ALLOWED = frozenset({
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
})


def _is_private(host: str) -> bool:
    """RFC1918 / link-local / lab nets — always allowed in strict mode."""
    if host in _ALWAYS_ALLOWED:
        return True
    # 10.0.0.0/8, 172.16-31, 192.168/16, 169.254/16
    if host.startswith(("10.", "192.168.", "169.254.")):
        return True
    if host.startswith("172."):
        try:
            second = int(host.split(".", 2)[1])
            if 16 <= second <= 31:
                return True
        except (ValueError, IndexError):
            pass
    return False


def build_allowlist(target_url: str) -> set[str]:
    """Derive the allowlist from target URL + VXIS_EGRESS_ALLOWLIST env."""
    hosts: set[str] = set()
    try:
        parsed = urlparse(target_url)
        if parsed.hostname:
            hosts.add(parsed.hostname.lower())
    except Exception:
        pass
    extra = os.environ.get("VXIS_EGRESS_ALLOWLIST", "")
    for h in extra.split(","):
        h = h.strip().lower()
        if h:
            hosts.add(h)
    return hosts


def is_strict_mode() -> bool:
    return os.environ.get("VXIS_EGRESS_STRICT", "").lower() in ("1", "true", "yes")


def extract_hosts(blob: str) -> list[str]:
    """Pull likely-contacted hostnames out of a shell/python command string."""
    if not blob:
        return []
    found: set[str] = set()
    for m in _URL_RE.finditer(blob):
        found.add(m.group(1).lower())
    for m in _HOST_FLAG_RE.finditer(blob):
        found.add(m.group(1).lower())
    return sorted(found)


def check_violations(blob: str, allowlist: set[str]) -> list[str]:
    """Return list of hosts that appear in blob but not in allowlist.

    Private/loopback hosts pass. Only returns violations in strict mode —
    returns [] otherwise so the check is a no-op outside enterprise runs.
    """
    if not is_strict_mode():
        return []
    hosts = extract_hosts(blob)
    return [h for h in hosts if h not in allowlist and not _is_private(h)]
