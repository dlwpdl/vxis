"""Vulnerability knowledge base module for VXIS.

Provides static lookup of remediation guidance, CWE/OWASP mappings,
and reference links for common vulnerability types.
"""

from vxis.knowledge.kb import RemediationInfo, VulnKB, get_vuln_kb

__all__ = ["RemediationInfo", "VulnKB", "get_vuln_kb"]
