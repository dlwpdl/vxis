"""nmap is OFF by default — held behind VXIS_ENABLE_NMAP.

Honesty/safety regression: the default registry advertised an nmap_scan tool
that is not installed in the sandbox image, and the system prompt claimed nmap
was pre-installed. Active port/service scanning also carries scope/noise/legality
risk. nmap is now opt-in: the default runtime registers no nmap tool (and makes
no nmap claim) unless the operator explicitly sets VXIS_ENABLE_NMAP.
"""

from __future__ import annotations

from vxis.agent.tools import build_default_registry


def test_nmap_off_by_default(monkeypatch):
    monkeypatch.delenv("VXIS_ENABLE_NMAP", raising=False)
    reg = build_default_registry()
    assert "nmap_scan" not in reg.list_tools()


def test_nmap_opt_in_with_flag(monkeypatch):
    monkeypatch.setenv("VXIS_ENABLE_NMAP", "1")
    reg = build_default_registry()
    assert "nmap_scan" in reg.list_tools()
