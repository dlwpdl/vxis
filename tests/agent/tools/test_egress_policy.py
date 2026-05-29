from __future__ import annotations

from vxis.agent.egress_policy import evaluate_python_egress, evaluate_shell_egress


def test_shell_egress_policy_blocks_raw_tools_only_when_ghost_active(monkeypatch) -> None:
    from vxis.ghost.layer import ghost_layer

    ghost_layer.deactivate()
    assert evaluate_shell_egress("nmap -sV localhost").allowed is True

    ghost_layer.activate(["socks5://127.0.0.1:9050"])
    try:
        blocked = evaluate_shell_egress("cd /tmp && nmap -sV localhost")
        assert blocked.allowed is False
        assert blocked.match == "nmap"

        allowed = evaluate_shell_egress("curl -i https://example.com")
        assert allowed.allowed is True

        monkeypatch.setenv("VXIS_ALLOW_DIRECT_EGRESS", "1")
        assert evaluate_shell_egress("nmap -sV localhost").allowed is True
    finally:
        ghost_layer.deactivate()


def test_python_egress_policy_blocks_raw_socket_and_subprocess_when_ghost_active() -> None:
    from vxis.ghost.layer import ghost_layer

    ghost_layer.activate(["socks5://127.0.0.1:9050"])
    try:
        assert evaluate_python_egress("import socket\nsocket.socket()").allowed is False
        assert evaluate_python_egress("import subprocess\nsubprocess.run(['nmap'])").allowed is False
        assert evaluate_python_egress("import httpx\nprint('proxy-aware client')").allowed is True
    finally:
        ghost_layer.deactivate()
