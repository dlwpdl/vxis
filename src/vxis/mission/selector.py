from __future__ import annotations

from .config import MissionConfig, Scope

SCOPE_AGENTS: dict[str, list[str]] = {
    "web": [
        "recon",
        "osint",
        "subdomain_takeover",
        "threat_intel",
        "web",
        "api",
        "http_protocol",
        "browser_client",
        "email_security",
        "crypto_tls",
        "compliance",
    ],
    "cloud": [
        "recon",
        "cloud",
        "container_k8s",
        "supply_chain",
        "secrets_lifecycle",
        "iam_deep",
        "compliance",
    ],
    "code": [
        "supply_chain",
        "secrets_lifecycle",
        "deserialization",
        "sast",
        "sbom",
        "compliance",
    ],
    "network": [
        "recon",
        "network",
        "l2_network",
        "ipv6",
        "bgp_routing",
        "legacy_protocol",
        "voip",
    ],
    "mobile": ["mobile", "web", "api", "crypto_tls"],
    "full": [],
}

ALL_AGENTS: list[str] = [
    "physical_usb",
    "side_channel",
    "dma_attack",
    "l2_network",
    "wireless",
    "bluetooth_deep",
    "network",
    "bgp_routing",
    "ipv6",
    "crypto_tls",
    "quic_http3",
    "dtls",
    "identity_ad",
    "remote_access",
    "deserialization",
    "encoding_attack",
    "recon",
    "osint",
    "subdomain_takeover",
    "threat_intel",
    "web",
    "api",
    "http_protocol",
    "mobile",
    "browser_client",
    "web3_blockchain",
    "dns_deep",
    "email_security",
    "voip",
    "cloud",
    "container_k8s",
    "database",
    "supply_chain",
    "iot_firmware",
    "ics_scada",
    "legacy_protocol",
    "message_queue",
    "big_data_analytics",
    "cms_biz_platform",
    "collaboration",
    "monitoring_stack",
    "cdn_edge",
    "secrets_lifecycle",
    "third_party_webhook",
    "backup_dr",
    "game_realtime",
    "phishing_intel",
    "ss7_cellular",
    "ntp_time",
    "cold_boot_memory",
    "ai_llm",
    "adversarial_ai",
    "os_host",
    "lateral_move",
    "dos_resilience",
    "data_exfiltration",
    "fuzzing_zerodday",
    "business_logic",
    "deception_detection",
    "compliance",
    "quantum_risk",
    "virtualization",
]

DEPTH_DISABLED: dict[str, list[str]] = {
    "passive": [
        "dos_resilience",
        "fuzzing_zerodday",
        "side_channel",
        "dma_attack",
        "ss7_cellular",
        "cold_boot_memory",
        "deserialization",
        "data_exfiltration",
    ],
    "normal": [
        "fuzzing_zerodday",
        "side_channel",
        "dma_attack",
        "ss7_cellular",
        "cold_boot_memory",
    ],
    "aggressive": ["fuzzing_zerodday"],
    "elite": [],
}

INTERNAL_AGENTS: list[str] = [
    "identity_ad",
    "remote_access",
    "os_host",
    "lateral_move",
    "l2_network",
    "wireless",
    "legacy_protocol",
    "ics_scada",
    "cold_boot_memory",
]

STEALTH_DISABLED: list[str] = [
    "dos_resilience",
    "fuzzing_zerodday",
    "side_channel",
    "ss7_cellular",
]
STEALTH_FORCED: list[str] = ["deception_detection"]


class AgentSelector:
    @classmethod
    def select(cls, cfg: MissionConfig) -> list[str]:
        if cfg.scope == Scope.FULL:
            pool = ALL_AGENTS.copy()
        elif cfg.scope == Scope.CUSTOM:
            pool = cfg.custom_agents.copy()
        else:
            pool = SCOPE_AGENTS.get(cfg.scope.value, ALL_AGENTS.copy())

        disabled = set(DEPTH_DISABLED.get(cfg.depth.value, []))

        if cfg.stealth:
            disabled.update(STEALTH_DISABLED)
            for agent in STEALTH_FORCED:
                if agent not in pool:
                    pool.append(agent)

        if cfg.perspective.value in ("internal", "both"):
            for agent in INTERNAL_AGENTS:
                if agent not in pool:
                    pool.append(agent)

        return [a for a in pool if a not in disabled]
