"""CRT Phase 2 agents — all 57 autonomous pentesting specialists."""

from __future__ import annotations

# Import all agents so @register decorators fire on module load.
from . import (
    # Layer 1 — Physical
    physical_usb_agent,
    side_channel_agent,
    dma_attack_agent,
    # Layer 2 — Data Link
    l2_network_agent,
    wireless_agent,
    bluetooth_deep_agent,
    # Layer 3 — Network
    network_agent,
    bgp_routing_agent,
    ipv6_agent,
    # Layer 4 — Transport
    crypto_tls_agent,
    quic_http3_agent,
    dtls_agent,
    # Layer 5 — Session
    identity_ad_agent,
    remote_access_agent,
    # Layer 6 — Presentation
    deserialization_agent,
    encoding_attack_agent,
    # Layer 7 — Application
    recon_agent,
    osint_agent,
    subdomain_takeover_agent,
    threat_intel_agent,
    web_agent,
    api_agent,
    http_protocol_agent,
    mobile_agent,
    browser_client_agent,
    web3_blockchain_agent,
    dns_deep_agent,
    email_security_agent,
    voip_agent,
    cloud_agent,
    container_k8s_agent,
    database_agent,
    supply_chain_agent,
    iot_firmware_agent,
    ics_scada_agent,
    legacy_protocol_agent,
    message_queue_agent,
    big_data_analytics_agent,
    cms_biz_platform_agent,
    collaboration_agent,
    monitoring_stack_agent,
    cdn_edge_agent,
    secrets_lifecycle_agent,
    third_party_webhook_agent,
    backup_dr_agent,
    game_realtime_agent,
    # Layer 8+ — Human / Signal / Time
    phishing_intel_agent,
    ss7_cellular_agent,
    ntp_time_agent,
    cold_boot_memory_agent,
    # Special / Meta
    ai_llm_agent,
    adversarial_ai_agent,
    os_host_agent,
    lateral_move_agent,
    dos_resilience_agent,
    data_exfiltration_agent,
    fuzzing_zeroday_agent,
    business_logic_agent,
    deception_detection_agent,
    compliance_agent,
    quantum_risk_agent,
    virtualization_agent,
)
