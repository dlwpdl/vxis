"""MITRE ATT&CK technique mapping for web-focused findings.

This is a SMALL curated subset of the ATT&CK Enterprise matrix focused on
the techniques that appear in web application pentests. Not a full matrix
— just what VXIS actually finds. Extend as needed.

Each entry: technique_id → (name, tactic, finding_types_that_map_here)
"""

MITRE_TECHNIQUES: dict[str, dict[str, object]] = {
    # Reconnaissance / Initial Access
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "finding_types": [
            "sql_injection", "command_injection", "rce", "xxe", "ssti",
            "deserialization", "xss_stored", "csrf",
        ],
    },
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconnaissance",
        "finding_types": ["information_disclosure"],
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactic": "Reconnaissance",
        "finding_types": ["information_disclosure"],
    },

    # Credential Access
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "finding_types": ["weak_auth", "auth_bypass"],
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic": "Credential Access",
        "finding_types": [
            "information_disclosure",  # env / config file leaks
            "sensitive_data_exposure",
        ],
        "keywords": [".env", "config", ".git", "actuator/env", "wp-config", "credentials"],
    },
    "T1555": {
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "finding_types": ["sensitive_data_exposure"],
    },

    # Collection / Discovery
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "finding_types": ["information_disclosure"],
        "keywords": ["ftp/", "backup", "listing", "directory"],
    },
    "T1526": {
        "name": "Cloud Service Discovery",
        "tactic": "Discovery",
        "finding_types": ["information_disclosure"],
        "keywords": ["actuator", "metadata", "cloud", "aws", "gcp", "azure"],
    },

    # Privilege / Access Control
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "finding_types": ["broken_access_control", "idor", "privilege_escalation"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "finding_types": ["auth_bypass", "session_hijacking"],
    },

    # Execution
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "finding_types": ["command_injection", "rce"],
    },

    # Impact
    "T1485": {
        "name": "Data Destruction",
        "tactic": "Impact",
        "finding_types": ["sql_injection"],  # destructive SQLi
    },
    "T1567": {
        "name": "Exfiltration Over Web Service",
        "tactic": "Exfiltration",
        "finding_types": [
            "sql_injection", "information_disclosure", "xxe", "ssrf",
        ],
    },

    # Defense evasion / misconfig
    "T1600": {
        "name": "Weaken Encryption",
        "tactic": "Defense Evasion",
        "finding_types": ["weak_crypto", "tls_misconfiguration"],
    },
    "T1556": {
        "name": "Modify Authentication Process",
        "tactic": "Credential Access",
        "finding_types": ["auth_bypass", "jwt_confusion"],
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic": "Initial Access",
        "finding_types": ["information_disclosure"],
        "keywords": ["aws", "s3", "iam", "cloud"],
    },
}


def infer_techniques(finding_type: str, title: str = "", affected_component: str = "") -> list[str]:
    """Return MITRE technique IDs that likely apply to this finding.

    Matching strategy:
    1. Exact finding_type match in technique's finding_types list
    2. Keyword match in title or affected_component
    """
    finding_type_l = finding_type.lower().strip()
    context = f"{title} {affected_component}".lower()
    matches: list[str] = []
    for tech_id, tech in MITRE_TECHNIQUES.items():
        types = tech.get("finding_types", []) or []
        if finding_type_l in [str(t).lower() for t in types]:
            matches.append(tech_id)
            continue
        keywords = tech.get("keywords", []) or []
        if keywords and any(str(kw).lower() in context for kw in keywords):
            matches.append(tech_id)
    return matches


def coverage_report(findings: list[dict]) -> dict[str, object]:
    """Build a coverage report from a list of findings.

    Returns:
        {
            "techniques_covered": [tech_id, ...],
            "tactics_covered": [tactic_name, ...],
            "per_technique": [{"id", "name", "tactic", "finding_count"}, ...],
            "coverage_pct": float (covered / total_known),
        }
    """
    tech_counts: dict[str, int] = {}
    for f in findings:
        ft = str(f.get("finding_type", ""))
        title = str(f.get("title", ""))
        comp = str(f.get("affected_component", ""))
        for tid in infer_techniques(ft, title, comp):
            tech_counts[tid] = tech_counts.get(tid, 0) + 1

    per_technique = []
    tactics: set[str] = set()
    for tid, count in sorted(tech_counts.items(), key=lambda x: (-x[1], x[0])):
        tech = MITRE_TECHNIQUES.get(tid, {})
        per_technique.append({
            "id": tid,
            "name": tech.get("name", tid),
            "tactic": tech.get("tactic", "unknown"),
            "finding_count": count,
        })
        tactics.add(str(tech.get("tactic", "unknown")))

    return {
        "techniques_covered": list(tech_counts.keys()),
        "tactics_covered": sorted(tactics),
        "per_technique": per_technique,
        "coverage_pct": round(
            100.0 * len(tech_counts) / max(1, len(MITRE_TECHNIQUES)), 1
        ),
        "total_known_techniques": len(MITRE_TECHNIQUES),
    }
