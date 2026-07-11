"""
Fixed case-template library — predefined task checklists for common
incident types, so opening a case doesn't start from a blank page.
"""

CASE_TEMPLATES: dict[str, dict] = {
    "phishing": {
        "label": "Phishing",
        "description": "Suspicious or confirmed phishing email",
        "tasks": [
            "Identify sender address, return-path, and originating IP",
            "Analyze email headers and any attachments/links",
            "Identify all recipients / affected mailboxes",
            "Block sender domain and IOCs at the email gateway",
            "Search mail environment for similar/related messages",
            "Reset credentials for any users who entered them",
            "Send user awareness notification",
        ],
    },
    "ransomware": {
        "label": "Ransomware",
        "description": "Ransomware infection or encryption event",
        "tasks": [
            "Isolate affected host(s) from the network immediately",
            "Identify ransomware family/variant",
            "Determine initial access vector",
            "Verify backup integrity and availability",
            "Assess lateral movement / blast radius",
            "Preserve forensic evidence before any remediation",
            "Notify legal/management per the IR plan",
            "Eradicate and restore from a known-clean backup",
        ],
    },
    "malware": {
        "label": "Malware",
        "description": "Malware detection on an endpoint",
        "tasks": [
            "Isolate the affected host",
            "Identify the malware family (hash / YARA / AV verdict)",
            "Determine the persistence mechanism",
            "Check for lateral movement to other hosts",
            "Collect IOCs and block them at the perimeter",
            "Remediate and verify the host is clean",
        ],
    },
    "data_breach": {
        "label": "Data breach",
        "description": "Suspected or confirmed exposure of sensitive data",
        "tasks": [
            "Identify the scope of exposed data",
            "Determine the access timeline",
            "Preserve logs and evidence",
            "Assess regulatory notification requirements",
            "Notify legal/compliance",
            "Rotate exposed credentials/keys",
        ],
    },
    "unauthorized_access": {
        "label": "Unauthorized access",
        "description": "Compromised account or unauthorized system access",
        "tasks": [
            "Identify the compromised account(s)",
            "Force password reset and revoke active sessions",
            "Review account activity for lateral movement",
            "Check for persistence (new accounts, keys, forwarding rules)",
            "Review MFA / conditional-access gaps",
        ],
    },
}


def list_templates() -> list[dict]:
    return [{"key": k, **v} for k, v in CASE_TEMPLATES.items()]


def get_template(key: str) -> dict | None:
    return CASE_TEMPLATES.get(key)
