"""Rule-Based MITRE ATT&CK Tagger for ChronoTrace.

Strictly maps supported Windows Event logs to MITRE ATT&CK techniques based on verifiable rule logic.
Does not invent classifications or rely on black-box heuristics.
"""

from typing import Dict, Any, Optional, Tuple


MITRE_TECHNIQUE_METADATA = {
    "T1059.001": {
        "name": "PowerShell Execution",
        "stage": "Execution",
        "tactic": "Execution",
        "description": "Adversaries may abuse PowerShell commands and scripts for execution."
    },
    "T1053.005": {
        "name": "Scheduled Task",
        "stage": "Persistence",
        "tactic": "Persistence",
        "description": "Adversaries may abuse the Windows Task Scheduler to schedule programs or scripts for initial or recurring execution."
    },
    "T1003.001": {
        "name": "LSASS Memory Dump",
        "stage": "Credential Access",
        "tactic": "Credential Access",
        "description": "Adversaries may attempt to access and dump credentials from the Local Security Authority Subsystem Service (LSASS) process."
    },
    "T1136.001": {
        "name": "Local Account Creation",
        "stage": "Persistence",
        "tactic": "Persistence",
        "description": "Adversaries may create a local account to maintain access to victim systems."
    },
    "T1071.001": {
        "name": "Web Protocols (C2 Outbound)",
        "stage": "Command and Control",
        "tactic": "Command and Control",
        "description": "Adversaries may communicate using application layer protocols (HTTP/HTTPS) to avoid detection."
    },
    "T1070.001": {
        "name": "Clear Windows Event Logs",
        "stage": "Defense Evasion",
        "tactic": "Defense Evasion",
        "description": "Adversaries may clear Windows event logs to remove evidence of their activity."
    },
    "T1078": {
        "name": "Valid Accounts (Logon)",
        "stage": "Initial Access",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access."
    },
    "T1021.002": {
        "name": "SMB/Windows Admin Shares",
        "stage": "Lateral Movement",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid accounts to log into a service that accepts Remote Procedure Calls (RPC) or Server Message Block (SMB)."
    }
}


def tag_mitre_technique(event: Dict[str, Any]) -> Tuple[Optional[str], str, str]:
    """
    Evaluates rule conditions on normalized event fields.
    Returns:
        (technique_id, technique_name, attack_stage)
    """
    code = event.get("event_code")
    image = (event.get("image") or "").lower()
    cmd = (event.get("command_line") or "").lower()
    dst_port = event.get("dst_port")

    # Rule 1: Audit Log Cleared (Security 1102) or wevtutil cl
    if code == 1102 or "wevtutil" in image and (" cl " in cmd or "clear-log" in cmd):
        return ("T1070.001", "Clear Windows Event Logs", "Defense Evasion")

    # Rule 2: Credential Dumping (procdump, mimikatz, comsvcs lsass minidump)
    if "procdump" in image or "mimikatz" in image or ("lsass" in cmd and ("minidump" in cmd or "dump" in cmd or "comsvcs" in cmd)):
        return ("T1003.001", "LSASS Memory Dump", "Credential Access")

    # Rule 3: Scheduled Task Creation (schtasks.exe /create)
    if "schtasks.exe" in image and ("/create" in cmd or "-create" in cmd):
        return ("T1053.005", "Scheduled Task", "Persistence")

    # Rule 4: Local Account Creation (net.exe user /add)
    if ("net.exe" in image or "net1.exe" in image) and "user" in cmd and ("/add" in cmd or "-add" in cmd):
        return ("T1136.001", "Local Account Creation", "Persistence")

    # Rule 5: PowerShell Execution
    if "powershell.exe" in image or "pwsh.exe" in image:
        return ("T1059.001", "PowerShell Execution", "Execution")

    # Rule 6: Network Connection (Sysmon 3) on Web/C2 ports (80, 443, 8080, 8443)
    if code == 3 and dst_port in (80, 443, 8080, 8443, 4444):
        return ("T1071.001", "Web Protocols (C2 Outbound)", "Command and Control")

    # Rule 7: Successful Logon (Security 4624)
    if code == 4624:
        return ("T1078", "Valid Accounts (Logon)", "Initial Access")

    # Rule 8: File Drop (Sysmon 11) with executable extensions
    if code == 11 and (image.endswith(".exe") or image.endswith(".dll") or image.endswith(".ps1") or image.endswith(".bat")):
        return (None, "File Modification/Drop", "Execution")

    return (None, "General Activity", "Collection")
