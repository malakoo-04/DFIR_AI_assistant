"""
Deterministic mapping between correlation rules and
MITRE ATT&CK techniques.

This module contains no logic.

It simply defines which ATT&CK techniques are
associated with each correlation rule.
"""

RULE_TO_MITRE = {

    # -------------------------------------------------
    # Execution
    # -------------------------------------------------

    "powershell_execution": [
        "T1059.001",      # PowerShell
    ],

    "browser_download_execution": [
        "T1105",          # Ingress Tool Transfer
        "T1204.002",      # User Execution: Malicious File
    ],

    # -------------------------------------------------
    # Persistence
    # -------------------------------------------------

    "registry_persistence": [
        "T1547.001",      # Registry Run Keys / Startup Folder
    ],

    "scheduled_task_persistence": [
        "T1053.005",      # Scheduled Task
    ],

    "service_installation": [
        "T1543.003",      # Windows Service
    ],

    # -------------------------------------------------
    # Discovery
    # -------------------------------------------------

    "browser_activity": [
        "T1016",          # System Network Configuration Discovery
    ],

    # -------------------------------------------------
    # Defense Evasion
    # -------------------------------------------------

    "event_log_cleared": [
        "T1070.001",      # Clear Windows Event Logs
    ],

    "defender_detection": [
        "T1562.001",      # Impair Defenses
    ],

    # -------------------------------------------------
    # Lateral Movement
    # -------------------------------------------------

    "usb_connection": [
        "T1091",          # Replication Through Removable Media
    ],
}