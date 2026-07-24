from enum import Enum


class ArtifactType(Enum):
    """
    Représente tous les types d'artefacts supportés
    par le framework DFIR-AI.
    """

    # ==========================================================
    # Windows Event Logs
    # ==========================================================
    EVTX = "evtx"

    # ==========================================================
    # Execution Artifacts
    # ==========================================================
    PREFETCH = "prefetch"
    AMCACHE = "amcache"
    BAM = "bam"
    SHIMCACHE = "shimcache"

    # ==========================================================
    # Registry
    # ==========================================================
    REGISTRY_SYSTEM = "registry_system"
    REGISTRY_SOFTWARE = "registry_software"
    REGISTRY_SECURITY = "registry_security"
    REGISTRY_SAM = "registry_sam"
    REGISTRY_NTUSER = "registry_ntuser"
    REGISTRY_DEFAULT = "registry_default"  # <-- AJOUTÉ
    USRCLASS = "usrclass"
    REGISTRY_TRANSACTION_LOG = "registry_transaction_log"

    # ==========================================================
    # File System
    # ==========================================================
    MFT = "mft"
    USN = "usn"            # <-- AJOUTÉ
    LOGFILE = "logfile"
    BOOT = "boot"
    SECURE = "secure"

    # ==========================================================
    # Activity & Logs
    # ==========================================================
    ACTIVITIESCACHE = "activitiescache"
    SRU = "sru"
    ESE_SUPPORT = "ese_support"  # <-- AJOUTÉ
    DEFENDER_LOG = "defender_log"  # <-- AJOUTÉ

    # ==========================================================
    # Shortcuts & Persistence
    # ==========================================================
    LNK = "lnk"
    JUMPLIST = "jumplist"
    SCHEDULED_TASK = "scheduled_task"  # <-- AJOUTÉ

    # ==========================================================
    # Browser
    # ==========================================================
    BROWSER = "browser"

    # ==========================================================
    # Windows Defender
    # ==========================================================
    DEFENDER = "defender"

    # ==========================================================
    # ESE Databases
    # ==========================================================
    ESE = "ese"

    # ==========================================================
    # Threat Intelligence / Incident Response Alerts
    # ==========================================================
    RANSOM_NOTE = "ransom_note"  # <-- AJOUTÉ

    # ==========================================================
    # Unknown
    # ==========================================================
    UNKNOWN = "unknown"