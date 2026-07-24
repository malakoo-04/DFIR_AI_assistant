# Base de connaissance DFIR

from .artifact_type import ArtifactType
from .signature import Signature


SIGNATURES = [

    # ==========================================================
    # WINDOWS EVENT LOGS
    # ==========================================================
    Signature(
        name="Windows Event Logs",
        artifact_type=ArtifactType.EVTX,
        extension=".evtx",
        parser="EVTXParser",
        description="Tous les journaux Windows (.evtx)",
        priority=1,
    ),

    # ==========================================================
    # PREFETCH
    # ==========================================================
    Signature(
        name="Prefetch",
        artifact_type=ArtifactType.PREFETCH,
        extension=".pf",
        parent="prefetch",
        parser="PrefetchParser",
        description="Fichiers Prefetch Windows",
        priority=1,
    ),

    # ==========================================================
    # AMCACHE
    # ==========================================================
    Signature(
        name="Amcache",
        artifact_type=ArtifactType.AMCACHE,
        filename="Amcache.hve",
        parser="AmcacheParser",
        description="Base Amcache",
        priority=1,
    ),

    # ==========================================================
    # REGISTRY HIVES & LOGS
    # ==========================================================
    Signature(
        name="SYSTEM Hive",
        artifact_type=ArtifactType.REGISTRY_SYSTEM,
        filename="SYSTEM",
        parent="config",
        parser="RegistryParser",
        description="Ruche SYSTEM",
        priority=1,
    ),
    Signature(
        name="SOFTWARE Hive",
        artifact_type=ArtifactType.REGISTRY_SOFTWARE,
        filename="SOFTWARE",
        parent="config",
        parser="RegistryParser",
        description="Ruche SOFTWARE",
        priority=1,
    ),
    Signature(
        name="SAM Hive",
        artifact_type=ArtifactType.REGISTRY_SAM,
        filename="SAM",
        parent="config",
        parser="RegistryParser",
        description="Ruche SAM",
        priority=1,
    ),
    Signature(
        name="SECURITY Hive",
        artifact_type=ArtifactType.REGISTRY_SECURITY,
        filename="SECURITY",
        parent="config",
        parser="RegistryParser",
        description="Ruche SECURITY",
        priority=1,
    ),
    Signature(
        name="DEFAULT Hive",
        artifact_type=ArtifactType.REGISTRY_DEFAULT,
        filename="DEFAULT",
        parent="config",
        parser="RegistryParser",
        description="Ruche utilisateur par défaut Windows",
        priority=1,
    ),
    Signature(
        name="NTUSER",
        artifact_type=ArtifactType.REGISTRY_NTUSER,
        filename="NTUSER.DAT",
        parser="RegistryParser",
        description="NTUSER.DAT de l'utilisateur",
        priority=2,
    ),
    Signature(
        name="UsrClass",
        artifact_type=ArtifactType.USRCLASS,
        filename="UsrClass.dat",
        parser="RegistryParser",
        description="UsrClass.dat de l'utilisateur",
        priority=2,
    ),
    Signature(
        name="Registry Transaction Logs",
        artifact_type=ArtifactType.REGISTRY_TRANSACTION_LOG,
        pattern="**/*.log[12]",
        parser="RegistryParser",
        description="Journaux de transaction de ruches de registre (.LOG1, .LOG2)",
        priority=10,
    ),

    # ==========================================================
    # FILE SYSTEM METADATA
    # ==========================================================
    Signature(
        name="Master File Table",
        artifact_type=ArtifactType.MFT,
        filename="$MFT",
        parser="MFTParser",
        description="Master File Table NTFS",
        priority=1,
    ),
    Signature(
        name="NTFS Change Journal",
        artifact_type=ArtifactType.USN,
        filename="$J",
        parent="$Extend",
        parser="USNJournalParser",
        description="Journal des modifications de fichiers USN NTFS ($J)",
        priority=1,
    ),
    Signature(
        name="NTFS LogFile",
        artifact_type=ArtifactType.LOGFILE,
        filename="$LogFile",
        parser="LogFileParser",
        description="Journal de transactions de métadonnées NTFS ($LogFile)",
        priority=1,
    ),
    Signature(
        name="NTFS Boot Sector",
        artifact_type=ArtifactType.BOOT,
        filename="$Boot",
        parser="BootParser",
        description="Fichier de secteur d'amorçage NTFS ($Boot)",
        priority=1,
    ),

    # ==========================================================
    # PERSISTENCE / SCHEDULED TASKS
    # ==========================================================
    Signature(
        name="Scheduled Tasks",
        artifact_type=ArtifactType.SCHEDULED_TASK,
        parent="Tasks",
        parser="TaskSchedulerParser",
        description="Définitions de tâches planifiées (Persistance)",
        priority=10,
    ),

    # ==========================================================
    # SYSTEM MONITORING & SECURITY LOGS
    # ==========================================================
    Signature(
        name="SRU Database",
        artifact_type=ArtifactType.SRU,
        filename="SRUDB.dat",
        parser="SRUParser",
        description="System Resource Usage Database",
        priority=1,
    ),
    Signature(
        name="ESE Database Transaction Logs",
        artifact_type=ArtifactType.ESE_SUPPORT,
        parent="SRU",
        parser="ESELogParser",
        description="Journaux de support/transaction ESE pour SRUM (.log, .chk, .jfm)",
        priority=5,
    ),
    Signature(
        name="Windows Defender CLI Log",
        artifact_type=ArtifactType.DEFENDER_LOG,
        filename="MpCmdRun.log",
        parser="DefenderCLIParser",
        description="Journal des exécutions de commandes Windows Defender",
        priority=1,
    ),

    # ==========================================================
    # INCIDENT RESPONSE HIGH-PRIORITY ALERTS
    # ==========================================================
    Signature(
        name="Ransomware Note",
        artifact_type=ArtifactType.RANSOM_NOTE,
        filename="README_FOR_DECRYPTION.txt",
        parser="RansomNoteParser",
        description="ALERTE : Note de rançongiciel détectée !",
        priority=1,
    ),

    # ==========================================================
    # SHORTCUTS & USER ACTIVITIES
    # ==========================================================
    Signature(
        name="Shortcut Files",
        artifact_type=ArtifactType.LNK,
        extension=".lnk",
        parser="LNKParser",
        description="Raccourcis Windows",
        priority=50,
    ),
    Signature(
        name="Automatic Jump Lists",
        artifact_type=ArtifactType.JUMPLIST,
        extension=".automaticDestinations-ms",
        parser="JumpListParser",
        description="Automatic Jump Lists",
        priority=20,
    ),
    Signature(
        name="Custom Jump Lists",
        artifact_type=ArtifactType.JUMPLIST,
        extension=".customDestinations-ms",
        parser="JumpListParser",
        description="Custom Jump Lists",
        priority=20,
    ),
    # -------------------------
    # Google Chrome
    # -------------------------

    Signature(
        name="Chrome History",
        artifact_type=ArtifactType.BROWSER,
        filename="History",
        parent="Chrome",
        parser="BrowserParser",
        description="Chrome browsing history",
        priority=1,
    ),

    Signature(
        name="Chrome Downloads",
        artifact_type=ArtifactType.BROWSER,
        filename="History",
        parent="Chrome",
        parser="BrowserParser",
        description="Chrome downloads history",
        priority=1,
    ),

    # -------------------------
    # Microsoft Edge
    # -------------------------

    Signature(
        name="Edge History",
        artifact_type=ArtifactType.BROWSER,
        filename="History",
        parent="Edge",
        parser="BrowserParser",
        description="Microsoft Edge browsing history",
        priority=1,
    ),

    Signature(
        name="Edge Downloads",
        artifact_type=ArtifactType.BROWSER,
        filename="History",
        parent="Edge",
        parser="BrowserParser",
        description="Microsoft Edge downloads history",
        priority=1,
    ),

    # -------------------------
    # Mozilla Firefox
    # -------------------------

    Signature(
        name="Firefox Places",
        artifact_type=ArtifactType.BROWSER,
        filename="places.sqlite",
        parent="Firefox",
        parser="BrowserParser",
        description="Firefox history and downloads database",
        priority=1,
    ),
]