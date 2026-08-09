"""Data contract for the IOC Extraction Agent (Agent 2).

This module defines the *shape* IOCExtractionAgent's output must take.
It contains no reasoning of its own -- it only describes what a valid
IOC record looks like, so QwenIOCValidator has something concrete to
check the model's JSON against, and so any later consumer (Agent 3,
the Final Report Agent) has a stable contract to import instead of
re-deriving it from prose.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class IOCType(str, Enum):
    """Canonical IOC categories this agent is allowed to emit.

    This list mirrors the categories enumerated in the Agent 2 spec.
    It is deliberately closed -- QwenIOCValidator normalizes whatever
    string the model returns onto one of these values (see
    ``IOCType.coerce``) rather than accepting arbitrary free-text
    types, so downstream consumers can switch/filter on ``type``
    without having to handle unbounded string variance.
    """

    IP_ADDRESS = "ip_address"
    URL = "url"
    DOMAIN = "domain"
    HOSTNAME = "hostname"
    EMAIL_ADDRESS = "email_address"
    POWERSHELL_COMMAND = "powershell_command"
    CMD_COMMAND = "cmd_command"
    ENCODED_POWERSHELL_PAYLOAD = "encoded_powershell_payload"
    DOWNLOADED_FILE = "downloaded_file"
    EXECUTABLE = "executable"
    DLL = "dll"
    SCRIPT = "script"
    REGISTRY_RUN_KEY = "registry_run_key"
    REGISTRY_PERSISTENCE_KEY = "registry_persistence_key"
    SCHEDULED_TASK = "scheduled_task"
    WINDOWS_SERVICE = "windows_service"
    FILE_PATH = "file_path"
    USER_ACCOUNT = "user_account"
    PROCESS_NAME = "process_name"
    MUTEX = "mutex"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    SUSPICIOUS_FILENAME = "suspicious_filename"
    RANSOM_NOTE = "ransom_note"
    ENCRYPTION_EXTENSION = "encryption_extension"
    NETWORK_INDICATOR = "network_indicator"
    DEFENDER_DETECTION = "defender_detection"
    BROWSER_DOWNLOAD = "browser_download"
    OTHER = "other"

    @classmethod
    def coerce(cls, raw: str) -> tuple["IOCType", str | None]:
        """Map a model-supplied type string onto a canonical IOCType.

        Returns ``(ioc_type, original_if_changed)``. ``original_if_changed``
        is ``None`` when ``raw`` already matched a canonical value
        exactly, and is the original string otherwise (so callers can
        preserve it, e.g. inside ``reason``, instead of silently
        discarding what the model actually said).
        """

        if not isinstance(raw, str):
            return cls.OTHER, str(raw)

        normalized = raw.strip().lower().replace("-", "_").replace(" ", "_")

        for member in cls:
            if normalized == member.value:
                return member, None

        alias_map = {
            "ip": cls.IP_ADDRESS,
            "ip_addr": cls.IP_ADDRESS,
            "ipv4": cls.IP_ADDRESS,
            "ipv6": cls.IP_ADDRESS,
            "email": cls.EMAIL_ADDRESS,
            "powershell": cls.POWERSHELL_COMMAND,
            "powershell_cmd": cls.POWERSHELL_COMMAND,
            "cmd": cls.CMD_COMMAND,
            "command": cls.CMD_COMMAND,
            "encoded_payload": cls.ENCODED_POWERSHELL_PAYLOAD,
            "base64_payload": cls.ENCODED_POWERSHELL_PAYLOAD,
            "download": cls.DOWNLOADED_FILE,
            "file": cls.FILE_PATH,
            "path": cls.FILE_PATH,
            "exe": cls.EXECUTABLE,
            "binary": cls.EXECUTABLE,
            "dll_file": cls.DLL,
            "registry_key": cls.REGISTRY_PERSISTENCE_KEY,
            "run_key": cls.REGISTRY_RUN_KEY,
            "service": cls.WINDOWS_SERVICE,
            "windows_service_name": cls.WINDOWS_SERVICE,
            "task": cls.SCHEDULED_TASK,
            "account": cls.USER_ACCOUNT,
            "username": cls.USER_ACCOUNT,
            "user": cls.USER_ACCOUNT,
            "process": cls.PROCESS_NAME,
            "md5": cls.HASH_MD5,
            "sha1": cls.HASH_SHA1,
            "sha256": cls.HASH_SHA256,
            "hash": cls.OTHER,
            "filename": cls.SUSPICIOUS_FILENAME,
            "ransomnote": cls.RANSOM_NOTE,
            "ransom_note_file": cls.RANSOM_NOTE,
            "extension": cls.ENCRYPTION_EXTENSION,
            "network": cls.NETWORK_INDICATOR,
            "port": cls.NETWORK_INDICATOR,
            "defender": cls.DEFENDER_DETECTION,
            "av_detection": cls.DEFENDER_DETECTION,
            "browser_file_download": cls.BROWSER_DOWNLOAD,
        }

        mapped = alias_map.get(normalized)
        if mapped is not None:
            return mapped, raw

        return cls.OTHER, raw


class IOCConfidence(str, Enum):
    """How confidently the model believes an IOC is genuine, based
    only on how directly the supplied evidence supports it."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @classmethod
    def coerce(cls, raw: str) -> "IOCConfidence":
        if isinstance(raw, str):
            normalized = raw.strip().lower()
            for member in cls:
                if normalized == member.value:
                    return member
        return cls.LOW


@dataclass(slots=True, frozen=True)
class IOC:
    """One indicator of compromise, traceable back to the evidence
    that produced it."""

    type: IOCType
    value: str
    confidence: IOCConfidence
    source: str
    reason: str


@dataclass(slots=True, frozen=True)
class IOCReport:
    """The complete, validated output of the IOC Extraction Agent."""

    iocs: list[IOC] = field(default_factory=list)


# Required keys for each IOC object in the model's raw JSON response,
# and the exact contract shown to the model inside the prompt.
IOC_REQUIRED_FIELDS: tuple[str, ...] = (
    "type",
    "value",
    "confidence",
    "source",
    "reason",
)

IOC_JSON_EXAMPLE: dict = {
    "iocs": [
        {
            "type": "url",
            "value": "http://10.0.2.7:8000/vpnupdate.exe",
            "confidence": "high",
            "source": "incident a93a81694a / correlation browser_download_execution",
            "reason": (
                "URL directly present in a browser_download_execution "
                "correlation's evidence field."
            ),
        }
    ]
}

ALLOWED_IOC_TYPES: tuple[str, ...] = tuple(member.value for member in IOCType)
