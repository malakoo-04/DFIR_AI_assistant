"""Data model for Indicators of Compromise (IOC) extraction.

IOC objects are produced exclusively from data that already exists in
the deterministic pipeline's own output (normalized events, Correlation
objects, serialized incidents). Nothing here re-parses forensic
artifacts or infers a value that isn't literally present somewhere in
that output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from modules.models.severity import Severity


class IOCType(str, Enum):
    """Canonical IOC categories. str-backed for direct JSON/text use,
    consistent with every other enum in this project (EventType,
    EventCategory, Severity)."""

    FILE = "file"
    DIRECTORY = "directory"
    EXECUTABLE = "executable"
    DROPPED_FILE = "dropped_file"
    POWERSHELL_SCRIPT = "powershell_script"
    COMMAND_LINE = "command_line"
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    UNC_PATH = "unc_path"
    REGISTRY_KEY = "registry_key"
    REGISTRY_VALUE = "registry_value"
    PERSISTENCE_LOCATION = "persistence_location"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    DRIVER = "driver"
    MUTEX = "mutex"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    CERTIFICATE_THUMBPRINT = "certificate_thumbprint"
    USERNAME = "username"
    HOSTNAME = "hostname"
    COMPUTER_NAME = "computer_name"
    MITRE_TECHNIQUE = "mitre_technique"


# Display grouping for reports (ioc_report.py), independent from IOCType
# itself so report structure can change without touching the model.
IOC_REPORT_GROUPS: dict[str, tuple[IOCType, ...]] = {
    "IP Addresses": (IOCType.IPV4, IOCType.IPV6),
    "Domains": (IOCType.DOMAIN,),
    "URLs": (IOCType.URL,),
    "Files": (
        IOCType.FILE,
        IOCType.DIRECTORY,
        IOCType.EXECUTABLE,
        IOCType.DROPPED_FILE,
        IOCType.UNC_PATH,
    ),
    "Registry": (
        IOCType.REGISTRY_KEY,
        IOCType.REGISTRY_VALUE,
        IOCType.PERSISTENCE_LOCATION,
    ),
    "Scheduled Tasks": (IOCType.SCHEDULED_TASK,),
    "Services": (IOCType.SERVICE, IOCType.DRIVER),
    "PowerShell": (IOCType.POWERSHELL_SCRIPT, IOCType.COMMAND_LINE),
    "Hashes": (IOCType.HASH_MD5, IOCType.HASH_SHA1, IOCType.HASH_SHA256),
    "Certificates": (IOCType.CERTIFICATE_THUMBPRINT,),
    "Identity": (IOCType.USERNAME, IOCType.HOSTNAME, IOCType.COMPUTER_NAME),
    "MITRE ATT&CK Techniques": (IOCType.MITRE_TECHNIQUE,),
    "Mutexes": (IOCType.MUTEX,),
}


@dataclass(slots=True)
class IOC:
    """
    One deduplicated indicator of compromise.

    `count`, `first_seen`, `last_seen`, `related_*_ids`, and
    `supporting_evidence` all accumulate as the same IOC is observed
    again across different events/correlations -- see
    IOCExtractor._merge() for how that accumulation works. Nothing
    about an IOC's identity (`ioc_type`, `value`) ever changes after
    creation; only its accumulated evidence does.
    """

    ioc_type: IOCType
    value: str
    source_artifact: str

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    confidence: float = 0.5

    related_incident_ids: set[str] = field(default_factory=set)
    related_correlation_ids: set[str] = field(default_factory=set)
    related_event_ids: set[str] = field(default_factory=set)

    # Bounded, human-readable snippets (e.g. a description or command
    # line fragment) -- not every occurrence, just enough to show why
    # this IOC was extracted. See IOCExtractor._MAX_SUPPORTING_EVIDENCE.
    supporting_evidence: list[str] = field(default_factory=list)

    count: int = 1

    severity: Severity | None = None

    @property
    def dedup_key(self) -> tuple[IOCType, str]:
        """Canonical identity used for merging duplicates. Value is
        normalized (case-folded, stripped) so 'C:\\Foo' and 'c:\\foo'
        merge into one IOC rather than staying as two near-duplicates."""
        return (self.ioc_type, self.value.strip().lower())