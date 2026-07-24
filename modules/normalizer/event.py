from __future__ import annotations
from modules.utils.time_utils import TimeUtils
import hashlib
from enum import Enum




def _scalar(value) -> str:
    """
    Convert an Enum member (or any value) into its canonical string
    representation.

    Examples:
        EventType.PROCESS_EXECUTION -> "process_execution"
        Severity.HIGH              -> "high"
        "registry"                 -> "registry"
        None                       -> ""
    """
    if value is None:
        return ""

    if isinstance(value, Enum):
        return str(value.value)

    return str(value)


def _build_event_id(
    artifact_type,
    event_type,
    timestamp,
    source_file,
    object_name,
    object_path,
) -> str:
    """
    Build a deterministic identifier for a normalized event.

    Only intrinsic event properties are used.

    Deliberately excluded:
        - confidence
        - evidence
        - description
        - raw_data
        - metadata

    because they may change without changing the forensic meaning
    of the event.
    """

    canonical_timestamp = TimeUtils.coerce_timestamp(timestamp)

    parts = [
        _scalar(artifact_type),
        _scalar(event_type),
        canonical_timestamp.isoformat() if canonical_timestamp else "",
        str(source_file or ""),
        str(object_name or ""),
        str(object_path or ""),
    ]

    canonical = "|".join(parts)

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def ensure_event_id(event: dict) -> str:
    """Return an event ID, hydrating deterministic IDs in legacy exports."""
    existing_id = event.get("event_id")
    if existing_id:
        return str(existing_id)

    event_id = _build_event_id(
        artifact_type=event.get("artifact_type"),
        event_type=event.get("event_type"),
        timestamp=event.get("timestamp"),
        source_file=event.get("source_file"),
        object_name=event.get("object_name"),
        object_path=event.get("object_path"),
    )
    event["event_id"] = event_id
    return event_id


def create_event(
    *,
    artifact_type:str,
    event_type:str,
    category:str,
    timestamp=None,
    object_name=None,
    object_path=None,
    related_objects=None,
    user=None,
    computer=None,
    description=None,
    confidence=1.0,
    evidence=None,
    source_file=None,
    raw_data=None,
    identity_keys=[],
):
    """
    Create a normalized DFIR event.

    Every event receives a deterministic event_id built from its
    intrinsic forensic properties.
    """

    event = {
        "artifact_type": artifact_type,
        "event_type": event_type,
        "category": category,
        "timestamp": timestamp,
        "object_name": object_name,
        "object_path": object_path,
        "related_objects": related_objects or [],
        "user": user,
        "computer": computer,
        "description": description,
        "confidence": confidence,
        "evidence": evidence or {},
        "source_file": source_file,
        "raw_data": raw_data or {},
        "identity_keys": identity_keys or [],
    }
    ensure_event_id(event)
    return event
