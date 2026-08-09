from __future__ import annotations

from datetime import datetime

from modules.ioc.ioc_models import IOC
from modules.ioc.ioc_statistics import compute_statistics


class IOCSerializer:
    """Convert IOC objects into a plain, JSON-compatible dict -- same
    boundary discipline as IncidentSerializer: no dataclasses, no
    enums, no datetime objects, no sets cross this line."""

    def serialize(self, iocs: list[IOC]) -> dict:
        return {
            "ioc_statistics": compute_statistics(iocs),
            "iocs": [self._serialize_ioc(ioc) for ioc in iocs],
        }

    @staticmethod
    def _serialize_ioc(ioc: IOC) -> dict:
        return {
            "type": ioc.ioc_type.value,
            "value": ioc.value,
            "source_artifact": ioc.source_artifact,
            "first_seen": IOCSerializer._iso(ioc.first_seen),
            "last_seen": IOCSerializer._iso(ioc.last_seen),
            "confidence": ioc.confidence,
            "count": ioc.count,
            "severity": ioc.severity.value if ioc.severity else None,
            "related_incident_ids": sorted(ioc.related_incident_ids),
            "related_correlation_ids": sorted(ioc.related_correlation_ids),
            "related_event_ids": sorted(ioc.related_event_ids),
            "supporting_evidence": list(ioc.supporting_evidence),
        }

    @staticmethod
    def _iso(value: datetime | str | None) -> str | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value.isoformat()
        return str(value)