from __future__ import annotations

from modules.ioc.ioc_context import IOCExtractionContext
from modules.ioc.ioc_extractors.base import BaseIOCExtractor
from modules.ioc.ioc_models import IOC, IOCType


class ServiceIOCExtractor(BaseIOCExtractor):
    """
    Services and drivers, from registry_persistence's SERVICE_CREATED
    events and the service_installation (EVTX 7045) correlation --
    the two places a service/driver name is already recorded.
    """

    _RULES = {"registry_persistence", "service_installation"}

    def extract(self, context: IOCExtractionContext) -> list[IOC]:
        iocs: list[IOC] = []

        for correlation in context.correlations:
            if correlation.rule_name not in self._RULES:
                continue

            for event_id in correlation.event_ids:
                event = context.event_by_id.get(event_id)
                if not event:
                    continue

                name = event.get("object_name")
                path = event.get("object_path") or ""
                if not name:
                    continue

                ioc_type = IOCType.DRIVER if path.lower().endswith(".sys") else IOCType.SERVICE

                iocs.append(
                    IOC(
                        ioc_type=ioc_type,
                        value=name,
                        source_artifact=str(event.get("artifact_type") or "unknown"),
                        first_seen=event.get("timestamp"),
                        last_seen=event.get("timestamp"),
                        confidence=correlation.confidence,
                        related_correlation_ids={correlation.correlation_id},
                        related_event_ids={event_id},
                        related_incident_ids=set(context.incidents_for(correlation.correlation_id)),
                        supporting_evidence=[path] if path else [],
                        severity=correlation.severity,
                    )
                )

        return iocs