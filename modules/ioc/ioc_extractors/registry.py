from __future__ import annotations

from modules.ioc.ioc_context import IOCExtractionContext
from modules.ioc.ioc_extractors.base import BaseIOCExtractor
from modules.ioc.ioc_models import IOC, IOCType


class RegistryIOCExtractor(BaseIOCExtractor):
    """
    Registry keys/values from every registry-sourced event, and a
    dedicated PERSISTENCE_LOCATION marker for the two rules that
    already interpret a registry key as a persistence mechanism
    (registry_persistence, service_installation via the Services key).
    """

    _PERSISTENCE_RULES = {"registry_persistence", "service_installation"}

    def extract(self, context: IOCExtractionContext) -> list[IOC]:
        iocs: list[IOC] = []

        for event in context.timeline:
            if event.get("artifact_type") != "registry":
                continue

            key_path = (event.get("evidence") or {}).get("key_path")
            if key_path:
                iocs.append(
                    IOC(
                        ioc_type=IOCType.REGISTRY_KEY,
                        value=key_path,
                        source_artifact="registry",
                        first_seen=event.get("timestamp"),
                        last_seen=event.get("timestamp"),
                        confidence=float(event.get("confidence", 0.5) or 0.5),
                        related_event_ids={event["event_id"]} if event.get("event_id") else set(),
                        supporting_evidence=[str(event.get("description") or "")] if event.get("description") else [],
                    )
                )

            value_name = event.get("object_name")
            value_data = event.get("object_path")
            if key_path and value_name and value_data:
                iocs.append(
                    IOC(
                        ioc_type=IOCType.REGISTRY_VALUE,
                        value=f"{key_path}\\{value_name} = {value_data}",
                        source_artifact="registry",
                        first_seen=event.get("timestamp"),
                        last_seen=event.get("timestamp"),
                        confidence=float(event.get("confidence", 0.5) or 0.5),
                        related_event_ids={event["event_id"]} if event.get("event_id") else set(),
                    )
                )

        for correlation in context.correlations:
            if correlation.rule_name not in self._PERSISTENCE_RULES:
                continue
            key_path = (correlation.evidence or {}).get("key_path")
            if not key_path:
                continue

            iocs.append(
                IOC(
                    ioc_type=IOCType.PERSISTENCE_LOCATION,
                    value=key_path,
                    source_artifact="registry",
                    first_seen=correlation.start_time,
                    last_seen=correlation.end_time,
                    confidence=correlation.confidence,
                    related_correlation_ids={correlation.correlation_id},
                    related_event_ids=set(correlation.event_ids),
                    related_incident_ids=set(context.incidents_for(correlation.correlation_id)),
                    supporting_evidence=[correlation.description] if correlation.description else [],
                    severity=correlation.severity,
                )
            )

        return iocs