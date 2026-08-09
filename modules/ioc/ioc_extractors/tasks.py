from __future__ import annotations

from modules.ioc.ioc_context import IOCExtractionContext
from modules.ioc.ioc_extractors.base import BaseIOCExtractor
from modules.ioc.ioc_models import IOC, IOCType


class ScheduledTaskIOCExtractor(BaseIOCExtractor):
    """Scheduled task names and their configured command line, from
    the scheduled_task_persistence correlation."""

    def extract(self, context: IOCExtractionContext) -> list[IOC]:
        iocs: list[IOC] = []

        for correlation in context.correlations:
            if correlation.rule_name != "scheduled_task_persistence":
                continue

            for event_id in correlation.event_ids:
                event = context.event_by_id.get(event_id)
                if not event:
                    continue

                task_name = event.get("object_name")
                command = event.get("object_path")

                if task_name:
                    iocs.append(
                        IOC(
                            ioc_type=IOCType.SCHEDULED_TASK,
                            value=task_name,
                            source_artifact="scheduled_task",
                            first_seen=event.get("timestamp"),
                            last_seen=event.get("timestamp"),
                            confidence=correlation.confidence,
                            related_correlation_ids={correlation.correlation_id},
                            related_event_ids={event_id},
                            related_incident_ids=set(context.incidents_for(correlation.correlation_id)),
                            supporting_evidence=[command] if command else [],
                            severity=correlation.severity,
                        )
                    )

                if command:
                    iocs.append(
                        IOC(
                            ioc_type=IOCType.COMMAND_LINE,
                            value=command,
                            source_artifact="scheduled_task",
                            first_seen=event.get("timestamp"),
                            last_seen=event.get("timestamp"),
                            confidence=correlation.confidence,
                            related_correlation_ids={correlation.correlation_id},
                            related_event_ids={event_id},
                            related_incident_ids=set(context.incidents_for(correlation.correlation_id)),
                        )
                    )

        return iocs