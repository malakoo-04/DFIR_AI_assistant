"""Shared, read-only context passed to every IOC sub-extractor.

Built once per extraction run so no sub-extractor has to re-derive
event/correlation/incident lookups independently -- exactly the
"no duplicated extraction logic" requirement.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from modules.correlation.models import Correlation


@dataclass(slots=True)
class IOCExtractionContext:
    """
    timeline:
        The full normalized event list (TimelineBuilder.build() output).
        Sub-extractors that need broad coverage (e.g. hashes.py scanning
        every Amcache event, not just ones a correlation rule flagged)
        iterate this directly.
    correlations:
        The full Correlation object list (CorrelationEngine.run()
        output). Sub-extractors that care about rule-specific,
        already-interpreted evidence (e.g. powershell_execution's
        matched_indicators) iterate this instead.
    event_by_id:
        event_id -> event dict, for extractors that start from a
        correlation's event_ids and need the underlying event's own
        fields (object_path, user, computer, source_file...).
    incident_ids_by_correlation:
        correlation_id -> set of incident_ids that reference it as
        either a primary or supporting correlation, derived from
        IncidentSerializer output. Empty set if a correlation belongs
        to no incident (e.g. it was filtered out of every cluster).
    """

    timeline: list[dict]
    correlations: list[Correlation]
    event_by_id: dict[str, dict] = field(default_factory=dict)
    incident_ids_by_correlation: dict[str, set[str]] = field(default_factory=dict)

    def incidents_for(self, correlation_id: str) -> set[str]:
        return self.incident_ids_by_correlation.get(correlation_id, set())


def build_context(
    timeline: list[dict],
    correlations: list[Correlation],
    serialized_incidents: list[dict],
) -> IOCExtractionContext:
    """
    Build an IOCExtractionContext from the three pipeline outputs IOC
    extraction is allowed to use (see the module's own restriction:
    never reparse forensic artifacts).
    """

    event_by_id = {
        event.get("event_id"): event
        for event in timeline
        if event.get("event_id")
    }

    incident_ids_by_correlation: dict[str, set[str]] = {}
    for incident in serialized_incidents:
        incident_id = incident.get("incident_id")
        if not incident_id:
            continue
        for bucket in ("primary_correlations", "supporting_correlations"):
            for correlation_payload in incident.get(bucket) or []:
                correlation_id = correlation_payload.get("correlation_id")
                if not correlation_id:
                    continue
                incident_ids_by_correlation.setdefault(correlation_id, set()).add(
                    incident_id
                )

    return IOCExtractionContext(
        timeline=timeline,
        correlations=correlations,
        event_by_id=event_by_id,
        incident_ids_by_correlation=incident_ids_by_correlation,
    )