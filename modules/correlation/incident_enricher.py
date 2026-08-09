from __future__ import annotations

from datetime import timedelta

from modules.correlation.incident_models import IncidentCandidate
from modules.correlation.models import Correlation

_CONTEXTUAL_RULE_NAMES = frozenset(
    {
        "registry_persistence",
        "scheduled_task_persistence",
        "browser_activity",
        "logon_activity",
        "process_execution",
    }
)

_TEMPORAL_WINDOW = timedelta(minutes=10)


class IncidentEnricher:
    """Attach contextual correlations to already-built IncidentCandidate

    objects as supporting evidence.
    """

    def enrich(
        self,
        incidents: list[IncidentCandidate],
        correlations: list[Correlation],
    ) -> list[IncidentCandidate]:
        contextual = self._contextual_correlations(incidents, correlations)

        for incident in incidents:
            supporting_ids: set[str] = set(incident.supporting_correlation_ids)

            for correlation in contextual:
                if self._matches_incident(correlation, incident):
                    supporting_ids.add(correlation.correlation_id)

            self._attach_support(incident, supporting_ids)

        return incidents

    @staticmethod
    def _contextual_correlations(
        incidents: list[IncidentCandidate],
        correlations: list[Correlation],
    ) -> list[Correlation]:
        primary_ids: set[str] = set()

        for incident in incidents:
            primary_ids.update(incident.correlation_ids)

        return [
            correlation
            for correlation in correlations
            if correlation.rule_name in _CONTEXTUAL_RULE_NAMES
            and correlation.correlation_id not in primary_ids
        ]

    @classmethod
    def _matches_incident(
        cls,
        correlation: Correlation,
        incident: IncidentCandidate,
    ) -> bool:
        return (
            cls._shared_entities(correlation, incident)
            or cls._shared_events(correlation, incident)
            or cls._temporal_match(correlation, incident)
        )

    @staticmethod
    def _shared_entities(correlation: Correlation, incident: IncidentCandidate) -> bool:
        return bool(set(correlation.entity_ids) & set(incident.entity_ids))

    @staticmethod
    def _shared_events(correlation: Correlation, incident: IncidentCandidate) -> bool:
        return bool(set(correlation.event_ids) & set(incident.event_ids))

    @staticmethod
    def _temporal_match(correlation: Correlation, incident: IncidentCandidate) -> bool:
        window_start = incident.start_time - _TEMPORAL_WINDOW
        window_end = incident.end_time + _TEMPORAL_WINDOW
        return window_start <= correlation.start_time <= window_end

    @staticmethod
    def _attach_support(incident: IncidentCandidate, supporting_ids: set[str]) -> None:
        incident.supporting_correlation_ids = sorted(supporting_ids)