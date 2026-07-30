from __future__ import annotations

from datetime import timedelta

from modules.correlation.incident_models import IncidentCandidate
from modules.correlation.models import Correlation

# Rule names considered "contextual": correlations from these rules are
# never selected as primary drivers of an incident, but they can be
# attached as supporting evidence when they relate to one.
#
# This is a placeholder policy. A future refactor is planned to move
# this decision onto the rules themselves (e.g. a CorrelationRole enum
# checked via `correlation.role`), so the pipeline doesn't need to
# hardcode rule names here. Not done in this PR to keep scope narrow.
_CONTEXTUAL_RULE_NAMES = frozenset(
    {
        "registry_persistence",
        "scheduled_task_persistence",
        "browser_activity",
    }
)

_TEMPORAL_WINDOW = timedelta(minutes=10)


class IncidentEnricher:
    """
    Attach contextual correlations to already-built IncidentCandidate
    objects as supporting evidence.

    This class does not build incidents, compute graph edges, or run
    UnionFind -- it only decides, for correlations that were never
    selected as primary drivers, whether they are related closely
    enough to an existing incident to be attached to it.
    """

    def enrich(
        self,
        incidents: list[IncidentCandidate],
        correlations: list[Correlation],
    ) -> list[IncidentCandidate]:
        """
        Populate supporting_correlation_ids on every incident.

        Nothing else on any IncidentCandidate is modified.
        """

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
        """
        Return correlations that are eligible to become supporting
        evidence: contextual rule type, and not already a primary
        correlation of any incident.
        """

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
        """
        True when a contextual correlation is related closely enough
        to attach to this incident: shared entity, shared event, or
        temporal overlap.
        """

        return (
            cls._shared_entities(correlation, incident)
            or cls._shared_events(correlation, incident)
            or cls._temporal_match(correlation, incident)
        )

    @staticmethod
    def _shared_entities(correlation: Correlation, incident: IncidentCandidate) -> bool:
        """
        True when the correlation shares at least one entity_id with
        the incident.
        """

        return bool(set(correlation.entity_ids) & set(incident.entity_ids))

    @staticmethod
    def _shared_events(correlation: Correlation, incident: IncidentCandidate) -> bool:
        """
        True when the correlation shares at least one event_id with
        the incident.
        """

        return bool(set(correlation.event_ids) & set(incident.event_ids))

    @staticmethod
    def _temporal_match(correlation: Correlation, incident: IncidentCandidate) -> bool:
        """
        True when the correlation's start_time falls within the
        incident's [start_time, end_time] window, expanded by
        TEMPORAL_WINDOW on each side.
        """

        window_start = incident.start_time - _TEMPORAL_WINDOW
        window_end = incident.end_time + _TEMPORAL_WINDOW

        return window_start <= correlation.start_time <= window_end

    @staticmethod
    def _attach_support(incident: IncidentCandidate, supporting_ids: set[str]) -> None:
        """
        Write the sorted, de-duplicated supporting_correlation_ids
        back onto the incident. No other field is touched.
        """

        incident.supporting_correlation_ids = sorted(supporting_ids)
