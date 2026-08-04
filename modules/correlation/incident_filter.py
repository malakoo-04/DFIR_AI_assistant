from __future__ import annotations

from datetime import timedelta

from modules.correlation.incident_models import IncidentCandidate

MIN_CONFIDENCE = 0.55
MIN_PRIMARY_CORRELATIONS = 2
MIN_EVENTS = 3
MIN_DURATION = timedelta(seconds=2)

CONTEXTUAL_RULES = {
    "browser_activity",
    "registry_persistence",
    "scheduled_task_persistence",
}


class IncidentFilter:
    """
    Remove weak incidents before they ever reach the LLM.

    This module never modifies an incident.
    It simply decides whether it is worth keeping.
    """

    def filter(
        self,
        incidents: list[IncidentCandidate],
    ) -> list[IncidentCandidate]:

        return [
            incident
            for incident in incidents
            if self._keep(incident)
        ]

    def _keep(self, incident: IncidentCandidate) -> bool:

        if incident.confidence < MIN_CONFIDENCE:
            return False

        if len(incident.correlation_ids) < MIN_PRIMARY_CORRELATIONS:
            return False

        if len(incident.event_ids) < MIN_EVENTS:
            return False

        duration = incident.end_time - incident.start_time

        if duration < MIN_DURATION:
            return False

        if self._contextual_only(incident):
            return False

        return True

    @staticmethod
    def _contextual_only(incident: IncidentCandidate) -> bool:

        if not incident.rule_names:
            return True

        return all(
            rule in CONTEXTUAL_RULES
            for rule in incident.rule_names
        )