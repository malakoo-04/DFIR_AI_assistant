from __future__ import annotations

from datetime import datetime

from modules.correlation.incident_models import GraphEdge, IncidentCandidate
from modules.correlation.models import Correlation


class IncidentSerializer:
    """
    Convert IncidentCandidate objects into a deterministic,
    JSON-compatible payload.

    This is the contract boundary between the deterministic forensic
    engine and any future AI consumer: no dataclasses, no enums, no
    datetime objects, and no Python-object identity ever cross this
    line. This class performs no reasoning, enrichment, or scoring --
    it only reshapes data that has already been fully computed
    upstream.
    """

    def serialize(
        self,
        incidents: list[IncidentCandidate],
        correlations: list[Correlation],
    ) -> list[dict]:
        """
        Serialize every incident into a plain dict, sorted
        deterministically by incident_id.
        """

        by_id = {correlation.correlation_id: correlation for correlation in correlations}

        serialized = [
            self._serialize_incident(incident, by_id) for incident in incidents
        ]

        return sorted(serialized, key=lambda payload: payload["incident_id"])

    def _serialize_incident(
        self,
        incident: IncidentCandidate,
        by_id: dict[str, Correlation],
    ) -> dict:
        """
        Serialize a single IncidentCandidate into a plain dict.
        """

        return {
            "incident_id": incident.incident_id,
            "time_window": {
                "start": self._iso_time(incident.start_time),
                "end": self._iso_time(incident.end_time),
            },
            "severity": incident.severity.value,
            "confidence": incident.confidence,
            "primary_correlations": self._serialize_correlation_list(
                incident.correlation_ids, by_id
            ),
            "supporting_correlations": self._serialize_correlation_list(
                incident.supporting_correlation_ids, by_id
            ),
            "entities": sorted(incident.entity_ids),
            "events": sorted(incident.event_ids),
            "rules": sorted(incident.rule_names),
            "graph": self._serialize_graph(incident.graph_edges),
            "related_incidents": sorted(incident.related_incident_ids),
        }

    def _serialize_correlation_list(
        self,
        correlation_ids: list[str],
        by_id: dict[str, Correlation],
    ) -> list[dict]:
        """
        Serialize a list of correlation_ids into their full
        correlation payloads, sorted by correlation_id.

        Any correlation_id not found in `by_id` is skipped rather
        than raising, since serialization should not fail an entire
        incident over a single missing lookup.
        """

        correlations = [
            self._serialize_correlation(by_id[correlation_id])
            for correlation_id in correlation_ids
            if correlation_id in by_id
        ]

        return sorted(correlations, key=lambda payload: payload["correlation_id"])

    def _serialize_correlation(self, correlation: Correlation) -> dict:
        """
        Serialize a single Correlation into a plain dict.
        """

        return {
            "correlation_id": correlation.correlation_id,
            "rule_name": correlation.rule_name,
            "start_time": self._iso_time(correlation.start_time),
            "end_time": self._iso_time(correlation.end_time),
            "severity": correlation.severity.value,
            "confidence": correlation.confidence,
            "entity_ids": sorted(correlation.entity_ids),
            "event_ids": sorted(correlation.event_ids),
        }

    def _serialize_graph(self, graph_edges: list[GraphEdge]) -> list[dict]:
        """
        Serialize every GraphEdge into a plain dict, sorted
        deterministically by (source, target).
        """

        edges = [
            {
                "source": edge.source_correlation_id,
                "target": edge.target_correlation_id,
                "score": edge.score,
                "matched_criteria": list(edge.matched_criteria),
            }
            for edge in graph_edges
        ]

        return sorted(edges, key=lambda edge: (edge["source"], edge["target"]))

    @staticmethod
    def _iso_time(value: datetime) -> str:
        """
        Convert a datetime into an ISO-8601 string.
        """

        return value.isoformat()
