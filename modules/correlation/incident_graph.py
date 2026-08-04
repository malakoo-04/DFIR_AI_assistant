from __future__ import annotations

from itertools import combinations
from typing import Any

from modules.correlation.incident_config import (
    EDGE_WEIGHTS,
    MIN_EDGE_SCORE,
    TEMPORAL_WINDOW_SECONDS,
)
from modules.correlation.incident_models import GraphEdge
from modules.correlation.models import Correlation

_EXECUTABLE_FIELDS = (
    "object_name",
    "object_path",
    "executed_name",
    "process_name",
    "image",
)

_USER_FIELDS = (
    "user",
    "username",
    "account",
    "account_name",
)


class IncidentGraphBuilder:
    """
    Build a weighted graph of GraphEdge objects connecting
    correlations that appear to be related.

    This class is deliberately narrow in scope: it only computes
    deterministic graph connectivity between Correlation objects.
    It knows nothing about incidents, clustering, or entity
    resolution.
    """

    def __init__(self) -> None:
        pass

    def build(self, correlations: list[Correlation]) -> list[GraphEdge]:
        """
        Compute a weighted edge for every unique pair of
        correlations whose combined score meets MIN_EDGE_SCORE.
        """

        edges: list[GraphEdge] = []

        for correlation_a, correlation_b in combinations(correlations, 2):
            score, matched_criteria = self._score_pair(correlation_a, correlation_b)

            if score < MIN_EDGE_SCORE:
                continue

            edges.append(
                GraphEdge(
                    source_correlation_id=correlation_a.correlation_id,
                    target_correlation_id=correlation_b.correlation_id,
                    score=score,
                    matched_criteria=matched_criteria,
                )
            )

        return edges

    def _score_pair(
        self,
        correlation_a: Correlation,
        correlation_b: Correlation,
    ) -> tuple[int, list[str]]:

        matched_criteria: list[str] = []

        shared_event = self._shared_events(correlation_a, correlation_b)
        shared_entity = self._shared_entities(correlation_a, correlation_b)
        same_executable = self._same_executable(correlation_a, correlation_b)
        same_user = self._same_user(correlation_a, correlation_b)
        temporal = self._temporal_proximity(correlation_a, correlation_b)

        score = 0

        # Strongest forensic evidence
        if shared_event:
            matched_criteria.append("shared_event")
            score += EDGE_WEIGHTS["shared_event"]

        if shared_entity:
            matched_criteria.append("shared_entity")
            score += EDGE_WEIGHTS["shared_entity"]

        # Executable/user are ONLY supporting evidence.
        # They never create an edge by themselves.
        if same_executable and (shared_event or shared_entity):
            matched_criteria.append("same_executable")
            score += EDGE_WEIGHTS["same_executable"]

        if same_user and (shared_event or shared_entity):
            matched_criteria.append("same_user")
            score += EDGE_WEIGHTS["same_user"]

        # Time proximity only reinforces an already-existing relationship.
        if temporal and score > 0:
            matched_criteria.append("temporal_proximity")
            score += EDGE_WEIGHTS["temporal_proximity"]

        return score, matched_criteria

    @staticmethod
    def _shared_events(
        correlation_a: Correlation,
        correlation_b: Correlation,
    ) -> bool:
        """
        True when the two correlations share at least one event_id.
        """

        return bool(set(correlation_a.event_ids) & set(correlation_b.event_ids))

    @staticmethod
    def _shared_entities(
        correlation_a: Correlation,
        correlation_b: Correlation,
    ) -> bool:
        """
        True when the two correlations share at least one entity_id.
        """

        return bool(set(correlation_a.entity_ids) & set(correlation_b.entity_ids))

    @classmethod
    def _same_executable(
        cls,
        correlation_a: Correlation,
        correlation_b: Correlation,
    ) -> bool:
        """
        Best-effort match on common executable-identifying fields
        found in correlation evidence. Exact match only, after
        normalizing to lowercase.
        """

        values_a = cls._evidence_values(correlation_a, _EXECUTABLE_FIELDS)
        values_b = cls._evidence_values(correlation_b, _EXECUTABLE_FIELDS)

        return bool(values_a & values_b)

    @classmethod
    def _same_user(
        cls,
        correlation_a: Correlation,
        correlation_b: Correlation,
    ) -> bool:
        """
        Best-effort match on common user-identifying fields found
        in correlation evidence. Exact match only, after
        normalizing to lowercase.
        """

        values_a = cls._evidence_values(correlation_a, _USER_FIELDS)
        values_b = cls._evidence_values(correlation_b, _USER_FIELDS)

        return bool(values_a & values_b)

    @staticmethod
    def _temporal_proximity(
        correlation_a: Correlation,
        correlation_b: Correlation,
    ) -> bool:
        """
        True when the two correlations start within
        TEMPORAL_WINDOW_SECONDS of each other.
        """

        delta_seconds = abs(
            (correlation_a.start_time - correlation_b.start_time).total_seconds()
        )

        return delta_seconds <= TEMPORAL_WINDOW_SECONDS

    @staticmethod
    def _evidence_values(
        correlation: Correlation,
        fields: tuple[str, ...],
    ) -> set[str]:
        """
        Extract and normalize the values of the given field names
        from a correlation's evidence dict. Missing or empty values
        are ignored.
        """

        evidence: dict[str, Any] = correlation.evidence or {}

        values: set[str] = set()

        for field_name in fields:
            value = evidence.get(field_name)

            if value:
                values.add(str(value).strip().lower())

        return values
