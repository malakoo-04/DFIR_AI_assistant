from __future__ import annotations

import hashlib

from modules.correlation.graph import UnionFind
from modules.correlation.incident_models import GraphEdge, IncidentCandidate
from modules.correlation.models import Correlation
from modules.correlation.sequence import combine_confidence
from modules.models.severity import Severity
from datetime import datetime

# Severity is a plain str Enum (not an IntEnum), so it has no intrinsic
# ordering. This module owns the one ranking it needs -- from least to
# most severe -- to compute the maximum severity across a cluster.
_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


class IncidentCandidateBuilder:
    """
    Turn a weighted correlation graph into IncidentCandidate objects.

    This class consumes a graph that has already been built -- it never
    computes scores, inspects evidence, or reconstructs edges. Its only
    job is: cluster correlation_ids using the existing generic
    UnionFind, then materialize one IncidentCandidate per connected
    component.
    """

    def __init__(self) -> None:
        pass

    def build(
        self,
        correlations: list[Correlation],
        graph_edges: list[GraphEdge],
    ) -> list[IncidentCandidate]:
        """
        Cluster correlations by graph connectivity and return one
        IncidentCandidate per connected component.
        """

        by_id = {correlation.correlation_id: correlation for correlation in correlations}

        clusters = self._build_clusters(correlations, graph_edges)

        incidents = [
            self._build_incident(cluster_ids, by_id, graph_edges)
            for cluster_ids in clusters
        ]

        return sorted(incidents, key=lambda incident: incident.incident_id)

    def _build_incident(
        self,
        cluster_ids: list[str],
        by_id: dict[str, Correlation],
        graph_edges: list[GraphEdge],
    ) -> IncidentCandidate:
        """
        Build a single IncidentCandidate from one connected component.
        """

        cluster_correlations = [by_id[correlation_id] for correlation_id in cluster_ids]
        cluster_id_set = set(cluster_ids)

        start_time, end_time = self._compute_time_bounds(cluster_correlations)

        return IncidentCandidate(
            incident_id=self._generate_incident_id(cluster_ids),
            start_time=start_time,
            end_time=end_time,
            severity=self._compute_severity(cluster_correlations),
            confidence=self._confidence(cluster_correlations),
            correlation_ids=sorted(cluster_ids),
            supporting_correlation_ids=[],
            entity_ids=self._collect_entity_ids(cluster_correlations),
            event_ids=self._collect_event_ids(cluster_correlations),
            rule_names=self._collect_rule_names(cluster_correlations),
            graph_edges=self._collect_graph_edges(graph_edges, cluster_id_set),
            related_incident_ids=[],
        )

    @staticmethod
    def _build_clusters(
        correlations: list[Correlation],
        graph_edges: list[GraphEdge],
    ) -> list[list[str]]:
        """
        Partition correlation_ids into connected components using the
        existing generic UnionFind. Every correlation becomes a node,
        even one with no edges -- it simply ends up alone in its own
        cluster.
        """

        union_find: UnionFind[str] = UnionFind()

        for correlation in correlations:
            union_find.make_set(correlation.correlation_id)

        for edge in graph_edges:
            union_find.union(edge.source_correlation_id, edge.target_correlation_id)

        groups: dict[str, list[str]] = {}

        for correlation in correlations:
            root = union_find.find(correlation.correlation_id)
            groups.setdefault(root, []).append(correlation.correlation_id)

        return list(groups.values())

    @staticmethod
    def _generate_incident_id(correlation_ids: list[str]) -> str:
        """
        Generate a deterministic incident identifier from the sorted
        correlation_ids making up the cluster.
        """

        joined = "|".join(sorted(correlation_ids))

        return hashlib.sha256(joined.encode("utf-8")).hexdigest()

    @staticmethod
    def _collect_entity_ids(cluster_correlations: list[Correlation]) -> list[str]:
        """
        Return the sorted, de-duplicated union of entity_ids across
        the cluster.
        """

        entity_ids: set[str] = set()

        for correlation in cluster_correlations:
            entity_ids.update(correlation.entity_ids)

        return sorted(entity_ids)

    @staticmethod
    def _collect_event_ids(cluster_correlations: list[Correlation]) -> list[str]:
        """
        Return the sorted, de-duplicated union of event_ids across
        the cluster.
        """

        event_ids: set[str] = set()

        for correlation in cluster_correlations:
            event_ids.update(correlation.event_ids)

        return sorted(event_ids)

    @staticmethod
    def _collect_rule_names(cluster_correlations: list[Correlation]) -> list[str]:
        """
        Return the sorted, de-duplicated set of rule names that fired
        within the cluster.
        """

        rule_names = {correlation.rule_name for correlation in cluster_correlations}

        return sorted(rule_names)

    @staticmethod
    def _compute_time_bounds(
        cluster_correlations: list[Correlation],
    ) -> tuple[datetime, datetime]:
        """
        Return (earliest start_time, latest end_time) across the
        cluster.
        """

        start_time = min(correlation.start_time for correlation in cluster_correlations)
        end_time = max(correlation.end_time for correlation in cluster_correlations)

        return start_time, end_time

    @staticmethod
    def _compute_severity(cluster_correlations: list[Correlation]) -> Severity:
        """
        Return the highest severity among the cluster, using this
        module's explicit severity ranking.
        """

        return max(
            (correlation.severity for correlation in cluster_correlations),
            key=_SEVERITY_ORDER.index,
        )

    @staticmethod
    def _confidence(cluster_correlations: list[Correlation]) -> float:
        """
        Aggregate confidence for the incident candidate.

        Reuses the existing combine_confidence() helper (already used
        by multi-event correlation rules): weakest-link composition,
        since an incident is only as trustworthy as its least certain
        constituent correlation. No separate aggregation strategy is
        introduced here.
        """

        return combine_confidence(
            *(correlation.confidence for correlation in cluster_correlations)
        )

    @staticmethod
    def _collect_graph_edges(
        graph_edges: list[GraphEdge],
        cluster_id_set: set[str],
    ) -> list[GraphEdge]:
        """
        Return only the GraphEdge objects whose source and target both
        belong to this cluster.
        """

        return [
            edge
            for edge in graph_edges
            if edge.source_correlation_id in cluster_id_set
            and edge.target_correlation_id in cluster_id_set
        ]
