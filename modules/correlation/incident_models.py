from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from modules.models.severity import Severity


@dataclass(slots=True)
class GraphEdge:
    """
    A weighted edge linking two correlations that are believed
    to belong to the same incident.
    """

    source_correlation_id: str
    target_correlation_id: str
    score: int

    matched_criteria: list[str] = field(default_factory=list)


@dataclass(slots=True)
class IncidentCandidate:
    """
    A candidate grouping of correlations that may represent
    a single incident.
    """

    incident_id: str

    start_time: datetime
    end_time: datetime

    severity: Severity
    confidence: float

    correlation_ids: list[str] = field(default_factory=list)
    supporting_correlation_ids: list[str] = field(default_factory=list)

    entity_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)

    rule_names: list[str] = field(default_factory=list)

    graph_edges: list[GraphEdge] = field(default_factory=list)

    related_incident_ids: list[str] = field(default_factory=list)
