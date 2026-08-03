"""Serialized incidents -> deterministic processing order.

This module sits after ``IncidentSerializer`` and before any consumer
that has to decide *which* incident to look at first (today, that is
the LLM analysis loop):

    IncidentSerializer.serialize()
            v
    IncidentPrioritizer.prioritize()   <- this module
            v
    IncidentAnalysisAgent.analyze()  (one call per incident, in this order)

Why this exists
----------------
``IncidentSerializer.serialize()`` deliberately sorts its output by
``incident_id`` -- a content hash of the incident's correlation_ids --
so that the *exported* incident list is stable and reproducible
(same input, same JSON, byte for byte). That is the right behavior
for a deterministic export contract, and this module does not change
it.

But a hash has no relationship to forensic significance. Sorting by
hash means the first incident handed to a downstream consumer (for
example, the first incident sent to the LLM) is arbitrary with
respect to severity, confidence, or how much correlated evidence
supports it. On a dataset with hundreds of incidents, that means the
first (and, under a time budget, possibly *only*) incident actually
analyzed is essentially random.

What this module does -- and does not do
------------------------------------------
``IncidentPrioritizer`` re-orders an already-serialized incident list
using only fields the deterministic correlation engine already
computed and attached to each incident:

    - severity (already assigned by the correlation rules),
    - confidence (already computed by ``combine_confidence``),
    - number of correlations backing the incident (primary +
      supporting),
    - number of distinct timeline events involved.

It never opens a file, never inspects timeline event content, never
looks at filenames, and never assigns or changes severity/confidence
itself. It answers only "given the significance scores Python has
already computed, which incident should be looked at first?" -- an
operational triage/queue-ordering decision, not a forensic
classification one. That distinction matters: this module would be
out of bounds if it tried to guess *what an incident is* (ransomware,
persistence, etc.) from evidence; ranking already-computed severity
and confidence fields is not that.

This module consumes and returns the same plain-dict shape
``IncidentSerializer.serialize()`` produces -- it never touches
``IncidentCandidate`` or any other internal dataclass -- so it can be
inserted or removed from a pipeline without any other module knowing
it exists.
"""

from __future__ import annotations

# Severity is serialized as a lowercase string value (see
# modules.models.severity.Severity). This is the one ranking this
# module needs, from least to most severe.
_SEVERITY_RANK: dict[str, int] = {
    "low": 0,
    "medium": 1,
    "high": 2,
    "critical": 3,
}


class IncidentPrioritizer:
    """Order serialized incidents by already-computed significance fields.

    Consumes and returns ``list[dict]`` in the exact shape produced by
    ``IncidentSerializer.serialize()``. Performs no mutation of the
    incidents themselves -- it only returns a re-ordered list.
    """

    def prioritize(self, serialized_incidents: list[dict]) -> list[dict]:
        """Return ``serialized_incidents`` re-ordered from most to least

        significant, using, in order of precedence:

            1. severity (critical > high > medium > low),
            2. confidence (higher first),
            3. number of correlations backing the incident (primary +
               supporting, higher first),
            4. number of distinct timeline events involved (higher
               first),
            5. incident_id (ascending), as a final deterministic
               tie-break so equally-ranked incidents always sort the
               same way across runs.

        An empty input returns an empty list.
        """
        return sorted(
            serialized_incidents or [],
            key=self._sort_key,
        )

    @classmethod
    def _sort_key(cls, incident: dict) -> tuple:
        incident = incident or {}

        # Every component below is negated (or subtracted from zero)
        # so that a normal ascending sort yields "most significant
        # first" without needing reverse=True, which would also flip
        # the final incident_id tie-break (that one must stay
        # ascending for stable output).
        return (
            -cls._severity_rank(incident.get("severity")),
            -cls._confidence(incident.get("confidence")),
            -cls._correlation_count(incident),
            -cls._event_count(incident),
            str(incident.get("incident_id") or ""),
        )

    @staticmethod
    def _severity_rank(severity: str | None) -> int:
        return _SEVERITY_RANK.get(str(severity or "").lower(), -1)

    @staticmethod
    def _confidence(confidence: float | int | None) -> float:
        try:
            return float(confidence)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _correlation_count(incident: dict) -> int:
        primary = incident.get("primary_correlations") or []
        supporting = incident.get("supporting_correlations") or []
        return len(primary) + len(supporting)

    @staticmethod
    def _event_count(incident: dict) -> int:
        events = incident.get("events") or []
        return len(events)
