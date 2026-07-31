"""Full forensic timeline -> per-incident timeline slice.

This module exists to fix a specific, measured failure: sending the
entire investigation's timeline to the model once per incident. On a
real dataset this measured out to 359,795 timeline events sent
unchanged for each of 575 incidents, producing prompts on the order of
hundreds of millions of characters -- far beyond any local model's
context window, and the direct cause of the backend's "tokenize error"
HTTP 500.

The fix is not a bigger context window or a smaller model -- it is
giving the model only what a human DFIR analyst would read when
investigating one incident: the events that belong to *that* incident,
not the entire machine's history.

    Correlation Engine
            v
    Incident Graph Builder
            v
    Incident Builder
            v
    Incident Enricher
            v
    Incident Serializer
            v
    IncidentTimelineExtractor      <- this module
            v
    IncidentAnalysisPromptBuilder / IncidentAnalysisAgent

This module performs no forensic reasoning. It does not decide which
events matter -- that decision was already made deterministically
upstream (by the correlation rules and IncidentCandidateBuilder /
IncidentGraphBuilder) and is recorded in
``serialized_incident["events"]``, the sorted list of event IDs
IncidentSerializer already assigned to this incident. This module only
performs a lookup against that list: select the matching events out of
the full timeline, in their original order. It creates no new events,
merges nothing, and re-derives no relationships.
"""

from __future__ import annotations


class IncidentTimelineExtractor:
    """
    Reduce the full forensic timeline down to the events belonging to
    one incident.

    Given ``serialized_incident`` (one payload from
    ``IncidentSerializer.serialize()``) and the full ``timeline`` (from
    ``TimelineBuilder.build()``), return only the timeline events whose
    ``event_id`` is listed in that incident's ``events`` field --
    nothing added, nothing re-ordered relative to the source timeline,
    nothing reasoned about.
    """

    def extract(self, serialized_incident: dict, timeline: list[dict]) -> list[dict]:
        """
        Parameters
        ----------
        serialized_incident:
            One incident payload as produced by
            ``IncidentSerializer.serialize()``. Only its ``events``
            field (a list of event_id strings) is used.
        timeline:
            The full forensic timeline, as produced by
            ``TimelineBuilder.build()``.

        Returns
        -------
        The subset of `timeline` whose `event_id` appears in
        `serialized_incident["events"]`, preserving the order they
        already had in `timeline` (TimelineBuilder's chronological
        ordering is never re-derived or re-sorted here). An incident
        with no recorded event IDs returns an empty list rather than
        the full timeline -- silently falling back to "everything"
        would reintroduce the exact bug this module exists to fix.
        """

        incident_event_ids = set((serialized_incident or {}).get("events") or [])

        if not incident_event_ids:
            return []

        return [
            event
            for event in (timeline or [])
            if (event or {}).get("event_id") in incident_event_ids
        ]
