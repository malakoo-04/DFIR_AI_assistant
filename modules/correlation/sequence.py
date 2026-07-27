"""Shared temporal correlation primitive for multi-event rules.

Not a rule base class (see the earlier decision against SingleEventRule)
-- this is a matching *operation*, the same category of shared code as
ContextBuilder's indexes, not a shape rules are forced to inherit. Any
multi-event rule needing "did an event of some kind follow this one,
plausibly about the same object, within a time window" can call this
instead of re-implementing windowed matching from scratch.
"""

from __future__ import annotations

from datetime import timedelta


def best_effort_identity(event: dict) -> str | None:
    """A same-file heuristic usable even where identity_keys hasn't been
    enriched yet for the artifacts involved.

    Intentionally the same weak-fallback shape as EntityResolver's own
    fallback_object:<artifact_type> key: it under-matches (two different
    "update.exe" won't fuse) rather than over-matches, the safer failure
    mode for a forensic tool. Prefer passing same_entity_id to find_after
    when it's available -- this is only the fallback.
    """
    value = event.get("object_name") or event.get("object_path")
    if not value:
        return None
    return str(value).strip().lower().rsplit("\\", 1)[-1]


def find_after(
    anchor_event: dict,
    candidates: list[dict],
    *,
    within: timedelta,
    same_entity_id: str | None = None,
    candidate_entity_ids: dict[str, str] | None = None,
) -> dict | None:
    """Return the earliest candidate at/after anchor_event's timestamp,
    within `within`, that plausibly refers to the same object.

    Prefers an entity_id match (strong, exact) over a filename match
    (weak, best-effort). `candidate_entity_ids` maps event_id -> entity_id
    -- callers build it from EventContext.entity_id so this function stays
    a pure list/dict operation with no dependency on ContextBuilder.
    """

    anchor_time = anchor_event.get("timestamp")
    if anchor_time is None:
        return None

    anchor_key = best_effort_identity(anchor_event)
    candidate_entity_ids = candidate_entity_ids or {}

    best: dict | None = None
    best_time = None

    for candidate in candidates:
        candidate_time = candidate.get("timestamp")
        if candidate_time is None:
            continue
        if not (anchor_time <= candidate_time <= anchor_time + within):
            continue

        candidate_entity_id = candidate_entity_ids.get(candidate.get("event_id"))

        matched = (
            (same_entity_id and candidate_entity_id == same_entity_id)
            or (anchor_key and best_effort_identity(candidate) == anchor_key)
        )
        if not matched:
            continue

        if best_time is None or candidate_time < best_time:
            best, best_time = candidate, candidate_time

    return best


def combine_confidence(*confidences: float) -> float:
    """Weakest-link confidence for a chain of AND-composed evidence: a
    multi-event finding is only as trustworthy as its least certain step.
    Simple and conservative on purpose -- revisit if a rule needs a
    genuinely different composition (e.g. reinforcing evidence)."""
    values = [c for c in confidences if c is not None]
    return min(values) if values else 1.0