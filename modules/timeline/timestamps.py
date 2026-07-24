from datetime import datetime, timezone
"""Canonical timestamp handling for the timeline stage.

Every timeline event must expose a single "timestamp" field in the same
canonical form before it can be validated, ordered, or exported. Normalizers
may hand this stage either a native datetime (aware or naive) or an ISO-8601
string — the latter matters once something reloads normalized_events.json
from disk (a future correlation re-run) instead of receiving events
in-memory from the same pipeline run.

This module doesn't implement the coercion itself: it delegates to
TimeUtils.coerce_timestamp, the same implementation used by
modules.normalizer.event for event_id hashing, so there's exactly one
definition of "canonical UTC timestamp" across the whole pipeline instead
of two copies that could silently drift apart.
"""

from modules.utils.time_utils import TimeUtils

coerce_timestamp = TimeUtils.coerce_timestamp

def coerce_timestamp(value):
    """Coerce a raw event timestamp into a naive UTC datetime.

    Named "coerce" rather than "normalize" deliberately: this doesn't just
    adjust an already-datetime value, it accepts several different input
    representations (string, aware datetime, naive datetime) and forces
    them all into one canonical type and form.

    Returns None if `value` is missing or cannot be coerced. This function
    never raises and never logs — the caller decides how a rejected
    timestamp should be counted or reported.
    """

    if value is None:
        return None

    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return None

    if not isinstance(value, datetime):
        return None

    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)

    return value