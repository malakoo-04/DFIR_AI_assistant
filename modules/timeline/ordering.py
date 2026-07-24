def _scalar(value) -> str:
    """Coerce an Enum member (or a plain value) into a plain string.

    event_type/category are EventType/EventCategory members; artifact_type
    is a plain string today. Handling both the same way means ordering
    doesn't depend on Enum.__str__, and stays correct if artifact_type ever
    becomes an enum too.
    """
    if value is None:
        return ""
    return value.value if hasattr(value, "value") else str(value)


def sort_key(event: dict, sequence: int) -> tuple:
    """Build a deterministic, total-order sort key for one timeline event.

    `object_name` can legitimately be None (e.g. USN events never set it),
    and comparing None to a string raises TypeError mid-sort in Python 3 —
    so it's coerced to "" here rather than compared as-is.

    `sequence` is this event's position among the events actually entering
    the timeline for this build() call. It's the final tie-breaker: if
    every other field is identical, ordering still falls back to something
    fixed for that run instead of to incidental iteration order.
    """

    return (
        event.get("timestamp"),
        _scalar(event.get("artifact_type")),
        _scalar(event.get("event_type")),
        event.get("object_name") or "",
        sequence,
    )


class _OrderedEvent:
    """Opaque, sortable wrapper pairing an event with its sort key."""

    __slots__ = ("key", "event")

    def __init__(self, event: dict, sequence: int):
        self.key = sort_key(event, sequence)
        self.event = event

    def __lt__(self, other):
        return self.key < other.key


def wrap(event: dict, sequence: int) -> _OrderedEvent:
    """Prepare one event for ordering. Call once per accepted event."""
    return _OrderedEvent(event, sequence)


def sort_events(wrapped_events) -> list[dict]:
    """Sort wrapped events and return plain events, in final timeline order."""
    return [item.event for item in sorted(wrapped_events)]