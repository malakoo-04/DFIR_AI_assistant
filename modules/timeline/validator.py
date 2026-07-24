from modules.timeline.timestamps import coerce_timestamp
from datetime import datetime

REQUIRED_FIELDS = ("artifact_type", "event_type", "category")


def validate(event: dict) -> tuple[bool, 'datetime | None', str | None]:
    """Return (is_valid, canonical_timestamp, reason).

    `canonical_timestamp` is populated only when `is_valid` is True — it's
    the already-coerced value, so builder.py never has to call
    coerce_timestamp() a second time on the same raw input.
    `reason` is populated only when `is_valid` is False.
    """

    if not isinstance(event, dict):
        return False, None, "not_a_dict"

    for field in REQUIRED_FIELDS:
        if not event.get(field):
            return False, None, f"missing_{field}"

    evidence = event.get("evidence")
    if evidence is not None and not isinstance(evidence, dict):
        # Every normalizer now follows create_event()'s dict-only evidence
        # contract. A non-dict here means a normalizer regressed or a new
        # one wasn't written to the contract — worth rejecting loudly.
        return False, None, "evidence_not_a_dict"

    if event.get("timestamp") is None:
        return False, None, "missing_timestamp"

    canonical_timestamp = coerce_timestamp(event.get("timestamp"))
    if canonical_timestamp is None:
        return False, None, "invalid_timestamp"

    return True, canonical_timestamp, None