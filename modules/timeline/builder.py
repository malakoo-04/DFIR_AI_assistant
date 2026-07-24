from modules.timeline import ordering, validator

DEFAULT_TIMELINE_ELIGIBLE = True


class TimelineBuilder:
    """Turns validated, normalized events into a deterministic timeline.

    Deliberately does nothing beyond: validate -> normalize timestamps ->
    filter -> sort. No correlation, merging, persistence detection, process
    chaining, MITRE mapping, or attack inference happens here — that is the
    Correlation Engine's job, built on top of this output.
    """

    def __init__(self):
        self.last_report = None

    def build(self, events: list[dict]) -> list[dict]:
        """Build the timeline. Public API: build(events) -> list[dict].

        Run statistics (input/skip/output counts by exact reason, plus a
        bounded sample of skipped events per reason) are available
        afterward via `self.last_report`, rather than changing this
        method's return type.
        """

        report = self._new_report(len(events))
        prepared = []

        for index, event in enumerate(events):
            wrapped = self._accept(event, index, report)
            if wrapped is not None:
                prepared.append(wrapped)

        timeline = ordering.sort_events(prepared)

        report["timeline_events"] = len(timeline)
        self.last_report = report

        return timeline

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _accept(self, event: dict, index: int, report: dict):
        """Validate + filter one event. Returns a wrapped ordering entry,
        or None if the event was rejected (already recorded in `report`)."""

        is_valid, canonical_timestamp, reason = validator.validate(event)
        if not is_valid:
            self._record_skip(report, reason, event)
            return None

        # Keep compact metadata (for example, aggregated USN writes) in
        # normalized output for correlation without flooding the timeline.
        if not event.get("timeline_eligible", DEFAULT_TIMELINE_ELIGIBLE):
            self._record_skip(report, "timeline_eligible_false", event)
            return None

        prepared_event = {**event, "timestamp": canonical_timestamp}
        return ordering.wrap(prepared_event, index)

    @staticmethod
    def _new_report(input_count: int) -> dict:
        return {
            "input_events": input_count,
            "timeline_events": 0,
            # Keyed by the exact reason string from validator.validate()
            # (or "timeline_eligible_false"), e.g.:
            # {"invalid_timestamp": 14, "missing_category": 1, ...}
            "skipped_by_reason": {},
            "skipped_samples": {},
        }

    @staticmethod
    def _record_skip(
        report: dict, reason: str, event, limit: int = 20
    ) -> None:
        report["skipped_by_reason"][reason] = (
            report["skipped_by_reason"].get(reason, 0) + 1
        )

        samples = report["skipped_samples"].setdefault(reason, [])
        if len(samples) < limit:
            samples.append({
                "artifact_type": event.get("artifact_type") if isinstance(event, dict) else None,
                "event_type": event.get("event_type") if isinstance(event, dict) else None,
                "source_file": event.get("source_file") if isinstance(event, dict) else None,
            })