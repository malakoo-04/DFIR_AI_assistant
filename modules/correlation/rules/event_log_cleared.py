from __future__ import annotations

import hashlib

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation
from modules.correlation.rules.base import Rule, correlation_id
from modules.models.event_type import EventType
from modules.models.severity import Severity
from modules.normalizer.event import ensure_event_id


class EventLogClearedRule(Rule):
    """
    Was a Windows event log cleared (Event ID 1102)?

    EVTXNormalizer tags this as EventType.LOG_CLEARED with category=SYSTEM.
    """

    NAME = "event_log_cleared"

    _TITLE = "Windows event log cleared"

    # HIGH, not LOW like the persistence rules: clearing an event log is
    # anti-forensic behavior almost by definition -- unlike a Run key or a
    # new service, there's very little legitimate day-to-day reason for it
    # outside of deliberate retention/maintenance, and in an IR context it
    # is itself evidence of an attempt to cover tracks.
    _DESCRIPTION = "A Windows event log was cleared -- possible anti-forensic activity."

    def run(self, context: RuleContext) -> list[Correlation]:
        findings: list[Correlation] = []

        for event_context in context.timeline:
            event = event_context.event

            if event.get("artifact_type") != "evtx":
                continue

            if event.get("event_type") != EventType.LOG_CLEARED:
                continue

            findings.append(self._to_correlation(event, event_context.entity_id))

        return findings

    def _to_correlation(self, event: dict, entity_id: str | None) -> Correlation:
        event_id = ensure_event_id(event)
        timestamp = event["timestamp"]
        evidence = dict(event.get("evidence") or {})

        return Correlation(
            correlation_id=correlation_id(self.NAME, event_id),
            rule_name=self.NAME,
            title=self._TITLE,
            severity=Severity.HIGH,
            confidence=event.get("confidence", 1.0),
            start_time=timestamp,
            end_time=timestamp,
            event_ids=[event_id],
            entity_ids=[entity_id] if entity_id else [],
            description=self._DESCRIPTION,
            evidence=evidence,
        )

    def _correlation_id(self, event_id: str) -> str:
        """Deterministic id: same rule + same event always yields the
        same correlation_id, so re-running the pipeline is stable."""
        digest = hashlib.sha256(f"{self.NAME}|{event_id}".encode("utf-8"))
        return digest.hexdigest()