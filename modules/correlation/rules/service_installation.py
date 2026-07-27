from __future__ import annotations

import hashlib

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation
from modules.correlation.rules.base import Rule,correlation_id
from modules.models.event_type import EventType
from modules.models.severity import Severity
from modules.normalizer.event import ensure_event_id


class ServiceInstallationRule(Rule):
    """
    Did an EVTX Event ID 7045 (a new Windows service being installed)
    occur? EVTXNormalizer already tags this as EventType.SERVICE_INSTALL
    with category=PERSISTENCE.

    Kept separate from RegistryPersistenceRule's EventType.SERVICE_CREATED:
    that one comes from a Services\\<name> registry key (post-install
    configuration state), this one is the live SCM installation event
    itself (event log evidence of the install action happening at a
    specific moment) -- two different artifacts, two different kinds of
    evidence for what can be the same underlying service.
    """

    NAME = "service_installation"

    _TITLE = "Windows service installed (Event ID 7045)"

    # Same "observation only" stance as the other persistence rules here:
    # legitimate software installs new services constantly. Kept at LOW
    # for consistency with RegistryPersistenceRule/ScheduledTaskPersistenceRule
    # rather than judging this one more severe on its own -- open to
    # revisiting if you'd rather rank a live install event higher than a
    # static persistence artifact.
    _DESCRIPTION = "Windows service installation observed (System log, Event ID 7045)."

    def run(self, context: RuleContext) -> list[Correlation]:
        findings: list[Correlation] = []

        for event_context in context.timeline:
            event = event_context.event

            if event.get("artifact_type") != "evtx":
                continue

            if event.get("event_type") != EventType.SERVICE_INSTALL:
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
            severity=Severity.LOW,
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