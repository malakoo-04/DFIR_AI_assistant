from __future__ import annotations

import hashlib

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation
from modules.correlation.rules.base import Rule,correlation_id
from modules.models.event_type import EventType
from modules.models.severity import Severity
from modules.normalizer.event import ensure_event_id


class ScheduledTaskPersistenceRule(Rule):
    """
    Did we observe persistence through a Windows Scheduled Task?

    ScheduledTaskNormalizer tags every task as EventType.PERSISTENCE with
    category=PERSISTENCE -- the same EventType value RegistryPersistenceRule
    matches for Run/RunOnce keys. artifact_type is checked first for that
    reason: without it, this rule would also pick up Registry persistence
    events, and RegistryPersistenceRule would double-count Scheduled Task
    events. Each rule owns exactly one artifact_type.
    """

    NAME = "scheduled_task_persistence"

    _TITLE = "Scheduled Task persistence"

    # Same reasoning as RegistryPersistenceRule: a scheduled task is not
    # inherently suspicious (Windows Update, backup software, and most
    # legitimate installers register one) -- this rule only reports that
    # persistence was observed. Behavior Detection decides what's suspicious.
    _DESCRIPTION = "Scheduled Task persistence mechanism observed."

    def run(self, context: RuleContext) -> list[Correlation]:
        findings: list[Correlation] = []

        for event_context in context.timeline:
            event = event_context.event

            if event.get("artifact_type") != "scheduled_task":
                continue

            if event.get("event_type") != EventType.PERSISTENCE:
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