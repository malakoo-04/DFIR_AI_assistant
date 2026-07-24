from __future__ import annotations

import hashlib

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation
from modules.correlation.rules.base import Rule
from modules.models.event_type import EventType
from modules.models.severity import Severity
from modules.normalizer.event import ensure_event_id


class RegistryPersistenceRule(Rule):
    """
    Did we observe persistence through Registry Run / RunOnce / Services?

    The Registry normalizer already tags these as EventType.PERSISTENCE
    (Run, RunOnce) and EventType.SERVICE_CREATED (Services\\<name>) with
    category=PERSISTENCE, so this rule doesn't re-derive anything from
    key_path -- it only selects those two event types and reports what
    the timeline already shows. No cross-artifact identity is required:
    each Registry event stands on its own here.
    """

    NAME = "registry_persistence"

    _TITLES = {
        EventType.PERSISTENCE: "Registry Run/RunOnce persistence",
        EventType.SERVICE_CREATED: "Windows service persistence",
    }

    # Finding-level description, deliberately distinct from
    # event["description"]: the event describes what was found in the
    # registry (e.g. "Registry Run key: OneDrive"), the correlation
    # describes the forensic behavior observed (persistence). Behavior
    # Detection is what will later decide whether that's suspicious.
    _DESCRIPTIONS = {
        EventType.PERSISTENCE: "Registry persistence mechanism observed.",
        EventType.SERVICE_CREATED: "Windows service persistence observed.",
    }

    def run(self, context: RuleContext) -> list[Correlation]:
        findings: list[Correlation] = []

        for event_context in context.timeline:
            event = event_context.event

            if event.get("artifact_type") != "registry":
                continue

            event_type = event.get("event_type")

            if event_type not in self._TITLES:
                continue

            findings.append(self._to_correlation(event, event_context.entity_id))

        return findings

    def _to_correlation(self, event: dict, entity_id: str | None) -> Correlation:
        event_id = ensure_event_id(event)
        timestamp = event["timestamp"]
        evidence = dict(event.get("evidence") or {})

        return Correlation(
            correlation_id=self._correlation_id(event_id),
            rule_name=self.NAME,
            title=self._TITLES[event["event_type"]],
            # A Run key or a new service is not inherently suspicious --
            # OneDrive, Steam, Discord, Defender all do this. This rule
            # only reports that persistence was observed; deciding
            # whether it's suspicious (unsigned binary, temp folder,
            # unusual name...) is Behavior Detection's job downstream,
            # not this rule's.
            severity=Severity.LOW,
            # Reuse the normalizer's own confidence rather than
            # re-deriving one here -- this rule only observes.
            confidence=event.get("confidence", 1.0),
            start_time=timestamp,
            end_time=timestamp,
            event_ids=[event_id],
            entity_ids=[entity_id] if entity_id else [],
            description=self._DESCRIPTIONS[event["event_type"]],
            evidence=evidence,
        )

    def _correlation_id(self, event_id: str) -> str:
        """Deterministic id: same rule + same event always yields the
        same correlation_id, so re-running the pipeline is stable."""
        digest = hashlib.sha256(f"{self.NAME}|{event_id}".encode("utf-8"))
        return digest.hexdigest()
