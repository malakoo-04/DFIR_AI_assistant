from __future__ import annotations

import hashlib

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation
from modules.correlation.rules.base import Rule,correlation_id
from modules.models.event_type import EventType
from modules.models.severity import Severity
from modules.normalizer.event import ensure_event_id


class DefenderDetectionRule(Rule):
    """
    Did Windows Defender itself flag something as malicious?

    Deliberately scoped to EventType.MALWARE_DETECTION only -- not the
    other Defender event types (service started/stopped, scans, config
    changes, platform updates), which are operational telemetry, not
    detections. Those could become a separate "Defender activity" rule
    later if useful; this one stays narrow on purpose.
    """

    NAME = "defender_detection"

    _TITLE = "Windows Defender detection"

    # Unlike the persistence rules above, this isn't "observation only":
    # DefenderNormalizer only routes to MALWARE_DETECTION when the raw
    # message already contains threat/malware/quarantine/blocked/infected
    # keywords -- Defender has already made the classification judgment
    # here, this rule just surfaces it. HIGH reflects that distinction.
    _DESCRIPTION = "Windows Defender reported a threat detection."

    def run(self, context: RuleContext) -> list[Correlation]:
        findings: list[Correlation] = []

        for event_context in context.timeline:
            event = event_context.event

            if event.get("artifact_type") != "defender":
                continue

            if event.get("event_type") != EventType.MALWARE_DETECTION:
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