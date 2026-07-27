from __future__ import annotations

import hashlib

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation
from modules.correlation.rules.base import Rule,correlation_id
from modules.models.event_type import EventType
from modules.models.severity import Severity
from modules.normalizer.event import ensure_event_id


class BrowserActivityRule(Rule):
    """
    Surface raw browser activity: page visits and downloads.

    BrowserNormalizer emits EventType.URL_VISIT and EventType.FILE_DOWNLOAD.
    Both are handled by this single rule -- they're the same family of
    observation (what did the browser do), just two different actions.
    """

    NAME = "browser_activity"

    _TITLES = {
        EventType.URL_VISIT: "Browser page visit",
        EventType.FILE_DOWNLOAD: "Browser file download",
    }

    # LOW for both: visiting a page or downloading a file isn't inherently
    # suspicious (downloading Chrome isn't malware). Downloading an
    # executable that later gets run is the interesting signal -- that's
    # a future multi-event rule (browser -> prefetch/USN), not this one.
    _DESCRIPTIONS = {
        EventType.URL_VISIT: "Browser page visit observed.",
        EventType.FILE_DOWNLOAD: "Browser file download observed.",
    }

    def run(self, context: RuleContext) -> list[Correlation]:
        findings: list[Correlation] = []

        for event_context in context.timeline:
            event = event_context.event

            if event.get("artifact_type") != "browser":
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
            correlation_id=correlation_id(self.NAME, event_id),
            rule_name=self.NAME,
            title=self._TITLES[event["event_type"]],
            severity=Severity.LOW,
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