from __future__ import annotations

import hashlib

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation
from modules.correlation.rules.base import Rule,correlation_id
from modules.models.event_type import EventType
from modules.models.severity import Severity
from modules.normalizer.event import ensure_event_id


class USBConnectionRule(Rule):
    """
    Did we observe USB storage device history (USBSTOR)?

    RegistryNormalizer._normalize_usbstor tags this as
    EventType.USB_DEVICE_CONNECTED with category=DEVICE, and promotes the
    device identity (serial_number, device_instance_id, vendor, product)
    as top-level event fields rather than into event["evidence"] -- this
    rule folds them into the correlation's own evidence so the finding is
    self-contained without requiring a lookup into raw_data.

    Naming note: USBSTOR is historical presence evidence (the registry key
    was last written at `timestamp`), not proof of a live connection at
    that exact moment -- "connected" would overstate what this artifact
    actually shows, hence "observed"/"recorded" throughout.
    """

    NAME = "usb_connection"

    _TITLE = "USB storage device observed"

    # LOW: USBSTOR history isn't inherently malicious on its own. This only
    # becomes interesting once correlated with what happens next (Explorer
    # access, a file copied from it, something launched from it) -- a
    # future multi-event rule, not this one.
    _DESCRIPTION = (
        "USB storage device presence recorded in USBSTOR "
        "(registry key last-write time, not a live connection timestamp)."
    )

    def run(self, context: RuleContext) -> list[Correlation]:
        findings: list[Correlation] = []

        for event_context in context.timeline:
            event = event_context.event

            if event.get("artifact_type") != "registry":
                continue

            if event.get("event_type") != EventType.USB_DEVICE_CONNECTED:
                continue

            findings.append(self._to_correlation(event, event_context.entity_id))

        return findings

    def _to_correlation(self, event: dict, entity_id: str | None) -> Correlation:
        event_id = ensure_event_id(event)
        timestamp = event["timestamp"]

        evidence = dict(event.get("evidence") or {})
        for key in (
            "vendor",
            "product",
            "serial_number",
            "device_instance_id",
            "friendly_name",
        ):
            value = event.get(key)
            if value is not None:
                evidence[key] = value

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