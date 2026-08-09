from __future__ import annotations

from modules.ioc.ioc_context import IOCExtractionContext
from modules.ioc.ioc_extractors.base import BaseIOCExtractor
from modules.ioc.ioc_extractors.patterns import (
    DOMAIN_RE,
    IPV4_RE,
    IPV6_RE,
    URL_RE,
    is_ipv4,
)
from modules.ioc.ioc_models import IOC, IOCType


class NetworkIOCExtractor(BaseIOCExtractor):
    """
    URLs, domains, and IP addresses found anywhere in text fields
    across the timeline: object_path, command_line, host_application,
    and every evidence value. Regex-based on purpose -- this is the
    one extractor whose job is to catch network indicators wherever
    they appear, not just in fields a specific artifact type names
    "url".
    """

    _TEXT_FIELDS = ("object_path", "object_name", "command_line", "host_application", "description")

    def extract(self, context: IOCExtractionContext) -> list[IOC]:
        iocs: list[IOC] = []

        for event in context.timeline:
            texts = self._collect_texts(event)
            for text in texts:
                iocs.extend(self._scan(text, event))

        return iocs

    @classmethod
    def _collect_texts(cls, event: dict) -> list[str]:
        texts = []
        for field_name in cls._TEXT_FIELDS:
            value = event.get(field_name)
            if isinstance(value, str) and value:
                texts.append(value)
        evidence = event.get("evidence") or {}
        for value in evidence.values():
            if isinstance(value, str) and value:
                texts.append(value)
        return texts

    @staticmethod
    def _scan(text: str, event: dict) -> list[IOC]:
        found: list[IOC] = []
        event_id = event.get("event_id")
        timestamp = event.get("timestamp")
        confidence = float(event.get("confidence", 0.5) or 0.5)
        artifact_type = str(event.get("artifact_type") or "unknown")

        def make(ioc_type: IOCType, value: str) -> IOC:
            return IOC(
                ioc_type=ioc_type,
                value=value,
                source_artifact=artifact_type,
                first_seen=timestamp,
                last_seen=timestamp,
                confidence=confidence,
                related_event_ids={event_id} if event_id else set(),
            )

        for match in URL_RE.findall(text):
            found.append(make(IOCType.URL, match.rstrip(").,;'\"")))

        for match in IPV4_RE.findall(text):
            found.append(make(IOCType.IPV4, match))

        for match in IPV6_RE.findall(text):
            # IPV6_RE deliberately over-matches slightly (see patterns.py);
            # reject anything that's actually a bare IPv4 or too short to
            # plausibly be an address.
            if is_ipv4(match) or match.count(":") < 2:
                continue
            found.append(make(IOCType.IPV6, match))

        for match in DOMAIN_RE.findall(text):
            if is_ipv4(match):
                continue
            found.append(make(IOCType.DOMAIN, match))

        return found