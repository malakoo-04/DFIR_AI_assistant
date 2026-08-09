from __future__ import annotations

from modules.ioc.ioc_context import IOCExtractionContext
from modules.ioc.ioc_extractors.base import BaseIOCExtractor
from modules.ioc.ioc_extractors.patterns import MD5_RE, SHA1_RE, SHA256_RE
from modules.ioc.ioc_models import IOC, IOCType


class HashIOCExtractor(BaseIOCExtractor):
    """
    File hashes. Two sources: Amcache's own sha1 field (promoted to a
    top-level event field by AmcacheNormalizer), and a regex fallback
    over evidence values for any MD5/SHA1/SHA256-shaped hex string
    another artifact type might carry (e.g. Defender detection logs).
    """

    def extract(self, context: IOCExtractionContext) -> list[IOC]:
        iocs: list[IOC] = []

        for event in context.timeline:
            sha1 = event.get("sha1")
            if sha1 and isinstance(sha1, str) and SHA1_RE.fullmatch(sha1):
                iocs.append(
                    IOC(
                        ioc_type=IOCType.HASH_SHA1,
                        value=sha1,
                        source_artifact=str(event.get("artifact_type") or "amcache"),
                        first_seen=event.get("timestamp"),
                        last_seen=event.get("timestamp"),
                        confidence=float(event.get("confidence", 0.5) or 0.5),
                        related_event_ids={event["event_id"]} if event.get("event_id") else set(),
                        supporting_evidence=[str(event.get("object_name") or "")] if event.get("object_name") else [],
                    )
                )

            iocs.extend(self._scan_evidence(event))

        return iocs

    @staticmethod
    def _scan_evidence(event: dict) -> list[IOC]:
        found: list[IOC] = []
        evidence = event.get("evidence") or {}
        event_id = event.get("event_id")
        timestamp = event.get("timestamp")
        confidence = float(event.get("confidence", 0.5) or 0.5)
        artifact_type = str(event.get("artifact_type") or "unknown")

        for value in evidence.values():
            if not isinstance(value, str):
                continue

            # Longest pattern first: a 64-hex string also satisfies the
            # 32/40-char patterns as a substring, so order avoids
            # mis-tagging a SHA256 fragment as an MD5/SHA1.
            for pattern, ioc_type in (
                (SHA256_RE, IOCType.HASH_SHA256),
                (SHA1_RE, IOCType.HASH_SHA1),
                (MD5_RE, IOCType.HASH_MD5),
            ):
                match = pattern.fullmatch(value.strip())
                if match:
                    found.append(
                        IOC(
                            ioc_type=ioc_type,
                            value=value.strip(),
                            source_artifact=artifact_type,
                            first_seen=timestamp,
                            last_seen=timestamp,
                            confidence=confidence,
                            related_event_ids={event_id} if event_id else set(),
                        )
                    )
                    break

        return found