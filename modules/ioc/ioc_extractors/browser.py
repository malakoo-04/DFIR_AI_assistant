from __future__ import annotations

from modules.ioc.ioc_context import IOCExtractionContext
from modules.ioc.ioc_extractors.base import BaseIOCExtractor
from modules.ioc.ioc_models import IOC, IOCType


class BrowserIOCExtractor(BaseIOCExtractor):
    """
    Browser-native IOCs: visited URLs and downloaded files, tagged with
    their real browser provenance (browser name, referrer) rather than
    relying on network.py's generic regex scan alone. Overlaps with
    network.py/files.py by design -- IOCExtractor's dedup step merges
    the results, it doesn't matter which extractor found a given value
    first.
    """

    def extract(self, context: IOCExtractionContext) -> list[IOC]:
        iocs: list[IOC] = []

        for event in context.timeline:
            if event.get("artifact_type") != "browser":
                continue

            event_id = event.get("event_id")
            timestamp = event.get("timestamp")
            confidence = float(event.get("confidence", 0.5) or 0.5)
            evidence = event.get("evidence") or {}

            if event.get("event_type") == "url_visit" and event.get("object_path"):
                iocs.append(
                    IOC(
                        ioc_type=IOCType.URL,
                        value=event["object_path"],
                        source_artifact="browser",
                        first_seen=timestamp,
                        last_seen=timestamp,
                        confidence=confidence,
                        related_event_ids={event_id} if event_id else set(),
                        supporting_evidence=[str(evidence.get("browser") or "")] if evidence.get("browser") else [],
                    )
                )

            if event.get("event_type") == "file_download" and event.get("object_path"):
                iocs.append(
                    IOC(
                        ioc_type=IOCType.DROPPED_FILE,
                        value=event["object_path"],
                        source_artifact="browser",
                        first_seen=timestamp,
                        last_seen=timestamp,
                        confidence=confidence,
                        related_event_ids={event_id} if event_id else set(),
                        supporting_evidence=[f"referrer: {evidence['referrer']}"] if evidence.get("referrer") else [],
                    )
                )
                referrer = evidence.get("referrer")
                if isinstance(referrer, str) and referrer.startswith(("http://", "https://")):
                    iocs.append(
                        IOC(
                            ioc_type=IOCType.URL,
                            value=referrer,
                            source_artifact="browser",
                            first_seen=timestamp,
                            last_seen=timestamp,
                            confidence=confidence,
                            related_event_ids={event_id} if event_id else set(),
                        )
                    )

        return iocs