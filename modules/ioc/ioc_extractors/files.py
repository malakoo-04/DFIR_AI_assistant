from __future__ import annotations

from modules.ioc.ioc_context import IOCExtractionContext
from modules.ioc.ioc_extractors.base import BaseIOCExtractor
from modules.ioc.ioc_extractors.patterns import (
    EXECUTABLE_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    UNC_PATH_RE,
)
from modules.ioc.ioc_models import IOC, IOCType


class FileIOCExtractor(BaseIOCExtractor):
    """
    Files, directories, executables, and dropped/downloaded files,
    from every event's own object_path -- not limited to events a
    correlation rule already flagged, since IOC extraction is meant
    to cover the whole normalized dataset.
    """

    def extract(self, context: IOCExtractionContext) -> list[IOC]:
        iocs: list[IOC] = []

        for event in context.timeline:
            path = event.get("object_path")
            if not path or not isinstance(path, str):
                continue
            if "\\" not in path and "/" not in path:
                # Not a filesystem-shaped value (e.g. a browser URL
                # already lives in object_path too -- handled by
                # browser.py/network.py, not here).
                continue
            if path.lower().startswith(("http://", "https://")):
                continue

            iocs.append(self._classify(path, event, context))

        return iocs

    @staticmethod
    def _classify(path: str, event: dict, context: IOCExtractionContext) -> IOC:
        lower = path.lower()
        suffix = "." + lower.rsplit(".", 1)[-1] if "." in lower.rsplit("\\", 1)[-1] else ""

        if UNC_PATH_RE.match(path):
            ioc_type = IOCType.UNC_PATH
        elif (
            event.get("artifact_type") == "browser"
            and event.get("event_type") == "file_download"
        ):
            ioc_type = IOCType.DROPPED_FILE
        elif suffix in SCRIPT_EXTENSIONS and suffix == ".ps1":
            ioc_type = IOCType.POWERSHELL_SCRIPT
        elif suffix in EXECUTABLE_EXTENSIONS or suffix in SCRIPT_EXTENSIONS:
            ioc_type = IOCType.EXECUTABLE
        else:
            ioc_type = IOCType.FILE

        return IOC(
            ioc_type=ioc_type,
            value=path,
            source_artifact=str(event.get("artifact_type") or "unknown"),
            first_seen=event.get("timestamp"),
            last_seen=event.get("timestamp"),
            confidence=float(event.get("confidence", 0.5) or 0.5),
            related_event_ids={event.get("event_id")} if event.get("event_id") else set(),
            supporting_evidence=[str(event.get("description") or "")][:1] if event.get("description") else [],
        )