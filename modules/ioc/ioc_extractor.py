"""IOC extraction orchestrator: run every sub-extractor, deduplicate
and merge their combined output into one canonical IOC list.

Consumes only the deterministic pipeline's own already-computed output
(timeline, correlations, serialized incidents) -- never touches raw
artifacts, per the module's own requirement.
"""

from __future__ import annotations

import logging

from modules.correlation.models import Correlation
from modules.ioc.ioc_context import IOCExtractionContext, build_context
from modules.ioc.ioc_extractors.base import BaseIOCExtractor
from modules.ioc.ioc_extractors.browser import BrowserIOCExtractor
from modules.ioc.ioc_extractors.files import FileIOCExtractor
from modules.ioc.ioc_extractors.hashes import HashIOCExtractor
from modules.ioc.ioc_extractors.network import NetworkIOCExtractor
from modules.ioc.ioc_extractors.powershell import PowerShellIOCExtractor
from modules.ioc.ioc_extractors.registry import RegistryIOCExtractor
from modules.ioc.ioc_extractors.services import ServiceIOCExtractor
from modules.ioc.ioc_extractors.tasks import ScheduledTaskIOCExtractor
from modules.ioc.ioc_models import IOC, IOCType

logger = logging.getLogger(__name__)

_DEFAULT_EXTRACTORS: tuple[type[BaseIOCExtractor], ...] = (
    FileIOCExtractor,
    RegistryIOCExtractor,
    PowerShellIOCExtractor,
    NetworkIOCExtractor,
    BrowserIOCExtractor,
    ServiceIOCExtractor,
    ScheduledTaskIOCExtractor,
    HashIOCExtractor,
)


class IOCExtractor:
    """
    Run every registered sub-extractor over the same
    IOCExtractionContext, then deduplicate/merge their combined output
    into one canonical list of IOC objects.
    """

    _MAX_SUPPORTING_EVIDENCE = 5

    def __init__(self, extractors: list[BaseIOCExtractor] | None = None):
        self._extractors = extractors or [cls() for cls in _DEFAULT_EXTRACTORS]

    def extract(
        self,
        timeline: list[dict],
        correlations: list[Correlation],
        serialized_incidents: list[dict],
    ) -> list[IOC]:
        context = build_context(timeline, correlations, serialized_incidents)

        merged: dict[tuple[IOCType, str], IOC] = {}

        for extractor in self._extractors:
            name = type(extractor).__name__
            try:
                candidates = extractor.extract(context)
            except Exception:
                logger.exception("IOC extractor %s failed; skipping it", name)
                continue

            for candidate in candidates:
                if not candidate.value:
                    continue
                self._merge(merged, candidate)

        logger.info("IOC extraction produced %d unique indicators", len(merged))
        return sorted(merged.values(), key=lambda ioc: (ioc.ioc_type.value, ioc.value))

    @classmethod
    def _merge(cls, merged: dict[tuple[IOCType, str], IOC], candidate: IOC) -> None:
        key = candidate.dedup_key
        existing = merged.get(key)

        if existing is None:
            merged[key] = candidate
            return

        existing.count += 1
        existing.confidence = max(existing.confidence, candidate.confidence)

        if candidate.first_seen and (not existing.first_seen or candidate.first_seen < existing.first_seen):
            existing.first_seen = candidate.first_seen
        if candidate.last_seen and (not existing.last_seen or candidate.last_seen > existing.last_seen):
            existing.last_seen = candidate.last_seen

        existing.related_incident_ids |= candidate.related_incident_ids
        existing.related_correlation_ids |= candidate.related_correlation_ids
        existing.related_event_ids |= candidate.related_event_ids

        if existing.severity is None:
            existing.severity = candidate.severity

        for snippet in candidate.supporting_evidence:
            if snippet and snippet not in existing.supporting_evidence:
                if len(existing.supporting_evidence) < cls._MAX_SUPPORTING_EVIDENCE:
                    existing.supporting_evidence.append(snippet)