from __future__ import annotations

from abc import ABC, abstractmethod

from modules.ioc.ioc_context import IOCExtractionContext
from modules.ioc.ioc_models import IOC


class BaseIOCExtractor(ABC):
    """
    One IOC sub-extractor: a single, narrow responsibility (files,
    network indicators, registry, etc.), same "one rule = one
    behavior" discipline already used for correlation rules.

    Sub-extractors never deduplicate their own output -- IOCExtractor
    (the orchestrator) does that once, across every sub-extractor's
    combined output, so two extractors independently finding the same
    IOC (e.g. network.py and browser.py both finding the same URL)
    merge correctly instead of producing two separate IOC objects.
    """

    @abstractmethod
    def extract(self, context: IOCExtractionContext) -> list[IOC]:
        ...