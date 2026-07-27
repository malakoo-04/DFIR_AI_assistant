from __future__ import annotations

from abc import ABC, abstractmethod
import hashlib

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation


def correlation_id(rule_name: str, *parts: str) -> str:
    canonical = "|".join((rule_name, *parts))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Rule(ABC):
    NAME = "unnamed"

    @abstractmethod
    def run(self, context: RuleContext) -> list[Correlation]:
        raise NotImplementedError