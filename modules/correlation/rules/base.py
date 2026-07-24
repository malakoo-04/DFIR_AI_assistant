from __future__ import annotations

from abc import ABC, abstractmethod

from modules.correlation.context import RuleContext
from modules.correlation.models import Correlation


class Rule(ABC):
    """Base contract for a correlation rule.

    Rules receive the fully prepared RuleContext and return zero or more
    Correlation objects. They do not mutate the timeline or engine state.
    """

    NAME = "unnamed"

    @abstractmethod
    def run(self, context: RuleContext) -> list[Correlation]:
        """Evaluate the context and return the correlations found."""
        raise NotImplementedError
