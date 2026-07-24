from __future__ import annotations

from collections.abc import Iterable

from modules.correlation.context import ContextBuilder, RuleContext
from modules.correlation.identity import EntityResolver
from modules.correlation.models import Correlation, Entity
from modules.correlation.rules.base import Rule
from modules.normalizer.event import ensure_event_id


class CorrelationEngine:
    """Prepare correlation context once and execute rules in registration order."""

    def __init__(self, rules: Iterable[Rule] | None = None):
        self.rules = list(rules or [])
        self.entities: dict[str, Entity] = {}
        self.context_builder: ContextBuilder | None = None
        self.context: RuleContext | None = None
        self.correlations: list[Correlation] = []

    def run(self, timeline: list[dict]) -> list[Correlation]:
        """Resolve identities, build rule context, and run every registered rule."""
        timeline = list(timeline)
        for event in timeline:
            ensure_event_id(event)

        resolver = EntityResolver()
        self.entities = resolver.resolve(timeline)

        self.context_builder = ContextBuilder(resolver.entity_id_by_event)
        event_contexts = self.context_builder.build(timeline)
        self.context = RuleContext(
            timeline=event_contexts,
            index=self.context_builder,
            entities=self.entities,
        )

        self.correlations = []
        for rule in self.rules:
            result = rule.run(self.context)
            if not isinstance(result, list):
                raise TypeError(
                    f"Correlation rule '{getattr(rule, 'NAME', type(rule).__name__)}' "
                    "must return a list of Correlation objects"
                )
            self.correlations.extend(result)

        return list(self.correlations)
