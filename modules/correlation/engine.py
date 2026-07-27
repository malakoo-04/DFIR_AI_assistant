# modules/correlation/engine.py

from __future__ import annotations

from modules.correlation.context import ContextBuilder, RuleContext
from modules.correlation.identity import EntityResolver
from modules.correlation.models import Correlation
from modules.correlation.rules.base import Rule


class CorrelationEngine:
    """
    Orchestrator only. Resolves identity, builds context, runs every
    registered rule once, and concatenates their findings.

    No correlation logic lives here -- see modules/correlation/rules/.
    Deliberately does not deduplicate or rank findings across rules;
    that belongs to Behavior Detection, the next stage downstream.
    """

    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def run(self, timeline: list[dict]) -> list[Correlation]:
        resolver = EntityResolver()
        entities = resolver.resolve(timeline)

        builder = ContextBuilder(resolver.entity_id_by_event)
        contexts = builder.build(timeline)

        rule_context = RuleContext(
            timeline=contexts,
            index=builder,
            entities=entities,
        )

        findings: list[Correlation] = []
        for rule in self.rules:
            findings.extend(rule.run(rule_context))

        return findings