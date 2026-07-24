from modules.correlation.engine import CorrelationEngine
from modules.correlation.rules.base import Rule


class DummyRule(Rule):
    NAME = "dummy"

    def __init__(self):
        self.executed = False

    def run(self, context):
        self.executed = True
        print("Dummy rule executed")
        assert len(context.timeline) == 1
        return []


def test_correlation_engine_executes_registered_rule():
    rule = DummyRule()
    engine = CorrelationEngine(rules=[rule])

    correlations = engine.run([
        {
            "event_id": "event-1",
            "artifact_type": "prefetch",
            "object_name": "demo.exe",
            "object_path": "C:\\Tools\\demo.exe",
        }
    ])

    assert rule.executed is True
    assert correlations == []
    assert engine.context is not None
    assert engine.context.timeline[0].event["event_id"]
