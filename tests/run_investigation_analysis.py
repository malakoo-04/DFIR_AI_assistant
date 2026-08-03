# tests/run_investigation_analysis.py
"""End-to-end run: real KAPE dataset -> ONE final DFIR report.

This replaces the loop in test_incident_analysis_pipeline.py that called
IncidentAnalysisAgent once per incident (648 calls). Everything up to
and including IncidentPrioritizer is unchanged -- this script only
replaces what happens after prioritization: instead of looping and
calling the model per incident, it builds ONE investigation-wide
prompt and calls the model ONCE.
"""

from __future__ import annotations

import json
import sys

from modules.correlation.engine import CorrelationEngine
from modules.correlation.incident_builder import IncidentCandidateBuilder
from modules.correlation.incident_enricher import IncidentEnricher
from modules.correlation.incident_graph import IncidentGraphBuilder
from modules.correlation.incident_prioritizer import IncidentPrioritizer
from modules.correlation.incident_serializer import IncidentSerializer
from modules.correlation.rules.browser_activity import BrowserActivityRule
from modules.correlation.rules.browser_download_execution import BrowserDownloadExecutionRule
from modules.correlation.rules.defender_detection import DefenderDetectionRule
from modules.correlation.rules.event_log_cleared import EventLogClearedRule
from modules.correlation.rules.powershell_execution import PowerShellExecutionRule
from modules.correlation.rules.registry_persistence import RegistryPersistenceRule
from modules.correlation.rules.scheduled_task_persistence import ScheduledTaskPersistenceRule
from modules.correlation.rules.service_installation import ServiceInstallationRule
from modules.correlation.rules.usb_connection import USBConnectionRule
from modules.discovery.inventory import Inventory
from modules.discovery.scanner import DiscoveryEngine
from modules.inventory.context_builder import InventoryContextBuilder
from modules.inventory.context_extractor import InventoryContextExtractor
from modules.llm.investigation_analysis_agent import (
    InvestigationAnalysisAgent,
    InvestigationAnalysisError,
)
from modules.normalizer.normalizer import Normalizer
from modules.parsers.parser_manager import ParserManager
from modules.timeline.builder import TimelineBuilder

DATASET_PATH = "input/KAPE_OUTPUT"
OLLAMA_MODEL_NAME = "qwen2.5:14b"
# Safety valve only -- None means every signal-bearing incident gets full
# detail (see InvestigationAnalysisPromptBuilder's docstring). Only set
# this if a real run shows the prompt exceeding your model's context
# window; even then, incidents beyond the cap fall back to a one-line
# summary, they are never dropped.
MAX_DETAILED_INCIDENTS: int | None = None


def _section(title: str) -> None:
    print("\n" + "=" * 41)
    print(title)
    print("=" * 41)


def _fail(stage: str, error: Exception) -> None:
    _section(f"PIPELINE FAILED AT: {stage}")
    print(f"{type(error).__name__}: {error}")
    sys.exit(1)


def main() -> None:
    # DISCOVERY / PARSING / NORMALIZATION / TIMELINE / CORRELATION are
    # identical to app.py and test_incident_analysis_pipeline.py.
    scanner = DiscoveryEngine(DATASET_PATH)
    artifacts = scanner.scan()
    inventory = Inventory()
    inventory.extend(artifacts)

    parser_manager = ParserManager()
    all_records = []
    unparsed_recognized_artifacts = []
    for artifact in artifacts:
        records = parser_manager.parse(artifact)
        if not records and parser_manager.get_parser(artifact.artifact_type) is None:
            unparsed_recognized_artifacts.append(artifact)
        all_records.extend(records)

    normalizer = Normalizer()
    normalized_events = normalizer.normalize(all_records)

    timeline_builder = TimelineBuilder()
    timeline = timeline_builder.build(normalized_events)

    correlation_engine = CorrelationEngine(
        rules=[
            RegistryPersistenceRule(),
            ScheduledTaskPersistenceRule(),
            ServiceInstallationRule(),
            DefenderDetectionRule(),
            EventLogClearedRule(),
            USBConnectionRule(),
            BrowserActivityRule(),
            BrowserDownloadExecutionRule(),
            PowerShellExecutionRule(),
        ]
    )
    correlations = correlation_engine.run(timeline)

    # INCIDENTS (unchanged)
    graph_edges = IncidentGraphBuilder().build(correlations)
    incidents = IncidentCandidateBuilder().build(correlations, graph_edges)
    incidents = IncidentEnricher().enrich(incidents, correlations)
    serialized_incidents = IncidentSerializer().serialize(incidents, correlations)
    prioritized_incidents = IncidentPrioritizer().prioritize(serialized_incidents)

    _section("INCIDENTS")
    print(f"Incidents generated: {len(serialized_incidents)}")
    if not serialized_incidents:
        print("No incidents -- nothing to send to the model.")
        return

    # INVENTORY CONTEXT -- built ONCE for the whole investigation, not
    # per incident (there is no longer a "per incident" step at all).
    extractor = InventoryContextExtractor()
    extracted = [extractor.extract(path) for path in scanner.unknown_files] + [
        extractor.extract(artifact) for artifact in unparsed_recognized_artifacts
    ]
    inventory_context = InventoryContextBuilder().build(extracted)

    # ------------------------------------------------------------
    # ONE model call for the whole investigation.
    # ------------------------------------------------------------
    try:
        agent = InvestigationAnalysisAgent(model_name=OLLAMA_MODEL_NAME)
        agent._prompt_builder._max_detailed_incidents = MAX_DETAILED_INCIDENTS
    except Exception as error:
        _fail("Investigation Analysis Agent (construction)", error)
        return

    prompt_preview = agent._build_prompt(prioritized_incidents, timeline, inventory_context)
    print(f"\nPrompt size: {len(prompt_preview):,} characters "
          f"(~{len(prompt_preview) // 4:,} estimated tokens)")

    try:
        response = agent.analyze(prioritized_incidents, timeline, inventory_context)
    except InvestigationAnalysisError as error:
        _fail("LLM Analysis (whole investigation)", error)
        return

    _section("FINAL DFIR REPORT")
    print(f"Model: {response.model_name}")
    print(f"Incidents analyzed: {response.incident_count} "
          f"({response.detailed_incident_count} in full detail)")
    print(f"Execution time: {response.duration_seconds:.2f}s")
    print()
    print(response.text)

    with open("output/reports/investigation_report.md", "w", encoding="utf-8") as f:
        f.write(response.text)


if __name__ == "__main__":
    main()
