"""End-to-end run: real KAPE dataset -> deterministic pipeline -> IOC report.

Mirrors run_investigation_analysis.py's pipeline-construction stage
exactly (same modules, same order, same rules) so both agents run
against identical prioritized_incidents / timeline / attack_chain /
inventory_context. It does not call InvestigationAnalysisAgent -- this
script exercises Agent 2 (IOCExtractionAgent) on its own, since Agent 2
is independent of Agent 1 by design.
"""

from __future__ import annotations

import sys

from modules.correlation.attack_chain_builder import AttackChainBuilder
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
from modules.ioc.candidate_ioc_collector import CandidateIOCCollector
from modules.llm.ioc_extraction_agent import IOCExtractionAgent, IOCExtractionError
from modules.normalizer.normalizer import Normalizer
from modules.parsers.parser_manager import ParserManager
from modules.timeline.builder import TimelineBuilder
from modules.utils.json_export import export_json

DATASET_PATH = "input/KAPE_OUTPUT"
MODEL_NAME = "gemini-3.5-flash"
MAX_DETAILED_INCIDENTS = 40
MAX_RETRIES = 2
OUTPUT_PATH = "output/iocs/ioc_report.json"


def _section(title: str) -> None:
    print("\n" + "=" * 41)
    print(title)
    print("=" * 41)


def _fail(stage: str, error: Exception) -> None:
    _section(f"PIPELINE FAILED AT: {stage}")
    print(f"{type(error).__name__}: {error}")
    sys.exit(1)


def main() -> None:
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

    # INCIDENTS -- identical construction to run_investigation_analysis.py
    graph_edges = IncidentGraphBuilder().build(correlations)
    incidents = IncidentCandidateBuilder().build(correlations, graph_edges)
    incidents = IncidentEnricher().enrich(incidents, correlations)
    serialized_incidents = IncidentSerializer().serialize(incidents, correlations)
    prioritized_incidents = IncidentPrioritizer().prioritize(serialized_incidents)
    attack_chain = AttackChainBuilder().build(prioritized_incidents)

    _section("INCIDENTS")
    print(f"Incidents generated: {len(serialized_incidents)}")
    if not serialized_incidents:
        print("No incidents -- nothing to send to the model.")
        return

    # INVENTORY CONTEXT
    extractor = InventoryContextExtractor()
    extracted = [extractor.extract(path) for path in scanner.unknown_files] + [
        extractor.extract(artifact) for artifact in unparsed_recognized_artifacts
    ]
    inventory_context = InventoryContextBuilder().build(extracted)

    # Collect candidate IOCs for prompt preview
    candidate_iocs = CandidateIOCCollector().collect(prioritized_incidents)

    # ------------------------------------------------------------
    # Agent 2: IOC extraction.
    # ------------------------------------------------------------
    try:
        agent = IOCExtractionAgent(
            model_name=MODEL_NAME, max_retries=MAX_RETRIES
        )
        agent._prompt_builder._max_detailed_incidents = MAX_DETAILED_INCIDENTS
    except Exception as error:
        _fail("IOC Extraction Agent (construction)", error)
        return

    # Updated: pass candidate_iocs to _build_prompt
    prompt_preview = agent._build_prompt(candidate_iocs)

    print(
        f"\nPrompt size: {len(prompt_preview):,} characters "
        f"(~{len(prompt_preview) // 4:,} estimated tokens)"
    )
    print("\n========== IOC PROMPT ==========")
    print(f"Characters : {len(prompt_preview):,}")
    print(f"Approx tokens : {len(prompt_preview)//3:,}")
    print("================================\n")
    print(prompt_preview[:5000])
    print("=" * 80)
    print(prompt_preview[-5000:])
    with open("ioc_prompt_debug.txt", "w", encoding="utf-8") as f:
        f.write(prompt_preview)

    try:
        result = agent.extract(
            prioritized_incidents, timeline, inventory_context, attack_chain
        )
    except IOCExtractionError as error:
        _fail("IOC Extraction (whole investigation)", error)
        return

    _section("IOC EXTRACTION RESULT")
    print(f"Model: {result.model_name}")
    print(
        f"Incidents analyzed: {result.incident_count} "
        f"({result.detailed_incident_count} candidate IOCs processed)"
    )
    print(f"Attempts used: {result.attempts} (max_retries={MAX_RETRIES})")
    print(f"Execution time: {result.duration_seconds:.2f}s")
    print(f"IOCs extracted: {len(result.report.iocs)}")

    export_json(result.report, OUTPUT_PATH)
    print(f"\nSaved validated IOC report to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()