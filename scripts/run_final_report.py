"""
End-to-end run:

KAPE/FastIR
        ↓
Deterministic Pipeline
        ↓
Investigation Agent
        ↓
IOC Agent
        ↓
Final DFIR Report Agent
"""

from __future__ import annotations
from modules.report.pdf_generator import generate_pdf
import json
import sys
from dataclasses import asdict
from modules.correlation.attack_chain_builder import AttackChainBuilder
from modules.correlation.engine import CorrelationEngine
from modules.correlation.incident_builder import IncidentCandidateBuilder
from modules.correlation.incident_enricher import IncidentEnricher
from modules.correlation.incident_filter import IncidentFilter
from modules.correlation.incident_graph import IncidentGraphBuilder
from modules.correlation.incident_prioritizer import IncidentPrioritizer
from modules.correlation.incident_serializer import IncidentSerializer

from modules.correlation.rules.browser_activity import BrowserActivityRule
from modules.correlation.rules.browser_download_execution import (
    BrowserDownloadExecutionRule,
)
from modules.correlation.rules.defender_detection import DefenderDetectionRule
from modules.correlation.rules.event_log_cleared import EventLogClearedRule
from modules.correlation.rules.powershell_execution import PowerShellExecutionRule
from modules.correlation.rules.registry_persistence import RegistryPersistenceRule
from modules.correlation.rules.scheduled_task_persistence import (
    ScheduledTaskPersistenceRule,
)
from modules.correlation.rules.service_installation import (
    ServiceInstallationRule,
)
from modules.correlation.rules.usb_connection import USBConnectionRule

from modules.discovery.inventory import Inventory
from modules.discovery.scanner import DiscoveryEngine

from modules.inventory.context_builder import InventoryContextBuilder
from modules.inventory.context_extractor import InventoryContextExtractor

from modules.llm.investigation_analysis_agent import (
    InvestigationAnalysisAgent,
    InvestigationAnalysisError,
)

from modules.llm.ioc_extraction_agent import (
    IOCExtractionAgent,
    IOCExtractionError,
)

from modules.llm.final_report.final_report_agent import (
    FinalReportAgent,
)

from modules.mitre.mapper import MITREMapper

from modules.normalizer.normalizer import Normalizer
from modules.parsers.parser_manager import ParserManager
from modules.timeline.builder import TimelineBuilder

from modules.utils.json_export import export_json

DATASET_PATH = "input/KAPE_OUTPUT"

MODEL_NAME = "gemini-3.5-flash"

MAX_DETAILED_INCIDENTS = None
MAX_RETRIES = 2

INVESTIGATION_OUTPUT = "output/reports/investigation_report.md"
IOC_OUTPUT = "output/iocs/ioc_report.json"
FINAL_REPORT_OUTPUT = "output/reports/final_report.md"
FINAL_REPORT_PDF_OUTPUT = "output/reports/final_report.pdf"

def _section(title: str) -> None:

    print("\n" + "=" * 45)
    print(title)
    print("=" * 45)


def _fail(stage: str, error: Exception) -> None:

    _section(f"PIPELINE FAILED AT: {stage}")

    print(f"{type(error).__name__}: {error}")

    print("[PHASE] FAILED")

    sys.exit(1)


def generate_final_report():
    """
    Run the full DFIR pipeline end-to-end (Discovery ... Final Report
    Agent) and return the output paths.

    This is the exact body that used to live directly in main(). It
    has only been extracted into a named, callable function so
    non-CLI callers (the FastAPI layer, notebooks, other scripts) can
    invoke it directly instead of going through `python -m
    scripts.run_final_report`. No behavior was changed: same steps,
    same order, same prints, same failure handling (_fail still calls
    sys.exit(1) on unrecoverable errors, exactly as before).

    Returns:
        dict with "investigation_report", "ioc_report" and
        "final_report" output paths on success, or None if no
        incidents were generated (mirrors the original early-return).
    """

    ##############################################################
    # DISCOVERY
    ##############################################################

    print("[PHASE] DISCOVERY")

    scanner = DiscoveryEngine(DATASET_PATH)

    artifacts = scanner.scan()

    print(f"[STAT] artifacts_discovered={len(artifacts)}")

    print("[PHASE] INVENTORY")

    inventory = Inventory()

    inventory.extend(artifacts)

    ##############################################################
    # PARSERS
    ##############################################################

    print("[PHASE] PARSERS")

    parser_manager = ParserManager()

    all_records = []

    unparsed_recognized_artifacts = []

    for artifact in artifacts:

        records = parser_manager.parse(artifact)

        if (
            not records
            and parser_manager.get_parser(
                artifact.artifact_type
            )
            is None
        ):
            unparsed_recognized_artifacts.append(
                artifact
            )

        all_records.extend(records)

    print(f"[STAT] parsed_events={len(all_records)}")

    ##############################################################
    # NORMALIZATION
    ##############################################################

    print("[PHASE] NORMALIZATION")

    normalizer = Normalizer()

    normalized_events = normalizer.normalize(
        all_records
    )

    print(f"[STAT] normalized_events={len(normalized_events)}")

    ##############################################################
    # TIMELINE
    ##############################################################

    print("[PHASE] TIMELINE")

    timeline = TimelineBuilder().build(
        normalized_events
    )

    ##############################################################
    # CORRELATION ENGINE
    ##############################################################

    print("[PHASE] CORRELATION")

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

    correlations = correlation_engine.run(
        timeline
    )

    ##############################################################
    # MITRE MAPPING
    ##############################################################

    print("[PHASE] MITRE")

    correlations = MITREMapper().map(
        correlations
    )

    ##############################################################
    # INCIDENT BUILDING
    ##############################################################

    graph_edges = IncidentGraphBuilder().build(
        correlations
    )

    incidents = IncidentCandidateBuilder().build(
        correlations,
        graph_edges,
    )

    incidents = IncidentEnricher().enrich(
        incidents,
        correlations,
    )

    serialized_incidents = (
        IncidentSerializer().serialize(
            incidents,
            correlations,
        )
    )

    prioritized_incidents = (
        IncidentPrioritizer().prioritize(
            serialized_incidents
        )
    )

    attack_chain = AttackChainBuilder().build(
        prioritized_incidents
    )

    ##############################################################
    # FILTER / ENRICH
    ##############################################################

    filterer = IncidentFilter()

    incidents = filterer.filter(
        incidents
    )

    incidents = IncidentEnricher().enrich(
        incidents,
        correlations,
    )

    ##############################################################
    # INVENTORY CONTEXT
    ##############################################################

    extractor = InventoryContextExtractor()

    extracted = (
        [
            extractor.extract(path)
            for path in scanner.unknown_files
        ]
        +
        [
            extractor.extract(artifact)
            for artifact in unparsed_recognized_artifacts
        ]
    )

    inventory_context = (
        InventoryContextBuilder().build(
            extracted
        )
    )

    _section("INCIDENTS")

    print(
        f"Incidents generated: {len(serialized_incidents)}"
    )

    if not serialized_incidents:

        print(
            "No incidents generated."
        )

        print("[PHASE] COMPLETED")

        return None

    #################################################################
    # PART 2 STARTS HERE
    #################################################################

        ##############################################################
    # AGENT 1
    # INVESTIGATION
    ##############################################################

    print("[PHASE] INVESTIGATION")

    try:

        investigation_agent = InvestigationAnalysisAgent(
            model_name=MODEL_NAME
        )

        investigation_agent._prompt_builder._max_detailed_incidents = (
            MAX_DETAILED_INCIDENTS
        )

    except Exception as error:

        _fail(
            "Investigation Agent (construction)",
            error,
        )

        return

    investigation_prompt = investigation_agent._build_prompt(
        prioritized_incidents,
        timeline,
        inventory_context,
        attack_chain,
    )

    print()
    print("=" * 50)
    print("INVESTIGATION PROMPT")
    print("=" * 50)
    print(f"Characters : {len(investigation_prompt):,}")
    print(
        f"Approx tokens : {len(investigation_prompt)//4:,}"
    )

    with open(
        "prompt_debug.txt",
        "w",
        encoding="utf-8",
    ) as f:

        f.write(investigation_prompt)

    FINAL_REPORT_PDF_OUTPUT = "output/reports/final_report.pdf"

    try:

        investigation_result = (
            investigation_agent.analyze(
                prioritized_incidents,
                timeline,
                inventory_context,
                attack_chain,
            )
        )
        import time

        print("\nWaiting 65 seconds for Gemini quota reset...\n")
        time.sleep(65)

    except InvestigationAnalysisError as error:

        _fail(
            "Investigation Analysis",
            error,
        )

        return

    with open(
        INVESTIGATION_OUTPUT,
        "w",
        encoding="utf-8",
    ) as f:

        f.write(investigation_result.text)

    ##############################################################
    # AGENT 2
    # IOC EXTRACTION
    ##############################################################

    print("[PHASE] IOC_EXTRACTION")

    try:

        ioc_agent = IOCExtractionAgent(
            model_name=MODEL_NAME,
            max_retries=MAX_RETRIES,
        )

        ioc_agent._prompt_builder._max_detailed_incidents = 50

    except Exception as error:

        _fail(
            "IOC Agent (construction)",
            error,
        )

        return

    candidate_iocs = ioc_agent._collector.collect(
    prioritized_incidents
)

    print(f"[STAT] candidate_iocs={len(candidate_iocs)}")

    ioc_prompt = ioc_agent._build_prompt(
        candidate_iocs
    )

    print()
    print("=" * 50)
    print("IOC PROMPT")
    print("=" * 50)
    print(f"Characters : {len(ioc_prompt):,}")
    print(
        f"Approx tokens : {len(ioc_prompt)//4:,}"
    )

    with open(
        "ioc_prompt_debug.txt",
        "w",
        encoding="utf-8",
    ) as f:

        f.write(ioc_prompt)

    try:

        ioc_result = ioc_agent.extract(
            prioritized_incidents,
            timeline,
            inventory_context,
            attack_chain,
        )
        print("\nWaiting 65 seconds for Gemini quota reset...\n")
        time.sleep(65)

    except IOCExtractionError as error:

        _fail(
            "IOC Extraction",
            error,
        )

        return

    print("[PHASE] IOC_REPORT")

    print(f"[STAT] confirmed_iocs={len(ioc_result.report.iocs)}")

    export_json(
        ioc_result.report,
        IOC_OUTPUT,
    )

    ##############################################################
    # AGENT 3
    # FINAL REPORT
    ##############################################################

    print("[PHASE] FINAL_REPORT")

    try:

        final_agent = FinalReportAgent()

    except Exception as error:

        _fail(
            "Final Report Agent (construction)",
            error,
        )

        return

    try:

        final_report = final_agent.analyze(

            prioritized_incidents=prioritized_incidents,

            investigation_report=investigation_result.text,

            ioc_report=json.dumps(
                asdict(ioc_result.report),
                indent=2,
                ensure_ascii=False,
            ),
        )

    except Exception as error:

        _fail(
            "Final Report Generation",
            error,
        )

        return

    ##############################################################
    # RESULTS
    ##############################################################

    with open(
        FINAL_REPORT_OUTPUT,
        "w",
        encoding="utf-8",
    ) as f:

        f.write(final_report)

    print("[PHASE] PDF_GENERATION")

    print("Generating PDF report...")

    try:

        final_report_pages = generate_pdf(
            FINAL_REPORT_OUTPUT,
            FINAL_REPORT_PDF_OUTPUT,
        )

        print(
            f"[STAT] final_report_pages={final_report_pages}"
        )

    except Exception as error:

        _fail(
            "PDF Generation",
            error,
        )

        return

    _section("FINAL DFIR REPORT")

    print()
    print(final_report)

    print()
    print("=" * 50)
    print("PIPELINE COMPLETED")
    print("=" * 50)
    print(f"Investigation : {INVESTIGATION_OUTPUT}")
    print(f"IOC           : {IOC_OUTPUT}")
    print(f"Final Report  : {FINAL_REPORT_OUTPUT}")

    print("[PHASE] COMPLETED")

    return {
        "investigation_report": INVESTIGATION_OUTPUT,
        "ioc_report": IOC_OUTPUT,

        # Keep Markdown available internally.
        "final_report": FINAL_REPORT_OUTPUT,

        # Actual user-facing PDF.
        "final_report_pdf": FINAL_REPORT_PDF_OUTPUT,

        # Real metadata for the UI.
        "incidents_generated": len(
            serialized_incidents
        ),

        "final_report_pages": final_report_pages,
    }


def main():
    """CLI entry point. Unchanged behavior: `python -m scripts.run_final_report`
    (or `python scripts/run_final_report.py`) still just runs the pipeline
    and prints exactly what it printed before."""
    generate_final_report()


if __name__ == "__main__":
    main()