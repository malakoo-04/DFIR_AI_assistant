from modules.correlation.engine import CorrelationEngine
from modules.discovery.scanner import DiscoveryEngine
from modules.discovery.inventory import Inventory
from modules.parsers.parser_manager import ParserManager
from modules.normalizer.normalizer import Normalizer
from modules.timeline.builder import TimelineBuilder
from collections import Counter
from modules.models.event_type import EventType
from modules.correlation.rules.registry_persistence import RegistryPersistenceRule
from modules.correlation.rules.scheduled_task_persistence import ScheduledTaskPersistenceRule
from modules.correlation.rules.service_installation import ServiceInstallationRule
from modules.correlation.rules.defender_detection import DefenderDetectionRule
from modules.correlation.rules.event_log_cleared import EventLogClearedRule
from modules.correlation.rules.usb_connection import USBConnectionRule
from modules.correlation.rules.browser_activity import BrowserActivityRule
from modules.correlation.rules.browser_download_execution import BrowserDownloadExecutionRule
from modules.correlation.rules.powershell_execution import PowerShellExecutionRule
from modules.correlation.incident_graph import IncidentGraphBuilder
from modules.correlation.incident_builder import IncidentCandidateBuilder
from modules.correlation.incident_enricher import IncidentEnricher
from modules.correlation.incident_serializer import IncidentSerializer
from modules.correlation.incident_prioritizer import IncidentPrioritizer
from modules.correlation.attack_chain_builder import AttackChainBuilder

from modules.inventory.context_extractor import InventoryContextExtractor
from modules.inventory.context_builder import InventoryContextBuilder

from modules.llm.investigation_analysis_agent import InvestigationAnalysisAgent
from modules.llm.ioc_extraction_agent import IOCExtractionAgent

import os
from modules.utils.json_export import export_json
from dataclasses import asdict
import json
# ==========================
# Discovery
# ==========================

scanner = DiscoveryEngine("input/KAPE_OUTPUT")

artifacts = scanner.scan()

inventory = Inventory()

inventory.extend(artifacts)

inventory.print_summary()

inventory.export_json("output/inventory/inventory.json")

inventory.export_summary_json(
    "output/inventory/inventory_summary.json"
)

scanner.export_unknown_inventory(
    "output/inventory/unknown_inventory.json"
)

# ==========================
# Parsing
# ==========================

parser_manager = ParserManager()

all_records = []

for artifact in artifacts:

    records = parser_manager.parse(artifact)

    if records:
 

        if not isinstance(records, list):
            print("NOT A LIST")
            print(type(records))
            exit()

        if not isinstance(records[0], dict):
            print("BAD RETURN")
            print(artifact.artifact_type)
            print(type(records[0]))
            print(records[:5])
            exit()

    all_records.extend(records)
# ==========================
# Normalization
# ==========================



normalizer = Normalizer()




normalized_events = normalizer.normalize(all_records)
export_json(
    normalized_events,
    "output/normalized/normalized_events.json"
)


# ==========================
# Timeline
# ==========================

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

# ============================================================
# INCIDENT BUILDING
# ============================================================

graph_edges = IncidentGraphBuilder().build(correlations)

incidents = IncidentCandidateBuilder().build(
    correlations,
    graph_edges,
)

incidents = IncidentEnricher().enrich(
    incidents,
    correlations,
)

serialized_incidents = IncidentSerializer().serialize(
    incidents,
    correlations,
)

prioritized_incidents = IncidentPrioritizer().prioritize(
    serialized_incidents
)

attack_chain = AttackChainBuilder().build(
    prioritized_incidents
)

# ============================================================
# INVENTORY CONTEXT
# ============================================================

extractor = InventoryContextExtractor()

unparsed_recognized_artifacts = []

for artifact in artifacts:
    if parser_manager.get_parser(artifact.artifact_type) is None:
        unparsed_recognized_artifacts.append(artifact)

extracted = [
    extractor.extract(path)
    for path in scanner.unknown_files
]

extracted.extend(
    extractor.extract(artifact)
    for artifact in unparsed_recognized_artifacts
)

inventory_context = InventoryContextBuilder().build(
    extracted
)

# ============================================================
# AGENT 1
# Investigation Analysis
# ============================================================

analysis_agent = InvestigationAnalysisAgent()

analysis_result = analysis_agent.analyze(
    prioritized_incidents,
    timeline,
    inventory_context,
    attack_chain,
)

os.makedirs("output/reports", exist_ok=True)

with open(
    "output/reports/investigation_report.md",
    "w",
    encoding="utf-8",
) as f:
    f.write(analysis_result.text)

print("\nInvestigation report generated.")

# ============================================================
# AGENT 2
# IOC Extraction
# ============================================================

ioc_agent = IOCExtractionAgent()

ioc_result = ioc_agent.extract(
    prioritized_incidents,
    timeline,
    inventory_context,
    attack_chain,
)

os.makedirs("output/iocs", exist_ok=True)

export_json(
    ioc_result.report,
    "output/iocs/ioc_report.json",
)

print("IOC report generated.")

export_json(
    [asdict(c) for c in correlations],
    "output/correlation/correlations.json",
)

export_json(
    timeline,
    "output/timeline/timeline.json"
)
# ==========================
# Summary
# ==========================

print("\n========== PIPELINE SUMMARY ==========\n")

print(f"Artifacts discovered : {len(artifacts)}")

print(f"Parser records       : {len(all_records)}")

print(f"Normalized events    : {len(normalized_events)}")


print(f"Timeline events      : {len(timeline)}")

print(f"Correlations        : {len(correlations)}")



counter = Counter(c.rule_name for c in correlations)

print("\n===== Correlations by rule =====")

for rule, count in counter.items():
    print(f"{rule:<35} {count}")

report = timeline_builder.last_report

print("\n========== TIMELINE REPORT ==========\n")

print(f"Input events       : {report['input_events']}")

print(f"Timeline events    : {report['timeline_events']}")

print("\nSkipped by reason:")

for reason, count in report["skipped_by_reason"].items():
    print(f"  {reason:<30} {count}")


counter=Counter(
    (event["artifact_type"], event["event_type"])
    for event in normalized_events
)

print("\n===== POWERSHELL COMMAND LINES =====\n")

for event in normalized_events:
    if event.get("artifact_type") != "evtx":
        continue

    if str(event.get("event_type")) != "process_execution":
        continue

    cmd = event.get("evidence", {}).get("command_line")

    if cmd:
        print("=" * 80)
        print("Time :", event.get("timestamp"))
        print("Process :", event.get("object_name"))
        print("Command :", cmd)


