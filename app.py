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
"""
report = timeline_builder.last_report

for reason, samples in report["skipped_samples"].items():
    print(f"\n===== {reason} =====")

    for sample in samples:
        print(sample)"""

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


