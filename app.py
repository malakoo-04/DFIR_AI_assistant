from modules.discovery.scanner import DiscoveryEngine
from modules.discovery.inventory import Inventory
from modules.parsers.parser_manager import ParserManager
from modules.normalizer.normalizer import Normalizer
from modules.timeline.builder import TimelineBuilder
from collections import Counter
from modules.utils.json_export import export_json

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


