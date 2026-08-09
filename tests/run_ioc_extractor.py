from collections import Counter

from modules.discovery.scanner import DiscoveryEngine
from modules.discovery.inventory import Inventory
from modules.parsers.parser_manager import ParserManager
from modules.normalizer.normalizer import Normalizer
from modules.timeline.builder import TimelineBuilder

from modules.correlation.engine import CorrelationEngine
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

from modules.ioc.ioc_extractor import IOCExtractor
from modules.ioc.ioc_serializer import IOCSerializer
from modules.ioc.ioc_report import IOCReportBuilder

from modules.utils.json_export import export_json

import os


print("=" * 60)
print("Running IOC Extraction Test")
print("=" * 60)

# --------------------------------------------------
# Discovery
# --------------------------------------------------

scanner = DiscoveryEngine("input/KAPE_OUTPUT")

artifacts = scanner.scan()

inventory = Inventory()
inventory.extend(artifacts)

print(f"Artifacts: {len(artifacts)}")

# --------------------------------------------------
# Parsing
# --------------------------------------------------

parser_manager = ParserManager()

all_records = []

for artifact in artifacts:
    all_records.extend(parser_manager.parse(artifact))

print(f"Records: {len(all_records)}")

# --------------------------------------------------
# Normalization
# --------------------------------------------------

normalizer = Normalizer()

normalized_events = normalizer.normalize(all_records)

print(f"Normalized events: {len(normalized_events)}")

# --------------------------------------------------
# Timeline
# --------------------------------------------------

timeline = TimelineBuilder().build(normalized_events)

print(f"Timeline events: {len(timeline)}")

# --------------------------------------------------
# Correlation
# --------------------------------------------------

engine = CorrelationEngine(
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

correlations = engine.run(timeline)

print(f"Correlations: {len(correlations)}")

# --------------------------------------------------
# Incident construction
# --------------------------------------------------

graph = IncidentGraphBuilder().build(correlations)

incidents = IncidentCandidateBuilder().build(
    correlations,
    graph,
)

incidents = IncidentEnricher().enrich(
    incidents,
    correlations,
)

serialized_incidents = IncidentSerializer().serialize(
    incidents,
    correlations,
)

print(f"Incidents: {len(serialized_incidents)}")

# --------------------------------------------------
# IOC Extraction
# --------------------------------------------------

extractor = IOCExtractor()

iocs = extractor.extract(
    timeline,
    correlations,
    serialized_incidents,
)

print()
print("=" * 60)
print("IOC SUMMARY")
print("=" * 60)

print(f"Unique IOCs: {len(iocs)}")

counter = Counter(ioc.ioc_type.value for ioc in iocs)

for t, c in sorted(counter.items()):
    print(f"{t:<25} {c}")

# --------------------------------------------------
# Export
# --------------------------------------------------

os.makedirs("output/iocs", exist_ok=True)

serializer = IOCSerializer()

export_json(
    serializer.serialize(iocs),
    "output/iocs/ioc_summary.json",
)

builder = IOCReportBuilder()

with open(
    "output/iocs/ioc_summary.md",
    "w",
    encoding="utf-8",
) as f:
    f.write(builder.build_markdown(iocs))

print()
print("IOC report exported.")
print("JSON : output/iocs/ioc_summary.json")
print("MD   : output/iocs/ioc_summary.md")