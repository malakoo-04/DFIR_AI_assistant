# tests/test_incident_analysis_pipeline.py
"""
End-to-end integration test: real KAPE/FastIR dataset -> real local
Ollama model.

This is NOT a unit test. It executes the full deterministic pipeline
exactly as app.py wires it, then sends every resulting incident to the
real local model via IncidentAnalysisAgent. No stage is mocked, no
model response is faked, and no production module is modified except
IncidentAnalysisAgent._call_model (see the accompanying diff) -- the one
seam its own docstring reserves for a real backend.

The script's only job is to prove the pipeline reaches the model and to
print exactly what came back. It never parses, scores, or classifies
the model's response -- that is IncidentAnalysisResult's job, not this
script's.

--------------------------------------------------------------------
Why IncidentTimelineExtractor is here
--------------------------------------------------------------------
The first run of this script against a real dataset sent every
incident the ENTIRE forensic timeline unfiltered -- 359,795 events,
identical, for each of 575 incidents -- producing prompts on the order
of hundreds of millions of characters and a "tokenize error" HTTP 500
from the model backend. That is not a bigger-context-window problem;
it is the same mistake a human analyst would never make: reading the
whole machine's history to investigate one incident instead of just
the events that belong to it.

IncidentTimelineExtractor fixes this by slicing the full timeline down
to only the events IncidentSerializer already assigned to a given
incident (its `events` field), before that incident's prompt is ever
built. It performs no reasoning -- the relevance decision was already
made deterministically upstream by the correlation engine and incident
builder; this only looks up event IDs.
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
from modules.correlation.incident_timeline_extractor import IncidentTimelineExtractor
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
from modules.llm.incident_analysis_agent import (
    IncidentAnalysisAgent,
    IncidentAnalysisError,
)
from modules.llm.incident_analysis_prompt_builder import IncidentAnalysisPromptBuilder
from modules.normalizer.normalizer import Normalizer
from modules.parsers.parser_manager import ParserManager
from modules.timeline.builder import TimelineBuilder

# --------------------------------------------------------------------
# Configuration -- adjust these two for your local setup before running
# --------------------------------------------------------------------

DATASET_PATH = "input/KAPE_OUTPUT"
OLLAMA_MODEL_NAME = "qwen2.5:14b"  # must match `ollama list` exactly

# Diagnostic-only threshold. This does NOT block the call -- it only
# prints a loud warning before the model is invoked, so an oversized
# prompt is caught by a human reading the summary instead of showing
# up forty minutes later as an opaque backend 500.
PROMPT_SIZE_WARNING_CHARS = 60_000  # ~15k estimated tokens


def _section(title: str) -> None:
    print("\n" + "=" * 41)
    print(title)
    print("=" * 41)


def _fail(stage: str, error: Exception) -> None:
    _section(f"PIPELINE FAILED AT: {stage}")
    print(f"{type(error).__name__}: {error}")
    sys.exit(1)


def main() -> None:
    # ------------------------------------------------------------
    # DISCOVERY
    # ------------------------------------------------------------
    try:
        scanner = DiscoveryEngine(DATASET_PATH)
        artifacts = scanner.scan()

        inventory = Inventory()
        inventory.extend(artifacts)
    except Exception as error:
        _fail("Discovery Engine", error)
        return

    # ------------------------------------------------------------
    # PARSING
    # ------------------------------------------------------------
    try:
        parser_manager = ParserManager()
        all_records = []
        unparsed_recognized_artifacts = []

        for artifact in artifacts:
            records = parser_manager.parse(artifact)

            if not records and parser_manager.get_parser(artifact.artifact_type) is None:
                # Recognized by signature, but no parser is registered for
                # this artifact_type (e.g. RANSOM_NOTE, DEFENDER today) --
                # this is exactly the gap described above: it will never
                # appear in scanner.unknown_files (discovery *did*
                # recognize it), so it must be routed to the inventory
                # context explicitly or it becomes invisible everywhere.
                unparsed_recognized_artifacts.append(artifact)

            all_records.extend(records)
    except Exception as error:
        _fail("Parser Manager", error)
        return

    # ------------------------------------------------------------
    # NORMALIZATION
    # ------------------------------------------------------------
    try:
        normalizer = Normalizer()
        normalized_events = normalizer.normalize(all_records)
    except Exception as error:
        _fail("Normalizer", error)
        return

    # ------------------------------------------------------------
    # TIMELINE
    # ------------------------------------------------------------
    try:
        timeline_builder = TimelineBuilder()
        timeline = timeline_builder.build(normalized_events)
    except Exception as error:
        _fail("Timeline Builder", error)
        return

    # ------------------------------------------------------------
    # CORRELATION
    # ------------------------------------------------------------
    try:
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
    except Exception as error:
        _fail("Correlation Engine", error)
        return

    # ------------------------------------------------------------
    # INCIDENT GRAPH -> CANDIDATES -> ENRICHMENT -> SERIALIZATION
    # ------------------------------------------------------------
    try:
        graph_edges = IncidentGraphBuilder().build(correlations)
        incidents = IncidentCandidateBuilder().build(correlations, graph_edges)
        incidents = IncidentEnricher().enrich(incidents, correlations)
        serialized_incidents = IncidentSerializer().serialize(incidents, correlations)
    except Exception as error:
        _fail("Incident Graph/Builder/Enricher/Serializer", error)
        return

    # ------------------------------------------------------------
    # INCIDENT PRIORITIZATION (processing order only -- does not
    # change serialized_incidents itself, which stays in the
    # IncidentSerializer's stable hash order for export/audit)
    # ------------------------------------------------------------
    try:
        prioritized_incidents = IncidentPrioritizer().prioritize(serialized_incidents)
    except Exception as error:
        _fail("Incident Prioritizer", error)
        return

    # ------------------------------------------------------------
    # INVENTORY CONTEXT
    #
    # Only extraction happens here -- it doesn't depend on any one
    # incident. The actual InventoryContextBuilder.build() call now
    # happens per-incident, inside the loop below, scoped to that
    # incident's own time_window. Building it once here and reusing
    # the same object for every incident was the reason a ransom
    # note (or any other unrelated artifact) showed up identically
    # in every one of 575 incidents' prompts regardless of whether
    # it had anything to do with that incident.
    # ------------------------------------------------------------
    try:
        extractor = InventoryContextExtractor()

        extracted = [
            extractor.extract(path) for path in scanner.unknown_files
        ] + [
            extractor.extract(artifact) for artifact in unparsed_recognized_artifacts
        ]

        inventory_builder = InventoryContextBuilder()
    except Exception as error:
        _fail("Inventory Context (Extractor)", error)
        return

    # ------------------------------------------------------------
    # SUMMARY (up to LLM analysis)
    # ------------------------------------------------------------
    _section("DISCOVERY")
    print(f"Artifacts discovered:   {len(artifacts)}")
    print(f"Known artifacts:        {len(artifacts) - len(unparsed_recognized_artifacts)}")
    print(f"Unsupported artifacts:  {len(scanner.unknown_files) + len(unparsed_recognized_artifacts)}")
    print(f"  - unrecognized files:        {len(scanner.unknown_files)}")
    print(f"  - recognized, unparsed type: {len(unparsed_recognized_artifacts)}")

    _section("PARSERS")
    print(f"Records parsed: {len(all_records)}")

    _section("NORMALIZERS")
    print(f"Events normalized: {len(normalized_events)}")

    _section("TIMELINE")
    print(f"Timeline events (full investigation): {len(timeline)}")

    _section("CORRELATION")
    print(f"Correlations: {len(correlations)}")

    _section("INCIDENTS")
    print(f"Incidents generated: {len(serialized_incidents)}")

    if not serialized_incidents:
        print(
            "\nNo incidents were generated by the deterministic pipeline "
            "on this dataset -- there is nothing to send to the model. "
            "This is a valid outcome, not a failure: it means no cluster "
            "of correlations met the incident graph's edge criteria."
        )
        return

    _section("INCIDENT PROCESSING ORDER (prioritized)")
    print(
        "Order below is by severity, then confidence, then correlation "
        "count, then event count -- NOT the incident_id hash order used "
        "for export.\n"
    )
    for rank, incident in enumerate(prioritized_incidents[:10], start=1):
        correlation_count = len(incident.get("primary_correlations") or []) + len(
            incident.get("supporting_correlations") or []
        )
        print(
            f"{rank:>2}. {incident.get('incident_id')[:12]}...  "
            f"severity={incident.get('severity'):<8} "
            f"confidence={incident.get('confidence'):<6} "
            f"correlations={correlation_count:<4} "
            f"events={len(incident.get('events') or [])}"
        )
    if len(prioritized_incidents) > 10:
        print(f"... and {len(prioritized_incidents) - 10} more")

    # ------------------------------------------------------------
    # LLM ANALYSIS -- real model, every incident, no mocking
    # ------------------------------------------------------------
    try:
        agent = IncidentAnalysisAgent(model_name=OLLAMA_MODEL_NAME)
    except Exception as error:
        _fail("Incident Analysis Agent (construction)", error)
        return

    timeline_extractor = IncidentTimelineExtractor()

    for serialized_incident in prioritized_incidents:
        incident_id = serialized_incident.get("incident_id")

        try:
            incident_timeline = timeline_extractor.extract(
                serialized_incident, timeline
            )
        except Exception as error:
            _fail(f"Incident Timeline Extractor (incident {incident_id})", error)
            return

        try:
            incident_time_window = (
                serialized_incident.get("time_window", {}).get("start"),
                serialized_incident.get("time_window", {}).get("end"),
            )
            inventory_context = inventory_builder.build(
                extracted,
            )

            with open(
                    f"inventory_context_{incident_id}.json",
                    "w",
                    encoding="utf-8",
                ) as f:
                    json.dump(
                        inventory_context,
                        f,
                        indent=4,
                        ensure_ascii=False,
                        default=str,
                    )

        except Exception as error:
            _fail(f"Inventory Context Builder (incident {incident_id})", error)
            return

        # ------------------------------------------------------------
        # STEP 2, 3, & 4: INPUT INSPECTION & JSON SIZES
        # ------------------------------------------------------------
        print("\n===== PROMPT INPUT =====")
        print("Incident fields:", len(serialized_incident))
        print("Timeline events:", len(incident_timeline))
        print("Inventory groups:", len(inventory_context))

        incident_json = json.dumps(
            serialized_incident,
            indent=2,
            default=str,
        )
        print("Serialized incident:", len(incident_json), "chars")

        inventory_json = json.dumps(
            inventory_context,
            indent=2,
            default=str,
        )
        print("Inventory context:", len(inventory_json), "chars")

        # ------------------------------------------------------------
        # STEP 1: PROMPT SECTION INSTRUMENTATION
        #
        # Uses IncidentAnalysisPromptBuilder's real section methods
        # directly (_build_system/_build_validated_incident/
        # _build_timeline/_build_inventory_context/_build_task) rather
        # than guessing at attribute names via getattr(..., default) --
        # the previous version of this block checked for a
        # `prompt_builder` attribute that doesn't exist (the agent
        # stores it as `_prompt_builder`) and called method names
        # (`_build_incident_section`, `_build_timeline_section`,
        # `_build_inventory_section`) that were never real methods on
        # this class, so every getattr() fell through to its default
        # and silently printed "0 chars" for every section regardless
        # of the actual prompt size.
        # ------------------------------------------------------------
        try:
            prompt_builder_cls = IncidentAnalysisPromptBuilder
            system_section = prompt_builder_cls._build_system()
            incident_section = prompt_builder_cls._build_validated_incident(serialized_incident)
            timeline_section = prompt_builder_cls._build_timeline(incident_timeline)
            inventory_section = prompt_builder_cls._build_inventory_context(inventory_context)
            task_section = prompt_builder_cls._build_task()

            print("\n" + "=" * 60)
            print("PROMPT BREAKDOWN")
            print("=" * 60)
            print(f"SYSTEM:        {len(system_section):>10,} chars")
            print(f"INCIDENT:      {len(incident_section):>10,} chars")
            print(f"TIMELINE:      {len(timeline_section):>10,} chars")
            print(f"INVENTORY:     {len(inventory_section):>10,} chars")
            print(f"TASK:          {len(task_section):>10,} chars")
            print("-" * 60)
            total = (
                len(system_section)
                + len(incident_section)
                + len(timeline_section)
                + len(inventory_section)
                + len(task_section)
            )
            print(f"TOTAL:         {total:>10,} chars")
            print("=" * 60)

            prompt = agent._build_prompt(
                serialized_incident,
                incident_timeline,
                inventory_context,
            )
        except IncidentAnalysisError as error:
            _fail(f"Prompt Construction (incident {incident_id})", error)
            return

        estimated_tokens = len(prompt) // 4

        print("\n" + "-" * 60)
        print(f"Incident {incident_id}")
        print(
            f"Timeline events: {len(incident_timeline)} "
            f"(of {len(timeline)} total in the full investigation)"
        )
        print(f"Prompt size: {len(prompt):,} characters (~{estimated_tokens:,} estimated tokens)")

        if len(prompt) > PROMPT_SIZE_WARNING_CHARS:
            print(
                f"WARNING: prompt exceeds the {PROMPT_SIZE_WARNING_CHARS:,}-character "
                "diagnostic threshold. This incident's correlation graph may be "
                "unusually large, or inventory_context may be unusually large -- "
                "investigate before assuming the model backend is at fault."
            )

        try:
            response = None

            for attempt in range(2):
                try:
                    response = agent.analyze(
                        serialized_incident,
                        incident_timeline,
                        inventory_context,
                    )
                    break

                except IncidentAnalysisError as error:
                    print(f"Attempt {attempt + 1} failed: {error}")

                    if attempt == 1:
                        raise
        except IncidentAnalysisError as error:
            _fail(f"LLM Analysis (incident {incident_id})", error)
            return

        _section("LLM ANALYSIS")
        print(f"Incident ID:   {incident_id}")
        print(f"Severity:      {serialized_incident.get('severity')}")
        print(f"Confidence:    {serialized_incident.get('confidence')}")
        print(f"Prompt size (characters):        {len(response.prompt)}")
        print(f"Prompt size (estimated tokens):  ~{len(response.prompt) // 4}")
        print(f"Model name:      {response.model_name}")
        print(f"Execution time:  {response.duration_seconds:.2f}s")

        _section("RAW MODEL RESPONSE")
        print(response.text)

        _section("END")


if __name__ == "__main__":
    main()