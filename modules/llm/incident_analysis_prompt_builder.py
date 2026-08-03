"""Deterministic prompt construction for the Incident Analysis Agent.

This module is fully independent from ``modules.llm.prompt_builder``
(``IncidentPromptBuilder``), which serves the QwenValidator agent. Nothing
here imports from, subclasses, or otherwise depends on that module, and
this module must never be modified to support it.

The Incident Analysis Agent has a different job than the validator: given
a single incident that the deterministic correlation engine has *already*
validated, decide what kind of incident it most likely is (ransomware,
credential theft, brute force, persistence, etc.), using only the
forensic evidence it is given.

This builder performs none of that reasoning itself. It only takes three
already-computed, deterministic Python outputs --

    1. the serialized validated incident (``IncidentSerializer.serialize``
       payload for one incident),
    2. the forensic timeline (``TimelineBuilder.build`` output), and
    3. an inventory context of artifacts that were never parsed into
       normalized events (KAPE logs, summary/console/copy/skip logs,
       unsupported or metadata-only artifacts, etc.),

-- and reshapes them into a single structured natural-language prompt.
No model calls, no JSON parsing, no incident classification, and no
forensic reasoning happen in this file.
"""

from __future__ import annotations


class IncidentAnalysisPromptBuilder:
    """
    Build a deterministic incident-classification prompt for the
    Incident Analysis Agent.

    Consumes only plain dicts / lists of plain dicts -- the JSON-compatible
    output contracts of IncidentSerializer and TimelineBuilder, plus a
    caller-supplied inventory context -- never dataclasses, enums, or
    datetime objects. This keeps the builder decoupled from the internal
    object models of the correlation engine, the timeline module, and the
    discovery/inventory module alike.
    """

    def build(
        self,
        serialized_incident: dict,
        timeline: list[dict],
        inventory_context: list[dict],
    ) -> str:
        """
        Build the full prompt for one validated incident.

        Public API: the only method this class exposes.

        Parameters
        ----------
        serialized_incident:
            One incident payload as produced by
            ``IncidentSerializer.serialize()`` (a single dict from that
            method's returned list).
        timeline:
            The full forensic timeline as produced by
            ``TimelineBuilder.build()``.
        inventory_context:
            Plain dicts describing artifacts that exist in the collection
            but were not parsed into normalized timeline events (for
            example KAPE summary/console/copy/skip logs, unsupported
            artifact types, or metadata-only artifacts). May be empty.
        """

        sections = [
            self._build_system(),
            self._build_inventory_context(inventory_context or []),
            self._build_timeline(timeline or []),
            self._build_validated_incident(serialized_incident),
            self._build_task(),
        ]

        return "\n\n".join(sections)

    # ------------------------------------------------------------------
    # Section 1 -- SYSTEM
    # ------------------------------------------------------------------

    @staticmethod
    def _build_system() -> str:
        lines = [
            "# SYSTEM",
            "",
            "You are the Incident Analysis Agent in a Digital Forensics and",
            "Incident Response (DFIR) pipeline. A deterministic forensic",
            "engine has already parsed, normalized, correlated, and",
            "validated the incident described below from Windows forensic",
            "artifacts (registry, EVTX, PowerShell logs, prefetch, browser",
            "history, USN journal, MFT, scheduled tasks, and related",
            "sources). Validation is complete -- you are not being asked to",
            "re-validate or re-group this incident.",
            "",
            "Your task is narrower and different: determine the most",
            "likely incident type (for example ransomware, credential",
            "theft, brute force, persistence, or another category) using",
            "only the forensic evidence supplied in this prompt.",
            "",
            "You are given three independent kinds of evidence below:",
            "  1. VALIDATED INCIDENT -- the correlation engine's validated",
            "     output for this incident.",
            "  2. FORENSIC TIMELINE -- the deterministic, normalized event",
            "     timeline covering this incident's time window.",
            "  3. INVENTORY CONTEXT -- artifacts that were discovered in",
            "     the collection but could not be parsed into normalized",
            "     events (for example KAPE summary, console, copy, or skip",
            "     logs; unsupported artifact types; metadata-only",
            "     artifacts).",
            "",
            "You must:",
            "- Reason only from the evidence supplied below.",
            "- Never invent evidence, fields, artifacts, or events that",
            "  are not present in this prompt.",
            "- Never assume missing facts: a missing or empty field means",
            "  the information is unknown to this incident, not that it is",
            "  absent from the system as a whole.",
            "- Treat INVENTORY CONTEXT strictly as supplementary,",
            "  low-confidence context. It consists of artifacts that were",
            "  never parsed into validated forensic events, so it must",
            "  never outweigh, override, or be used to contradict the",
            "  validated evidence in VALIDATED INCIDENT or FORENSIC",
            "  TIMELINE.",
            "- If the supplied evidence is insufficient or too ambiguous",
            "  to support a reliable incident classification, explicitly",
            "  state that no reliable incident classification can be made",
            "  -- do not guess an incident type to fill the gap.",
            "- Clearly distinguish direct observations (what the evidence",
            "  shows) from your own conclusions (what you infer from it).",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 2 -- VALIDATED INCIDENT
    # ------------------------------------------------------------------

    @classmethod
    def _build_validated_incident(cls, incident: dict) -> str:
        incident = incident or {}
        time_window = incident.get("time_window") or {}

        lines = [
            "# VALIDATED INCIDENT",
            "",
            f"Incident ID: {incident.get('incident_id')}",
            f"Time Window: {time_window.get('start')} -> {time_window.get('end')}",
            f"Severity: {incident.get('severity')}",
            f"Confidence: {incident.get('confidence')}",
            f"Rules Involved: {cls._join_or_none(incident.get('rules'))}",
            f"Entity IDs: {cls._join_or_none(incident.get('entities'))}",
            f"Event IDs: {cls._join_or_none(incident.get('events'))}",
            f"Related Incident IDs: {cls._join_or_none(incident.get('related_incidents'))}",
            "",
        ]

        lines.append(
            cls._build_correlation_section(
                "Primary Correlations", incident.get("primary_correlations") or []
            )
        )
        lines.append("")
        lines.append(
            cls._build_correlation_section(
                "Supporting Correlations",
                incident.get("supporting_correlations") or [],
            )
        )
        lines.append("")
        lines.append(cls._build_graph(incident.get("graph") or []))

        return "\n".join(lines)

    @staticmethod
    def _join_or_none(values: list[str] | None) -> str:
        return ", ".join(values) if values else "(none)"

    @classmethod
    def _build_correlation_section(cls, title: str, correlations: list[dict]) -> str:
        lines = [f"## {title}", ""]

        if not correlations:
            lines.append("(none)")
            return "\n".join(lines)

        for correlation in correlations:
            lines.extend(cls._format_correlation(correlation))
            lines.append("")

        if lines and lines[-1] == "":
            lines.pop()

        return "\n".join(lines)

    @staticmethod
    def _format_correlation(correlation: dict) -> list[str]:
        correlation = correlation or {}
        entity_ids = correlation.get("entity_ids") or []
        event_ids = correlation.get("event_ids") or []

        return [
            f"- Correlation ID: {correlation.get('correlation_id')}",
            f"  Rule: {correlation.get('rule_name')}",
            f"  Severity: {correlation.get('severity')}",
            f"  Confidence: {correlation.get('confidence')}",
            f"  Start Time: {correlation.get('start_time')}",
            f"  End Time: {correlation.get('end_time')}",
            f"  Entity IDs: {', '.join(entity_ids) if entity_ids else '(none)'}",
            f"  Event IDs: {', '.join(event_ids) if event_ids else '(none)'}",
        ]

    @staticmethod
    def _build_graph(edges: list[dict]) -> str:
        lines = ["## Correlation Graph", ""]

        if not edges:
            lines.append("(no edges)")
            return "\n".join(lines)

        for edge in edges:
            edge = edge or {}
            matched_criteria = edge.get("matched_criteria") or []
            matched = ", ".join(matched_criteria) if matched_criteria else "(none)"
            lines.append(
                f"- Source: {edge.get('source')} | Target: {edge.get('target')} | "
                f"Score: {edge.get('score')} | Matched Criteria: {matched}"
            )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 3 -- FORENSIC TIMELINE
    # ------------------------------------------------------------------

    @classmethod
    def _build_timeline(cls, timeline: list[dict]) -> str:
        lines = [
            "# FORENSIC TIMELINE",
            "",
            "Events below are listed in the exact order produced by the",
            "Timeline Builder. Do not reorder, merge, or drop any event.",
            "",
        ]

        if not timeline:
            lines.append("(no timeline events)")
            return "\n".join(lines)

        for event in timeline:
            lines.extend(cls._format_timeline_event(event))
            lines.append("")

        if lines and lines[-1] == "":
            lines.pop()

        return "\n".join(lines)

    @staticmethod
    def _format_timeline_event(event: dict) -> list[str]:
        event = event or {}
        related_objects = event.get("related_objects") or []
        identity_keys = event.get("identity_keys") or []

        return [
            f"- Event ID: {event.get('event_id')}",
            f"  Timestamp: {event.get('timestamp')}",
            f"  Artifact Type: {event.get('artifact_type')}",
            f"  Event Type: {event.get('event_type')}",
            f"  Category: {event.get('category')}",
            f"  Object Name: {event.get('object_name')}",
            f"  Object Path: {event.get('object_path')}",
            f"  Related Objects: {', '.join(related_objects) if related_objects else '(none)'}",
            f"  User: {event.get('user')}",
            f"  Computer: {event.get('computer')}",
            f"  Description: {event.get('description')}",
            f"  Confidence: {event.get('confidence')}",
            f"  Source File: {event.get('source_file')}",
            f"  Identity Keys: {', '.join(identity_keys) if identity_keys else '(none)'}",
        ]

    # ------------------------------------------------------------------
    # Section 4 -- INVENTORY CONTEXT
    # ------------------------------------------------------------------

    @classmethod
    def _build_inventory_context(cls, inventory_context: list[dict]) -> str:
        """
        Render INVENTORY CONTEXT.

        `inventory_context` is expected to be the output of
        InventoryContextBuilder.build(): a list of category groups,
        each shaped as {"category", "count", "artifacts"}. As a
        fallback, a flat list of artifact dicts (no "artifacts" key)
        is also accepted and rendered ungrouped, so this method still
        degrades gracefully if it is ever called directly with
        InventoryContextExtractor output rather than
        InventoryContextBuilder output. Either way, this method only
        formats what it is given -- it performs no sorting logic of
        its own beyond a stable, deterministic display order, and no
        parsing of artifact content.
        """

        lines = [
            "# INVENTORY CONTEXT",
            "",
            "The artifacts below were discovered during collection but",
            "were NOT parsed into normalized forensic events (for example",
            "KAPE summary, console, copy, or skip logs; unsupported",
            "artifact types; metadata-only artifacts). Previews and",
            "structural details (columns, table names, encoding, etc.)",
            "are shown where available, but this is still supplementary",
            "context only -- it must not be treated as validated evidence",
            "and must never outweigh VALIDATED INCIDENT or FORENSIC",
            "TIMELINE above.",
            "",
        ]

        if not inventory_context:
            lines.append("(no additional inventory artifacts)")
            return "\n".join(lines)

        if cls._is_grouped(inventory_context):
            for group in cls._sorted_groups(inventory_context):
                lines.extend(cls._format_inventory_group(group))
                lines.append("")
        else:
            for artifact in cls._sorted_flat_artifacts(inventory_context):
                lines.extend(cls._format_inventory_artifact(artifact))
                lines.append("")

        if lines and lines[-1] == "":
            lines.pop()

        return "\n".join(lines)

    @staticmethod
    def _is_grouped(inventory_context: list[dict]) -> bool:
        return all(
            isinstance(entry, dict) and "artifacts" in entry
            for entry in inventory_context
        )

    @staticmethod
    def _sorted_groups(groups: list[dict]) -> list[dict]:
        return sorted(groups, key=lambda group: str((group or {}).get("category") or ""))

    @staticmethod
    def _sorted_flat_artifacts(artifacts: list[dict]) -> list[dict]:
        return sorted(
            artifacts,
            key=lambda artifact: (
                str((artifact or {}).get("path") or ""),
                str((artifact or {}).get("name") or ""),
            ),
        )

    @classmethod
    def _format_inventory_group(cls, group: dict) -> list[str]:
        group = group or {}
        artifacts = group.get("artifacts") or []
        count = group.get("count", len(artifacts))

        lines = [f"## Category: {group.get('category')} ({count})", ""]

        if not artifacts:
            lines.append("(none)")
            return lines

        for artifact in artifacts:
            lines.extend(cls._format_inventory_artifact(artifact))
            lines.append("")

        if lines and lines[-1] == "":
            lines.pop()

        return lines

    @classmethod
    def _format_inventory_artifact(cls, artifact: dict) -> list[str]:
        artifact = artifact or {}

        lines = [
            f"- Name: {artifact.get('name')}",
            f"  Path: {artifact.get('path')}",
        ]

        if "category" in artifact:
            lines.append(f"  Category: {artifact.get('category')}")
        if "artifact_type" in artifact:
            lines.append(f"  Artifact Type: {artifact.get('artifact_type')}")

        lines.extend(
            [
                f"  Size: {artifact.get('size')}",
                f"  Created: {artifact.get('created')}",
                f"  Modified: {artifact.get('modified')}",
                f"  Accessed: {artifact.get('accessed')}",
                f"  Description: {artifact.get('description')}",
            ]
        )

        lines.extend(cls._format_structured_content(artifact))

        return lines

    @staticmethod
    def _format_structured_content(artifact: dict) -> list[str]:
        """
        Render whichever category-specific fields
        InventoryContextExtractor attached to this artifact (preview,
        columns, tables, JSON/XML structure, encoding, etc.), skipping
        any field that is not present rather than printing empty
        placeholders for fields that don't apply to this artifact's
        category. This is pure formatting: it does not decide what
        these fields mean, only how to display them.
        """

        lines: list[str] = []

        if "error" in artifact:
            lines.append(f"  Error: {artifact.get('error')}")

        if "encoding" in artifact:
            lines.append(f"  Encoding: {artifact.get('encoding')}")

        if "lines" in artifact:
            lines.append(f"  Line Count: {artifact.get('lines')}")

        if "columns" in artifact:
            columns = artifact.get("columns") or []
            lines.append(f"  Columns: {', '.join(columns) if columns else '(none)'}")

        if "preview_rows" in artifact:
            preview_rows = artifact.get("preview_rows") or []
            lines.append(f"  Preview Rows ({len(preview_rows)}):")
            for row in preview_rows:
                lines.append(f"    - {row}")

        if "json_valid" in artifact:
            lines.append(f"  JSON Valid: {artifact.get('json_valid')}")
            if artifact.get("json_type"):
                lines.append(f"  JSON Type: {artifact.get('json_type')}")
            if "top_level_keys" in artifact:
                keys = artifact.get("top_level_keys") or []
                lines.append(
                    f"  Top-Level Keys: {', '.join(keys) if keys else '(none)'}"
                )
            if "item_count" in artifact:
                lines.append(f"  Item Count: {artifact.get('item_count')}")

        if "xml_valid" in artifact:
            lines.append(f"  XML Valid: {artifact.get('xml_valid')}")
            if "root_tag" in artifact:
                lines.append(f"  Root Tag: {artifact.get('root_tag')}")

        if "tables" in artifact:
            tables = artifact.get("tables") or []
            lines.append(f"  Tables: {', '.join(tables) if tables else '(none)'}")

        if "preview" in artifact:
            truncated = artifact.get("preview_truncated") or artifact.get("truncated")
            suffix = " (truncated)" if truncated else ""
            lines.append(f"  Preview{suffix}:")
            preview_text = str(artifact.get("preview") or "")
            for preview_line in preview_text.splitlines() or [""]:
                lines.append(f"    | {preview_line}")

        return lines

    # ------------------------------------------------------------------
    # Section 5 -- TASK
    # ------------------------------------------------------------------

    @staticmethod
    def _build_task() -> str:
        lines = [
            "# TASK",
            "",
            "Using only the evidence supplied above, complete the following",
            "steps, in order:",
            "",
            "0. First, reconstruct -- in your own words, in chronological",
            "   order -- what happened on the system, using only the",
            "   supplied evidence. Do not classify the incident yet at",
            "   this step; simply describe the observed sequence of",
            "   events as they occurred.",
            "1. Based on that reconstruction, what is the most likely",
            "   incident type (for example ransomware, credential theft,",
            "   brute force, persistence, lateral movement, data",
            "   exfiltration, etc.)? If more than one type is plausible,",
            "   list each candidate.",
            "2. For each candidate incident type, cite the specific",
            "   correlations and/or timeline events (by ID) that support",
            "   it.",
            "3. Does INVENTORY CONTEXT add any relevant supplementary",
            "   detail? If so, describe it -- but do not let it override",
            "   or outweigh VALIDATED INCIDENT or FORENSIC TIMELINE.",
            "4. State your confidence in this classification and explain",
            "   any uncertainty or ambiguity in the evidence.",
            "5. If the supplied evidence is insufficient to support any",
            "   reliable incident classification, say so explicitly",
            "   instead of guessing.",
            "6. Never invent evidence.",
            "7. Base every conclusion only on the information supplied",
            "   above.",
        ]
        return "\n".join(lines)
