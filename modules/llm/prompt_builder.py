"""Deterministic prompt construction for the Incident -> LLM boundary.

This module sits between the deterministic forensic engine and Qwen.
It performs no reasoning, no AI inference, and no incident logic of its
own -- it only reshapes an already-serialized incident (the output of
IncidentSerializer) into a structured, deterministic natural-language
prompt.
"""

from __future__ import annotations


class IncidentPromptBuilder:
    """
    Build a deterministic DFIR analysis prompt from one serialized
    incident.

    Consumes only the plain dict produced by
    IncidentSerializer.serialize() -- never IncidentCandidate,
    Correlation, or any other dataclass -- so this module has no
    dependency on the deterministic engine's internal object model,
    only on its JSON-compatible output contract.
    """

    def build(self, serialized_incident: dict) -> str:
        """
        Build the full prompt for one serialized incident.

        Public API: the only method this class exposes.
        """

        sections = [
            self._build_system(),
            self._build_summary(serialized_incident),
            self._build_primary_correlations(serialized_incident),
            self._build_supporting_correlations(serialized_incident),
            self._build_graph(serialized_incident),
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
            "You are an experienced Digital Forensics and Incident Response",
            "(DFIR) analyst. You are reviewing a candidate incident produced",
            "by a deterministic correlation engine from Windows forensic",
            "artifacts (registry, EVTX, PowerShell logs, prefetch, browser",
            "history, USN journal, MFT, scheduled tasks, and related",
            "sources).",
            "",
            "The incident below was produced entirely by that deterministic",
            "engine: every correlation, edge, and grouping decision was",
            "already made by Python before this prompt was built.",
            "",
            "Your role is NOT to reconstruct the incident from scratch.",
            "Your role is to review the engine's conclusions.",
            "",
            "You may agree, partially agree, or disagree with the grouping",
            "below -- but every recommendation you make must be justified",
            "using only the evidence supplied in this prompt.",
            "",
            "You must:",
            "- Reason only from the evidence supplied below.",
            "- Never invent evidence, fields, or events that are not present.",
            "- Never assume missing facts: a missing or empty field means the",
            "  information is unknown to this incident, not that it is absent",
            "  from the system as a whole.",
            "- Explicitly state your uncertainty where the evidence is",
            "  incomplete or ambiguous.",
            "- Clearly distinguish direct observations (what the evidence",
            "  shows) from your own conclusions (what you infer from it).",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 2 -- INCIDENT SUMMARY
    # ------------------------------------------------------------------

    @classmethod
    def _build_summary(cls, incident: dict) -> str:
        time_window = incident.get("time_window") or {}

        lines = [
            "# INCIDENT SUMMARY",
            "",
            f"Incident ID: {incident.get('incident_id')}",
            f"Time Window: {time_window.get('start')} -> {time_window.get('end')}",
            f"Severity: {incident.get('severity')}",
            f"Confidence: {incident.get('confidence')}",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 3 -- PRIMARY CORRELATIONS
    # ------------------------------------------------------------------

    @classmethod
    def _build_primary_correlations(cls, incident: dict) -> str:
        return cls._build_correlation_section(
            "PRIMARY CORRELATIONS",
            incident.get("primary_correlations") or [],
        )

    # ------------------------------------------------------------------
    # Section 4 -- SUPPORTING CORRELATIONS
    # ------------------------------------------------------------------

    @classmethod
    def _build_supporting_correlations(cls, incident: dict) -> str:
        return cls._build_correlation_section(
            "SUPPORTING CORRELATIONS",
            incident.get("supporting_correlations") or [],
        )

    @classmethod
    def _build_correlation_section(cls, title: str, correlations: list[dict]) -> str:
        """Shared formatter for the primary/supporting sections, which
        use an identical layout and only differ by title and content."""

        lines = [f"# {title}", ""]

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

    # ------------------------------------------------------------------
    # Section 5 -- GRAPH
    # ------------------------------------------------------------------

    @classmethod
    def _build_graph(cls, incident: dict) -> str:
        edges = incident.get("graph") or []

        lines = ["# GRAPH", ""]

        if not edges:
            lines.append("(no edges)")
            return "\n".join(lines)

        for edge in edges:
            matched_criteria = edge.get("matched_criteria") or []
            matched = ", ".join(matched_criteria) if matched_criteria else "(none)"
            lines.append(
                f"- Source: {edge.get('source')} | Target: {edge.get('target')} | "
                f"Score: {edge.get('score')} | Matched Criteria: {matched}"
            )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section 6 -- TASK
    # ------------------------------------------------------------------

    @staticmethod
    def _build_task() -> str:
        lines = [
            "# TASK",
            "",
            "Answer the following questions, in order:",
            "",
            "1. Do you agree that the supplied correlations belong to a single incident?",
            "2. If not, which correlations should be removed?",
            "3. Are important correlations missing, based only on what is supplied?",
            "4. Explain your reasoning.",
            "5. Describe the likely attack progression.",
            "6. Mention any uncertainty.",
            "7. Never invent evidence.",
            "8. Base every conclusion only on the information supplied above.",
        ]
        return "\n".join(lines)