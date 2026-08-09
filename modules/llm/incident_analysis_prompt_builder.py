"""Deterministic prompt construction for the Investigation Analysis Agent.

Includes optimizations for token compression: noise tiering, evidence key 
filtering, capped detailed incidents, and removal of redundant metadata.
"""

from __future__ import annotations

CONTEXTUAL_RULES = {
    "browser_activity",
    "registry_persistence",
    "scheduled_task_persistence",
}

IMPORTANT_KEYS = {
    "command_line",
    "image",
    "process_name",
    "file_path",
    "target_path",
    "registry_key",
    "registry_value",
    "service_name",
    "task_name",
    "ip",
    "hostname",
    "domain",
    "url",
    "hash",
    "sha256",
    "sha1",
    "md5",
    "username",
}


class InvestigationAnalysisPromptBuilder:
    """Build a deterministic incident-classification prompt for the

    Investigation Analysis Agent with prompt compression optimizations.
    """

    def __init__(self, max_detailed_incidents: int = 40) -> None:
        self._max_detailed_incidents = max_detailed_incidents

    def build(
        self,
        prioritized_incidents: list[dict],
        timeline: list[dict],
        inventory_context: list[dict],
        attack_chain: list[dict] | dict | None = None,
    ) -> str:
        detailed, summarized, noise = self._tier(prioritized_incidents)

        sections = [
            self._build_system(),
            self._build_inventory_context(inventory_context or []),
            self._build_timeline(timeline or []),
            self._build_incidents_section(detailed, summarized, noise),
        ]

        if attack_chain:
            sections.append(self._build_attack_chain(attack_chain))

        sections.append(self._build_task())

        return "\n\n".join(sections)

    def _tier(self, incidents: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
        detailed: list[dict] = []
        summarized: list[dict] = []
        noise: list[dict] = []

        for incident in incidents:
            if self._is_noise(incident):
                noise.append(incident)
            elif len(detailed) < self._max_detailed_incidents:
                detailed.append(incident)
            else:
                summarized.append(incident)

        return detailed, summarized, noise

    def _is_noise(self, incident: dict) -> bool:
        correlations = (incident.get("primary_correlations") or []) + (
            incident.get("supporting_correlations") or []
        )
        correlation_count = len(correlations)
        rules = set(incident.get("rules") or [])

        return (
            incident.get("severity") == "low"
            and (
                correlation_count <= 2
                or rules.issubset(CONTEXTUAL_RULES)
            )
        )

    # ------------------------------------------------------------------
    # Prompt Sections
    # ------------------------------------------------------------------

    @staticmethod
    def _build_system() -> str:
        lines = [
            "# SYSTEM",
            "",
            "You are the Incident Analysis Agent in a Digital Forensics and",
            "Incident Response (DFIR) pipeline.",
            "Determine the most likely incident type using only the evidence",
            "supplied below.",
        ]
        return "\n".join(lines)

    @classmethod
    def _build_incidents_section(
        cls, detailed: list[dict], summarized: list[dict], noise: list[dict]
    ) -> str:
        lines = ["# VALIDATED INCIDENTS", ""]

        if detailed:
            lines.append("## Detailed Incidents")
            for incident in detailed:
                lines.append(cls._build_one_detailed_incident(incident))
                lines.append("")

        if summarized:
            lines.append(f"## Summarized Incidents ({len(summarized)} lower-priority items)")
            for incident in summarized:
                lines.append(
                    f"- Incident ID: {incident.get('incident_id')} | "
                    f"Rules: {', '.join(incident.get('rules') or [])} | "
                    f"Severity: {incident.get('severity')}"
                )
            lines.append("")

        if noise:
            lines.append(f"## Contextual / Low-Signal Activity ({len(noise)} items suppressed)")

        return "\n".join(lines)

    @classmethod
    def _build_one_detailed_incident(cls, incident: dict) -> str:
        incident = incident or {}
        time_window = incident.get("time_window") or {}

        lines = [
            f"### Incident ID: {incident.get('incident_id')}",
            f"Time Window: {time_window.get('start')} -> {time_window.get('end')}",
            f"Severity: {incident.get('severity')}",
            f"Confidence: {incident.get('confidence')}",
            f"Rules Involved: {', '.join(incident.get('rules') or [])}",
            "",
            cls._build_correlation_section(
                "Primary Correlations", incident.get("primary_correlations") or []
            ),
            cls._build_correlation_section(
                "Supporting Correlations", incident.get("supporting_correlations") or []
            ),
        ]
        return "\n".join(lines)

    @classmethod
    def _build_correlation_section(cls, title: str, correlations: list[dict]) -> str:
        lines = [f"#### {title}"]
        if not correlations:
            lines.append("  (none)")
            return "\n".join(lines)

        for correlation in correlations:
            lines.extend(cls._format_correlation(correlation))
        return "\n".join(lines)

    @staticmethod
    def _format_correlation(correlation: dict) -> list[str]:
        correlation = correlation or {}
        evidence = correlation.get("evidence") or {}

        # Excluded redundant severity, confidence, and description fields
        lines = [
            f"- Correlation ID: {correlation.get('correlation_id')}",
            f"  Rule: {correlation.get('rule_name')}",
            f"  Title: {correlation.get('title')}",
            f"  Start Time: {correlation.get('start_time')}",
            f"  End Time: {correlation.get('end_time')}",
        ]

        # Filter evidence to essential tokens only
        if evidence:
            filtered_evidence = {k: v for k, v in evidence.items() if k in IMPORTANT_KEYS}
            if filtered_evidence:
                lines.append("  Evidence:")
                for key in sorted(filtered_evidence):
                    lines.append(f"    {key}: {filtered_evidence[key]}")

        return lines

    @staticmethod
    def _build_timeline(timeline: list[dict]) -> str:
        lines = ["# FORENSIC TIMELINE", ""]
        if not timeline:
            lines.append("(no timeline events)")
            return "\n".join(lines)

        for event in timeline:
            lines.append(
                f"- [{event.get('timestamp')}] {event.get('event_type')} | "
                f"Object: {event.get('object_name')} | User: {event.get('user')}"
            )
        return "\n".join(lines)

    @staticmethod
    def _build_inventory_context(inventory_context: list[dict]) -> str:
        return "# INVENTORY CONTEXT\n(unparsed artifacts summary)"

    @staticmethod
    def _build_attack_chain(attack_chain: list[dict] | dict) -> str:
        return "# ATTACK CHAIN\n" + str(attack_chain)

    @staticmethod
    def _build_task() -> str:
        return "# TASK\nReconstruct timeline and classify the primary incident type."