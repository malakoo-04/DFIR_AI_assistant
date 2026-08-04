"""Deterministic prompt construction for the Investigation Analysis Agent."""

from __future__ import annotations

import re
from collections import Counter, defaultdict


class InvestigationAnalysisPromptBuilder:
    """Build a single deterministic prompt for the whole investigation."""

    def __init__(self, max_detailed_incidents: int | None = None):
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
        self._build_system(
            len(prioritized_incidents),
            len(detailed),
        ),

        # Most important evidence FIRST
        self._build_detailed_incidents(
            detailed,
        ),

        self._build_attack_chain(
            attack_chain,
        ),

        self._build_incident_index(
            detailed,
            summarized,
            noise,
        ),

        self._build_investigation_overview(
            prioritized_incidents,
            timeline,
        ),

        self._build_timeline_digest(
            timeline,
        ),

        # Lowest priority
        self._build_inventory_context(
            inventory_context or [],
        ),

        self._build_task(),
    ]

        return "\n\n".join(section for section in sections if section)

    # ------------------------------------------------------------------
    # Incident tiering
    # ------------------------------------------------------------------

    def _tier(
        self, prioritized_incidents: list[dict]
    ) -> tuple[list[dict], list[dict], list[dict]]:
        signal_bearing: list[dict] = []
        noise: list[dict] = []

        for incident in prioritized_incidents:
            if self._is_noise(incident):
                noise.append(incident)
            else:
                signal_bearing.append(incident)

        if self._max_detailed_incidents is not None:
            detailed = signal_bearing[: self._max_detailed_incidents]
            summarized = signal_bearing[self._max_detailed_incidents :]
        else:
            detailed = signal_bearing
            summarized = []

        return detailed, summarized, noise

    @staticmethod
    def _is_noise(incident: dict) -> bool:
        correlation_count = len(incident.get("primary_correlations") or []) + len(
            incident.get("supporting_correlations") or []
        )
        return (
            incident.get("severity") == "low"
            and correlation_count <= 1
            and len(incident.get("rules") or []) <= 1
        )

    # ------------------------------------------------------------------
    # Section -- SYSTEM
    # ------------------------------------------------------------------

    @staticmethod
    def _build_system(total_incidents: int, detailed_count: int) -> str:
        lines = [
            "# SYSTEM",
            "",
            "You are the Investigation Analysis Agent in a Digital Forensics",
            "and Incident Response (DFIR) pipeline. A deterministic forensic",
            "engine has already parsed, normalized, correlated, and grouped",
            "the entire investigation into incidents from Windows forensic",
            "artifacts (registry, EVTX, PowerShell logs, prefetch, browser",
            "history, USN journal, MFT, scheduled tasks, and related",
            "sources).",
            "",
            f"This investigation produced {total_incidents} incidents. EVERY",
            "one of them is represented below -- none are omitted. "
            f"{detailed_count} incidents that carry real multi-signal",
            "evidence are given in full detail; the rest are represented as",
            "individual one-line summaries, or, for genuine single-",
            "correlation noise, as counts aggregated by rule (see INCIDENT",
            "INDEX for exactly how each incident is represented).",
            "",
            "Your task is to analyze the INVESTIGATION AS A WHOLE, not each",
            "incident independently: reconstruct the chronological attack",
            "chain, identify the principal incident/attack family, and",
            "produce ONE final DFIR report for this machine.",
            "",
            "You must:",
            "- Reason only from the evidence supplied below.",
            """The description and evidence fields inside each correlation are the primary forensic evidence.

                Treat them as ground truth.

                Never replace them with your own cybersecurity knowledge."""
            "- Never invent evidence, fields, artifacts, or events that are",
            "  not present in this prompt.",
            "- Treat incidents listed only as one-line summaries as lower-",
            "  resolution evidence: use them to see patterns and volume,",
            "  but do not assert specific technical claims about them that",
            "  their summary line does not support.",
            "- Treat INVENTORY CONTEXT strictly as supplementary, low-",
            "  confidence context that must never override validated",
            "  incident evidence.",
            "- If the evidence is insufficient or too ambiguous to support",
            "  a reliable conclusion, say so explicitly instead of",
            "  guessing.",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section -- INVESTIGATION OVERVIEW
    # ------------------------------------------------------------------

    @staticmethod
    def _build_investigation_overview(incidents: list[dict], timeline: list[dict]) -> str:
        severity_counts = Counter(i.get("severity") for i in incidents)
        rule_counts: Counter[str] = Counter()
        for incident in incidents:
            rule_counts.update(incident.get("rules") or [])

        starts = [
            i.get("time_window", {}).get("start")
            for i in incidents
            if i.get("time_window", {}).get("start")
        ]
        ends = [
            i.get("time_window", {}).get("end")
            for i in incidents
            if i.get("time_window", {}).get("end")
        ]

        lines = [
            "# INVESTIGATION OVERVIEW",
            "",
            f"Total incidents: {len(incidents)}",
            f"Total timeline events (whole investigation): {len(timeline)}",
            f"Overall time span: {min(starts) if starts else '(unknown)'} -> "
            f"{max(ends) if ends else '(unknown)'}",
            "",
            "Incidents by severity: "
            + (", ".join(f"{k}={v}" for k, v in severity_counts.most_common()) or "(none)"),
            "",
            "Incidents by rule (an incident may involve multiple rules):",
        ]
        for rule, count in rule_counts.most_common():
            lines.append(f"  - {rule}: {count}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section -- TIMELINE DIGEST
    # ------------------------------------------------------------------

    @staticmethod
    def _build_timeline_digest(timeline: list[dict]) -> str:
        lines = ["# TIMELINE DIGEST", ""]

        if not timeline:
            lines.append("(no timeline events)")
            return "\n".join(lines)

        by_artifact_event: Counter[tuple[str, str]] = Counter()
        for event in timeline:
            key = (
                str(event.get("artifact_type") or "unknown"),
                str(event.get("event_type") or "unknown"),
            )
            by_artifact_event[key] += 1

        lines.append(
            "Event volume by (artifact_type, event_type) across the whole"
        )
        lines.append("investigation -- for chronological/volume context only;")
        lines.append("the actual events for high-priority incidents are in")
        lines.append("their own evidence sections below.")
        lines.append("")
        for (artifact_type, event_type), count in sorted(
            by_artifact_event.items(), key=lambda item: item[1], reverse=True
        ):
            lines.append(f"  - {artifact_type} / {event_type}: {count}")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section -- ATTACK CHAIN
    # ------------------------------------------------------------------

    @staticmethod
    def _build_attack_chain(attack_chain: list[dict] | dict | None) -> str:
        lines = [
            "# ATTACK CHAIN",
            "",
        ]
        if not attack_chain:
            lines.append("(no attack chain generated)")
            return "\n".join(lines)

        if isinstance(attack_chain, dict):
            for stage, details in attack_chain.items():
                lines.append(f"## {stage}")
                if isinstance(details, list):
                    for item in details:
                        lines.append(f"  - {item}")
                else:
                    lines.append(f"  {details}")
        elif isinstance(attack_chain, list):
            for stage in attack_chain:
                if isinstance(stage, dict):
                    name = stage.get("stage") or stage.get("name") or "Stage"
                    incidents = stage.get("incidents") or []
                    lines.append(f"- **{name}**: {', '.join(str(i) for i in incidents)}")
                else:
                    lines.append(f"- {stage}")
        else:
            lines.append(str(attack_chain))

        return "\n".join(lines).rstrip()

    # ------------------------------------------------------------------
    # Section -- INCIDENT INDEX
    # ------------------------------------------------------------------

    @classmethod
    def _build_incident_index(
        cls, detailed: list[dict], summarized: list[dict], noise: list[dict]
    ) -> str:
        total = len(detailed) + len(summarized) + len(noise)
        lines = [
            "# INCIDENT INDEX",
            "",
            f"All {total} incidents, most significant first. Tier 1 incidents "
            "have full evidence in DETAILED EVIDENCE below; Tier 2 are "
            "summarized here only; Tier 3 (routine, single-correlation noise) "
            "is aggregated by rule at the end -- every incident is accounted "
            "for in one of these three ways.",
            "",
        ]

        rank = 0
        for tier_label, incidents in (
            ("Tier 1 (full evidence below)", detailed),
            ("Tier 2 (summary only)", summarized),
        ):
            if not incidents:
                continue
            lines.append(f"## {tier_label}")
            for incident in incidents:
                rank += 1
                time_window = incident.get("time_window") or {}
                correlation_count = len(incident.get("primary_correlations") or []) + len(
                    incident.get("supporting_correlations") or []
                )
                lines.append(
                    f"{rank}. [{incident.get('incident_id', '')[:12]}] "
                    f"severity={incident.get('severity')} "
                    f"confidence={incident.get('confidence')} "
                    f"rules=[{', '.join(incident.get('rules') or [])}] "
                    f"window={time_window.get('start')}->{time_window.get('end')} "
                    f"correlations={correlation_count} "
                    f"events={len(incident.get('events') or [])}"
                )
            lines.append("")

        if noise:
            rule_counts: Counter[str] = Counter()
            for incident in noise:
                for rule in incident.get("rules") or []:
                    rule_counts[rule] += 1

            lines.append("## Tier 3 -- aggregated (routine, single-correlation noise)")
            lines.append(
                f"{len(noise)} low-severity, single-correlation, single-rule "
                "incidents (e.g. routine persistence entries for ordinary "
                "Windows services). Every one of them is counted below by "
                "rule -- none are excluded from these totals, they are just "
                "not expanded individually:"
            )
            for rule, count in rule_counts.most_common():
                lines.append(f"  - {rule}: {count}")

        return "\n".join(lines).rstrip()

    # ------------------------------------------------------------------
    # Section -- DETAILED INCIDENTS
    # ------------------------------------------------------------------

    @classmethod
    def _build_detailed_incidents(cls, incidents: list[dict]) -> str:

        lines = [
            "# DETAILED INCIDENTS",
            "",
        ]

        if not incidents:
            lines.append("(none)")
            return "\n".join(lines)

        # Most important incident first
        incidents = sorted(
            incidents,
            key=lambda i: (
                {"critical": 3, "high": 2, "medium": 1, "low": 0}.get(
                    str(i.get("severity")).lower(), 0
                ),
                i.get("confidence", 0),
                len(i.get("primary_correlations", [])),
            ),
            reverse=True,
        )

        for index, incident in enumerate(incidents, 1):

            lines.append("=" * 80)
            lines.append(f"INCIDENT #{index}")
            lines.append("=" * 80)
            lines.append("")

            lines.append(cls._build_one_detailed_incident(incident))
            lines.append("")

        return "\n".join(lines)

    @classmethod
    def _build_one_detailed_incident(cls, incident: dict) -> str:
        time_window = incident.get("time_window") or {}

        lines = [
            f"## Incident [{incident.get('incident_id', '')[:12]}]",
            f"Time Window: {time_window.get('start')} -> {time_window.get('end')}",
            f"Severity: {incident.get('severity')}",
            f"Confidence: {incident.get('confidence')}",
            f"Rules: {', '.join(incident.get('rules') or []) or '(none)'}",
            f"Related Incident IDs: "
            f"{', '.join(i[:12] for i in (incident.get('related_incidents') or [])) or '(none)'}",
            "",
        ]

        for section_title, key in (
            ("Primary Correlations", "primary_correlations"),
            ("Supporting Correlations", "supporting_correlations"),
        ):
            correlations = incident.get(key) or []
            lines.append(f"### {section_title}")
            if not correlations:
                lines.append("(none)")
            for correlation in correlations:
                lines.append(
                    f"- [{correlation.get('correlation_id', '')[:10]}] "
                    f"{correlation.get('rule_name')}: {correlation.get('title') or ''} "
                    f"severity={correlation.get('severity')} "
                    f"confidence={correlation.get('confidence')} "
                    f"time={correlation.get('start_time')}"
                )
                description = correlation.get("description")
                if description:
                    lines.append(f"    description: {description}")
                techniques = correlation.get("techniques") or []
                if techniques:
                    lines.append(f"    techniques: {', '.join(techniques)}")
                evidence = correlation.get("evidence") or {}
                for evidence_key, evidence_value in evidence.items():
                    lines.append(
                        f"    {evidence_key}: {cls._compact_evidence_value(evidence_value)}"
                    )
            lines.append("")

        return "\n".join(lines).rstrip()

    _BASE64_RUN = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")
    _MAX_EVIDENCE_VALUE_CHARS = 500

    @classmethod
    def _compact_evidence_value(cls, value):
        if isinstance(value, dict):
            return {k: cls._compact_evidence_value(v) for k, v in value.items()}

        if isinstance(value, list):
            return [cls._compact_evidence_value(v) for v in value]

        if not isinstance(value, str):
            return value

        redacted = cls._BASE64_RUN.sub(
            lambda match: f"<base64:{len(match.group(0))} chars omitted>", value
        )

        if len(redacted) <= cls._MAX_EVIDENCE_VALUE_CHARS:
            return redacted

        head = redacted[: cls._MAX_EVIDENCE_VALUE_CHARS]
        return f"{head}... <{len(redacted) - len(head)} more chars truncated>"

    # ------------------------------------------------------------------
    # Section -- INVENTORY CONTEXT
    # ------------------------------------------------------------------

    @staticmethod
    def _build_inventory_context(inventory_context: list[dict]) -> str:
        lines = [
            "# INVENTORY CONTEXT",
            "",
            "Unsupported or unparsed artifacts discovered during acquisition.",
            """This section is supplementary evidence only.This section is NOT proof of malicious activity.

It only lists files discovered during acquisition.

Do not build an attack scenario from inventory artifacts unless they are explicitly referenced by a correlation.""",
            "",
        ]

        if not inventory_context:
            lines.append("(no additional inventory artifacts)")
            return "\n".join(lines)

        for group in inventory_context:

            category = group.get("category", "unknown")
            count = group.get("count", 0)

            lines.append(f"## {category} ({count} artifact(s))")

            for artifact in group.get("artifacts", []):

                lines.append(f"- Name: {artifact.get('name')}")
                lines.append(f"  Path: {artifact.get('path')}")

                if artifact.get("description"):
                    lines.append(f"  Description: {artifact['description']}")

                if artifact.get("columns"):
                    lines.append(
                        "  Columns: "
                        + ", ".join(str(x) for x in artifact["columns"])
                    )

                if artifact.get("tables"):
                    lines.append(
                        "  Tables: "
                        + ", ".join(str(x) for x in artifact["tables"])
                    )

                if artifact.get("top_level_keys"):
                    lines.append(
                        "  JSON Keys: "
                        + ", ".join(str(x) for x in artifact["top_level_keys"])
                    )

                if artifact.get("preview_rows"):
                    lines.append("  Preview rows:")
                    for row in artifact["preview_rows"]:
                        lines.append(f"    {row}")

                if artifact.get("preview"):
                    lines.append("  Preview:")
                    lines.append(
                        "    "
                        + artifact["preview"].replace("\n", "\n    ")
                    )

                if artifact.get("encoding"):
                    lines.append(f"  Encoding: {artifact['encoding']}")

                if artifact.get("lines") is not None:
                    lines.append(f"  Lines: {artifact['lines']}")

                lines.append("")

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section -- TASK
    # ------------------------------------------------------------------

    @staticmethod
    def _build_task() -> str:
        lines = [
            "# TASK",
            "",
            "You are NOT writing one report per incident.",
            "",
            "Your mission is to analyze the ENTIRE investigation as a single DFIR case.",
            "",
            "Every incident shown above is one piece of the same investigation.",
            "",
            "Some incidents represent routine Windows activity.",
            "Some incidents represent the actual attack.",
            "",
            "Your primary objective is to distinguish signal from background noise.",
            "",
            "Produce ONE final investigation report.",
            "",
            "Determine:",
            "",
            """1. Determine whether the supplied evidence proves an attack.

                If the evidence does not prove an attack,
                state exactly that.

                Do NOT invent an attack scenario.""",
            "",
            """2. Reconstruct ONLY the attack stages explicitly supported by evidence.

                    If a stage is unsupported,
                    write "Unknown".

                    Never infer missing stages""",
            "",
            """3. Explain why your conclusion is supported.

                    If multiple explanations exist,
                    compare them.

                    If none can be proven,
                    say so..""",
            "",
            "4. Mention alternative hypotheses ONLY if supported by evidence.",
            "",
            "5. Ignore routine Windows activity unless it directly supports the attack.",
            "",
            """6. Every technical statement must cite

            - incident ID

            AND

            - correlation ID.

            Statements without evidence must not appear.""",
            "",
            """7. Never invent evidence.Never use general cybersecurity knowledge to fill missing information.

Only facts explicitly contained inside the supplied correlations may appear in the report.""",
            
            "",
            "8. If evidence is insufficient, explicitly state that.",
            """Before writing the report, follow these rules:

1. List every conclusion you intend to make.

2. For each conclusion, identify the correlation(s) that prove it.

3. If no correlation proves the conclusion, delete it.

4. Never infer initial access.

5. Never infer malware family.

6. Never infer phishing.

7. Never infer browser exploitation.

8. Never infer persistence unless a persistence correlation exists.

9. Unknown is always preferable to guessing."""
        ]

        
        return "\n".join(lines)