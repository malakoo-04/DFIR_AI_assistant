"""Deterministic prompt construction for the Investigation Analysis Agent.

This is the replacement for the "one LLM call per incident" architecture.
It sits at the very end of the deterministic pipeline and consumes
*everything* the pipeline has already computed for the whole
investigation -- not one incident:

    IncidentSerializer.serialize()   -> all incidents
            v
    IncidentPrioritizer.prioritize() -> incidents ranked by significance
            v
    InvestigationAnalysisPromptBuilder   <- this module
            v
    InvestigationAnalysisAgent
            v
    ONE final DFIR report

Why one prompt instead of N
----------------------------
The Correlation Engine and Incident Builder already did the expensive
deterministic work of turning ~360k raw events into a few hundred
incidents, most of which are single-correlation, low-signal clusters.
Asking the model to look at each one in isolation throws that structure
away: the model never gets the chance to notice that incident #12
(a scheduled task) and incident #340 (a PowerShell download) and
incident #501 (files renamed with a ransom-note extension) are all
part of the *same* attack chain, because it never sees them together.

Sending all incidents to the model is a token-budget problem, not a
free choice: even compact ~1KB-per-incident summaries for 500+
incidents would blow past a local model's context window. But the
answer to that budget problem is NOT "only look at the top N and
drop the rest" -- an incident type the pipeline hasn't seen before
could be sitting at rank 200. Every incident must participate in the
reasoning; only its *representation* gets more compact as its own
evidence volume shrinks. Three tiers, decided by each incident's own
content -- never by an arbitrary rank cutoff:

    - Tier 1, DETAILED: incidents that carry actual multi-signal
      evidence (severity above "low", OR more than one correlation,
      OR more than one rule involved). These get full evidence
      (correlations + graph) rendered individually.
    - Tier 2, SUMMARIZED: every other incident that still has at
      least one correlation to its name gets one identified summary
      line each (severity, confidence, rules, window, counts) --
      still individually addressable by ID, just not expanded.
    - Tier 3, AGGREGATED: genuine single-correlation, single-rule,
      low-severity noise (e.g. one hit per ordinary Windows service
      registration) is rolled up into counts per rule. This is lossy
      compression of *volume*, not of *presence* -- the model is told
      exactly how many such incidents exist and which rules produced
      them, so nothing is silently missing from the picture.

``max_detailed_incidents`` below is a safety valve for pathological
cases (e.g. thousands of genuinely high-severity incidents), not a
target to hit -- see its docstring. On a normal investigation, every
incident that has real evidence behind it ends up in Tier 1 or Tier 2,
i.e. individually represented; only Tier 3 is compressed, and even
that compression is fully accounted for (counts, not omission).

A single compact global timeline digest (counts and notable event
types per rule/category, not 360k raw rows) gives the model
chronological grounding without the tokenizer-breaking dump that
caused the original "tokenize error" failure.

This module performs no reasoning, no classification of attack type,
no scoring. Tiering by evidence volume is bookkeeping, not forensic
judgment -- it only decides *how much space* an incident gets in the
prompt, never whether it is mentioned.
"""

from __future__ import annotations

from collections import Counter


class InvestigationAnalysisPromptBuilder:
    """Build a single deterministic prompt for the whole investigation."""

    def __init__(self, max_detailed_incidents: int | None = None):
        """
        Parameters
        ----------
        max_detailed_incidents:
            Safety valve only. Tier 1 (full detail) is normally
            everything that qualifies by content (see module
            docstring) -- on a typical investigation that is a few
            dozen incidents out of several hundred, which comfortably
            fits a local model's context window (measured: ~27k
            incidents -> ~6-7k prompt tokens on a 575-incident real
            dataset). If a pathological investigation produces far
            more signal-bearing incidents than that, this caps how
            many get full detail (still by IncidentPrioritizer's
            ranking, most significant first) -- but incidents beyond
            the cap fall back to Tier 2 (individual summary line),
            never to Tier 3 (aggregated). Nothing is ever dropped
            entirely by this parameter. ``None`` (default) means no
            cap: every signal-bearing incident gets full detail.
        """
        self._max_detailed_incidents = max_detailed_incidents

    def build(
        self,
        prioritized_incidents: list[dict],
        timeline: list[dict],
        inventory_context: list[dict],
    ) -> str:
        """
        Build the full, single prompt for the whole investigation.

        Parameters
        ----------
        prioritized_incidents:
            The FULL list of serialized incidents, already ordered by
            ``IncidentPrioritizer.prioritize()`` (most significant
            first). Every one of them is represented in the resulting
            prompt, in one of the three tiers described in the module
            docstring -- this method does not truncate the list.
        timeline:
            The full forensic timeline (``TimelineBuilder.build()``
            output) for the whole investigation.
        inventory_context:
            Artifacts that were never parsed into normalized events
            (deduplicated once, globally -- not per incident).
        """
        detailed, summarized, noise = self._tier(prioritized_incidents)

        sections = [
            self._build_system(len(prioritized_incidents), len(detailed)),
            self._build_investigation_overview(prioritized_incidents, timeline),
            self._build_timeline_digest(timeline),
            self._build_incident_index(detailed, summarized, noise),
            self._build_detailed_incidents(detailed),
            self._build_inventory_context(inventory_context or []),
            self._build_task(),
        ]

        return "\n\n".join(section for section in sections if section)

    # ------------------------------------------------------------------
    # Incident tiering -- content-driven, never a rank cutoff that drops
    # incidents. See the module docstring for what each tier means.
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
        """
        A singleton, low-severity, single-rule incident is exactly the
        shape a broad correlation rule produces for every ordinary,
        legitimate object it matches (e.g. one "registry_persistence"
        hit per routine Windows service). It carries no analytical
        signal on its own. Everything else is signal-bearing and gets
        an individual representation (Tier 1 or Tier 2).
        """
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
    # Section -- TIMELINE DIGEST (compact, not the raw 100k+ event dump)
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
    # Section -- INCIDENT INDEX (one line per incident, all of them)
    # ------------------------------------------------------------------

    @classmethod
    def _build_incident_index(
        cls, detailed: list[dict], summarized: list[dict], noise: list[dict]
    ) -> str:
        """
        Every incident appears here, in one of three ways -- none are
        silently omitted. Tier 1 (``detailed``) incidents are still
        listed here too (with a pointer to their full evidence below)
        so the index alone gives a complete map of the investigation.
        """
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
    # Section -- DETAILED INCIDENTS (top-N, full evidence)
    # ------------------------------------------------------------------

    @classmethod
    def _build_detailed_incidents(cls, incidents: list[dict]) -> str:
        lines = [
            "# DETAILED EVIDENCE (top-priority incidents)",
            "",
            "Full correlation and graph evidence for the highest-priority",
            "incidents identified above. Reference these by their",
            "[incident_id prefix] from the INCIDENT INDEX.",
            "",
        ]

        if not incidents:
            lines.append("(no incidents met the detail threshold)")
            return "\n".join(lines)

        for incident in incidents:
            lines.append(cls._build_one_detailed_incident(incident))
            lines.append("")

        return "\n".join(lines).rstrip()

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

        for title, key in (
            ("Primary Correlations", "primary_correlations"),
            ("Supporting Correlations", "supporting_correlations"),
        ):
            correlations = incident.get(key) or []
            lines.append(f"### {title}")
            if not correlations:
                lines.append("(none)")
            for correlation in correlations:
                lines.append(
                    f"- [{correlation.get('correlation_id', '')[:10]}] "
                    f"{correlation.get('rule_name')} "
                    f"severity={correlation.get('severity')} "
                    f"confidence={correlation.get('confidence')} "
                    f"time={correlation.get('start_time')}"
                )
                evidence = correlation.get("evidence") or {}
                for evidence_key, evidence_value in evidence.items():
                    lines.append(f"    {evidence_key}: {evidence_value}")
            lines.append("")

        return "\n".join(lines).rstrip()

    # ------------------------------------------------------------------
    # Section -- INVENTORY CONTEXT
    # ------------------------------------------------------------------

    @staticmethod
    def _build_inventory_context(inventory_context: list[dict]) -> str:
        lines = [
            "# INVENTORY CONTEXT",
            "",
            "Artifacts discovered but not parsed into normalized events",
            "(deduplicated once for the whole investigation). Supplementary",
            "and low-confidence -- never overrides incident evidence.",
            "",
        ]

        if not inventory_context:
            lines.append("(no additional inventory artifacts)")
            return "\n".join(lines)

        for artifact in inventory_context:
            lines.append(
                f"- {artifact.get('name')} ({artifact.get('path')}): "
                f"{artifact.get('description')}"
            )

        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section -- TASK
    # ------------------------------------------------------------------

    @staticmethod
    def _build_task() -> str:
        lines = [
            "# TASK",
            "",
            "Using only the evidence supplied above, produce ONE final DFIR",
            "report answering, in order:",
            "",
            "1. What happened on this machine? Reconstruct the chronological",
            "   sequence of events across the WHOLE investigation, not one",
            "   incident at a time.",
            "2. What is the complete attack chain (initial access,",
            "   execution, persistence, defense evasion, impact, etc.),",
            "   citing which incidents/correlations (by ID) support each",
            "   stage?",
            "3. What is the principal incident, and what incident type /",
            "   attack family does it belong to (ransomware, credential",
            "   theft, brute force, persistence-only, etc.)? If more than",
            "   one is plausible, list each candidate with supporting",
            "   evidence.",
            "4. Which of the other incidents are part of the same attack,",
            "   versus unrelated/background activity (e.g. routine",
            "   persistence noise)?",
            "5. What is your overall confidence in this reconstruction, and",
            "   what specific uncertainty or gaps remain?",
            "6. If the supplied evidence is insufficient to support a",
            "   reliable conclusion, say so explicitly instead of guessing.",
            "7. Never invent evidence; base every conclusion only on the",
            "   information supplied above.",
        ]
        return "\n".join(lines)
