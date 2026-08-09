"""Deterministic prompt construction for the IOC Extraction Agent.

Builds a prompt from candidate IOCs extracted upstream, instructing
the model to validate and extract true indicators of compromise in
strict JSON format.
"""

from __future__ import annotations

import json
from modules.llm.ioc_models import ALLOWED_IOC_TYPES, IOC_JSON_EXAMPLE


class IOCExtractionPromptBuilder:
    """Build a single deterministic prompt asking the model for IOCs
    only, in strict JSON, using candidate IOC values collected from the pipeline."""

    def __init__(self, max_detailed_incidents: int = 40):
        self._max_detailed_incidents = max_detailed_incidents

    def build(
        self,
        candidate_iocs: list[dict],
    ) -> str:
        sections = [
            self._build_system(len(candidate_iocs)),
            self._build_output_contract(),
            self._build_candidate_iocs(candidate_iocs),
            self._build_task(),
        ]

        return "\n\n".join(section for section in sections if section)

    # ------------------------------------------------------------------
    # Section -- SYSTEM
    # ------------------------------------------------------------------

    @staticmethod
    def _build_system(total_candidates: int) -> str:
        return "\n".join([
            "# SYSTEM",
            "",
            "You are the IOC Extraction Agent.",
            "",
            "The deterministic DFIR engine has already reconstructed the investigation.",
            "",
            "You are NOT reconstructing the attack.",
            "You are NOT writing a report.",
            "",
            "Your ONLY task is extracting Indicators of Compromise.",
            "",
            f"You received {total_candidates} candidate IOC values.",
            "",
            """Every value below was extracted deterministically from forensic evidence.

                Do NOT invent new indicators.

                Your task is ONLY to:

                1. Reject obvious benign values.
                2. Classify each remaining IOC.
                3. Assign confidence.
                4. Explain briefly why it is an IOC.
                5. Deduplicate.""",
            "Discard benign values.",
            "",
            "Output ONLY JSON."
        ])

    # ------------------------------------------------------------------
    # Section -- OUTPUT CONTRACT
    # ------------------------------------------------------------------

    @staticmethod
    def _build_output_contract() -> str:
        lines = [
            "# OUTPUT CONTRACT",
            "",
            "Respond with EXACTLY ONE JSON object and nothing else -- no",
            "Markdown code fences, no preamble, no explanation before or",
            "after the JSON.",
            "",
            "Top-level shape:",
            "",
            '  { "iocs": [ <IOC object>, ... ] }',
            "",
            "Each IOC object has exactly these fields:",
            "",
            "  - type       : one of the allowed IOC types listed below",
            "  - value      : the literal indicator value as it appears",
            "                 in the evidence (command, URL, path, hash,",
            "                 name, etc.)",
            "  - confidence : \"high\", \"medium\", or \"low\"",
            "  - source     : which incident/correlation ID (or section)",
            "                 this value came from, e.g.",
            "                 \"incident a93a81694a / correlation",
            "                 browser_download_execution\"",
            "  - reason     : one short sentence on why this is an IOC,",
            "                 referencing what the evidence showed",
            "",
            "Allowed values for `type` (use the closest match; if truly",
            "none fit, use \"other\"):",
            "",
            "  " + ", ".join(ALLOWED_IOC_TYPES),
            "",
            "Example of the exact shape required (values are illustrative",
            "only -- do not reuse them, extract your own from the evidence",
            "below):",
            "",
            json.dumps(IOC_JSON_EXAMPLE, indent=2),
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Section -- CANDIDATE IOCS
    # ------------------------------------------------------------------

    @staticmethod
    def _build_candidate_iocs(candidate_iocs: list[dict]) -> str:
        return "\n".join([
            "# CANDIDATE IOCS",
            "",
            "Review the following candidate IOC values collected from the evidence:",
            "",
            json.dumps(
            candidate_iocs,
            separators=(",", ":"),
            ensure_ascii=False,
        ),
        ])

    # ------------------------------------------------------------------
    # Section -- TASK
    # ------------------------------------------------------------------

    @staticmethod
    def _build_task() -> str:
        lines = [
            "# TASK",
            "",
            "Extract every IOC you can confidently identify from the candidate IOCs",
            "above, following the OUTPUT CONTRACT exactly.",
            "",
            "Before answering:",
            "1. Review each entry in CANDIDATE IOCS for true indicators of compromise",
            "   (IPs, URLs, domains, hashes, suspicious command lines, file paths,",
            "   service/task names, account names, filenames, etc.).",
            "2. Discard benign, expected, or purely normal system activity values.",
            "3. Every candidate already contains a `source` field.",
            "   Use that exact source for the IOC you return."
            " Do not invent or modify source identifiers.",
            "4. Deduplicate: the same literal value should appear once, not once per occurrence.",
            "",
            "Output ONLY the JSON object described in OUTPUT CONTRACT.",
            "No Markdown. No prose. No explanation. JSON only.",
        ]
        return "\n".join(lines)