"""IncidentCandidate + ValidationResult -> ValidatedIncident boundary.

This module is the decision layer between the deterministic forensic
engine and the AI reviewer. It is the ONLY place in the pipeline where
Python decides whether an AI recommendation is accepted.

It does not call the model, parse JSON, rebuild incidents, compute
severity/confidence, or create graph edges -- all of that already
happened upstream (IncidentCandidateBuilder, IncidentEnricher,
IncidentSerializer, IncidentPromptBuilder, QwenValidator). This module
only compares what the engine built against what the AI recommended,
and decides what -- if anything -- gets accepted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from modules.correlation.incident_models import GraphEdge, IncidentCandidate
from modules.llm.qwen_validator import ValidationResult, ValidationVerdict
from modules.models.severity import Severity


@dataclass(slots=True)
class ValidatedIncident:
    """
    The final, validated incident: an IncidentCandidate combined with
    Python's decision about the AI's review of it.
    """

    incident_id: str

    severity: Severity
    confidence: float

    start_time: datetime
    end_time: datetime

    entity_ids: list[str] = field(default_factory=list)
    event_ids: list[str] = field(default_factory=list)
    rule_names: list[str] = field(default_factory=list)

    graph_edges: list[GraphEdge] = field(default_factory=list)

    primary_correlation_ids: list[str] = field(default_factory=list)
    supporting_correlation_ids: list[str] = field(default_factory=list)

    validation_verdict: ValidationVerdict = ValidationVerdict.DISAGREE
    validation_confidence: float = 0.0
    validation_reasoning: str = ""

    accepted_correlation_promotions: list[str] = field(default_factory=list)
    accepted_correlation_removals: list[str] = field(default_factory=list)


class IncidentValidator:
    """
    Decide whether the AI's recommendation about an IncidentCandidate
    is accepted, and produce the resulting ValidatedIncident.

    Python remains the final authority: the AI's verdict is only ever
    used as an input to a fixed, deterministic decision policy defined
    entirely in this class. The original IncidentCandidate is never
    mutated -- a new ValidatedIncident is always returned.
    """

    def validate(
        self,
        incident: IncidentCandidate,
        validation: ValidationResult,
    ) -> ValidatedIncident:
        """
        Compare `incident` with `validation` and return the final
        ValidatedIncident.

        Public API: the only method this class exposes.
        """

        if validation.verdict == ValidationVerdict.AGREE:
            return self._handle_agree(incident, validation)

        if validation.verdict == ValidationVerdict.DISAGREE:
            return self._handle_disagree(incident, validation)

        return self._handle_partial(incident, validation)

    # ------------------------------------------------------------------
    # Decision rules
    # ------------------------------------------------------------------

    def _handle_agree(
        self,
        incident: IncidentCandidate,
        validation: ValidationResult,
    ) -> ValidatedIncident:
        """
        Rule 1: AGREE -- accept the incident unchanged.

        Store the validation information, but make no modification to
        the incident's correlation membership.
        """

        return self._copy_incident(
            incident,
            validation,
            accepted_correlation_promotions=[],
            accepted_correlation_removals=[],
        )

    def _handle_disagree(
        self,
        incident: IncidentCandidate,
        validation: ValidationResult,
    ) -> ValidatedIncident:
        """
        Rule 2: DISAGREE -- reject every suggested modification.

        The original incident is kept exactly as-is. Only the AI's
        reasoning is stored, for analyst review.
        """

        return self._copy_incident(
            incident,
            validation,
            accepted_correlation_promotions=[],
            accepted_correlation_removals=[],
        )

    def _handle_partial(
        self,
        incident: IncidentCandidate,
        validation: ValidationResult,
    ) -> ValidatedIncident:
        """
        Rule 3: PARTIALLY_AGREE -- accept only recommendations that
        reference correlation_ids already belonging to the incident
        (as either a primary or a supporting correlation). Any id the
        AI mentions that the engine never produced is unknown evidence
        and is ignored.

        - An accepted removal drops that correlation_id from wherever
          it currently sits (primary or supporting).
        - An accepted promotion moves that correlation_id from the
          supporting list into the primary list. It can never
          introduce a brand new correlation_id, since only ids already
          known to the incident are eligible in the first place.
        """

        existing_ids = set(incident.correlation_ids) | set(
            incident.supporting_correlation_ids
        )

        accepted_correlation_removals = self._known_ids(
            validation.suggested_removals, existing_ids
        )
        accepted_correlation_promotions = self._known_ids(
            validation.suggested_additions, existing_ids
        )

        primary_ids = set(incident.correlation_ids)
        supporting_ids = set(incident.supporting_correlation_ids)

        for correlation_id in accepted_correlation_removals:
            primary_ids.discard(correlation_id)
            supporting_ids.discard(correlation_id)

        for correlation_id in accepted_correlation_promotions:
            if correlation_id in supporting_ids:
                supporting_ids.discard(correlation_id)
                primary_ids.add(correlation_id)

        return self._copy_incident(
            incident,
            validation,
            accepted_correlation_promotions=accepted_correlation_promotions,
            accepted_correlation_removals=accepted_correlation_removals,
            primary_correlation_ids=sorted(primary_ids),
            supporting_correlation_ids=sorted(supporting_ids),
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _known_ids(candidate_ids: list[str], existing_ids: set[str]) -> list[str]:
        """
        Return the sorted subset of `candidate_ids` that are already
        known to the incident. Unknown ids are silently ignored --
        this is how "never invent evidence" is enforced.
        """

        return sorted(set(candidate_ids) & existing_ids)

    @staticmethod
    def _copy_incident(
        incident: IncidentCandidate,
        validation: ValidationResult,
        *,
        accepted_correlation_promotions: list[str],
        accepted_correlation_removals: list[str],
        primary_correlation_ids: list[str] | None = None,
        supporting_correlation_ids: list[str] | None = None,
    ) -> ValidatedIncident:
        """
        Build a new ValidatedIncident from an IncidentCandidate.

        The original IncidentCandidate is never modified: every field
        copied here is a fresh list, and the incident argument is only
        ever read.
        """

        return ValidatedIncident(
            incident_id=incident.incident_id,
            severity=incident.severity,
            confidence=incident.confidence,
            start_time=incident.start_time,
            end_time=incident.end_time,
            entity_ids=list(incident.entity_ids),
            event_ids=list(incident.event_ids),
            rule_names=list(incident.rule_names),
            graph_edges=list(incident.graph_edges),
            primary_correlation_ids=(
                list(incident.correlation_ids)
                if primary_correlation_ids is None
                else primary_correlation_ids
            ),
            supporting_correlation_ids=(
                list(incident.supporting_correlation_ids)
                if supporting_correlation_ids is None
                else supporting_correlation_ids
            ),
            validation_verdict=validation.verdict,
            validation_confidence=validation.confidence,
            validation_reasoning=validation.reasoning,
            accepted_correlation_promotions=accepted_correlation_promotions,
            accepted_correlation_removals=accepted_correlation_removals,
        )
