from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class MitreTechnique:
    """
    One ATT&CK technique identified during the investigation.
    """

    technique_id: str
    name: str
    tactic: str
    confidence: str
    evidence: list[str] = field(default_factory=list)
    supporting_incidents: list[str] = field(default_factory=list)
    supporting_correlations: list[str] = field(default_factory=list)
    explanation: str = ""


@dataclass(slots=True)
class MitreReport:
    """
    Final structured MITRE ATT&CK report.
    """

    techniques: list[MitreTechnique] = field(default_factory=list)