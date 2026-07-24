from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from modules.models.entity_type import EntityType
from modules.models.severity import Severity
from modules.models.identity_strength import IdentityStrength


@dataclass(slots=True)
class Entity:
    """
    Canonical identity shared across multiple artifacts.
    Example:
        Browser History
        USN
        MFT
        LNK
        Prefetch
    All resolve to the same Entity.
    """

    entity_id: str
    entity_type: EntityType

    name: str | None = None
    canonical_path: str | None = None

    aliases: list[str] = field(default_factory=list)

    identity_strength: IdentityStrength = IdentityStrength.VERY_WEAK

    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Correlation:
    """
    Output produced by a correlation rule.

    This object becomes the input for:
        - MITRE Mapping
        - Suspicious Behavior Detection
        - LLM Report Generation
    """

    correlation_id: str

    rule_name: str
    title: str

    severity: Severity
    confidence: float

    start_time: datetime
    end_time: datetime

    # References to normalized events
    event_ids: list[str]

    # References to resolved entities
    entity_ids: list[str]

    description: str

    # Filled during the MITRE mapping stage
    techniques: list[str] = field(default_factory=list)

    evidence: dict[str, Any] = field(default_factory=dict)

    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate correlation invariants."""
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )