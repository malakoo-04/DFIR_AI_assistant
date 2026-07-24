from dataclasses import dataclass

from modules.models.entity_type import EntityType
from modules.models.identity_strength import IdentityStrength


@dataclass(slots=True, frozen=True)
class IdentityKey:
    kind: str
    value: str
    entity_type: EntityType
    strength: IdentityStrength