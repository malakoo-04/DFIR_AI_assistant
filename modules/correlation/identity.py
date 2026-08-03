from __future__ import annotations

import hashlib

from modules.correlation.graph import UnionFind
from modules.correlation.models import Entity
from modules.models.entity_type import EntityType
from modules.models.identity_key import IdentityKey
from modules.models.identity_strength import IdentityStrength


# Generic, multi-tenant Windows host processes. Dozens of unrelated,
# legitimate objects (e.g. every "netsvcs" Windows service) legitimately
# share one of these as their launching/hosting executable. Treating such
# a value as a WEAK fallback identity key silently fuses all of them into
# one canonical entity, which then cascades -- via IncidentGraphBuilder's
# shared_entity criterion -- into one oversized incident containing dozens
# of unrelated correlations. This is a value-level heuristic (not
# artifact-type-specific semantics), so it keeps EntityResolver generic.
_GENERIC_HOST_MARKERS = (
    "svchost.exe",
    "rundll32.exe",
    "dllhost.exe",
    "wmiprvse.exe",
    "conhost.exe",
    "msiexec.exe",
    "taskhostw.exe",
)


class EntityResolver:
    """
    Resolve normalized events into canonical entities.

    The resolver is completely artifact-agnostic.
    It never inspects artifact_type-specific semantics.

    Identity is resolved exclusively through IdentityKey objects.
    """

    def __init__(self):
        self._entities: dict[str, Entity] = {}

        self._index: dict[tuple[str, EntityType, str], str] = {}

        self.entity_id_by_event: dict[str, str] = {}

        # Union-Find structure, delegated to the generic implementation
        self._union_find: UnionFind[str] = UnionFind()

        # Reverse mapping: entity -> events
        self._entity_events: dict[str, set[str]] = {}

    def resolve(self, events: list[dict]) -> dict[str, Entity]:
        """
        Resolve all events into canonical entities.
        """

        for event in events:
            self.resolve_event(event)

        return dict(self._entities)
    
    def resolve_event(self, event: dict) -> str | None:
        """
        Resolve one normalized event into a canonical Entity.

        An event may bridge multiple existing entities.
        If so, they are merged through the Union-Find structure.
        """

        keys = self._extract_keys(event)

        if not keys:
            return None

        # Collect every candidate entity matching any identity key.
        strong_candidates: set[str] = set()
        weak_candidates: set[str] = set()

        for key in self._by_strength(keys):
            entity_id = self._find_existing(key)

            if entity_id is None:
                continue

            if key.strength == IdentityStrength.WEAK:
                weak_candidates.add(entity_id)
            else:
                strong_candidates.add(entity_id)

        ambiguous = False

        if strong_candidates:
            candidates = strong_candidates

        elif len(weak_candidates) <= 1:
            candidates = weak_candidates

        else:
            # Several unrelated weak matches. Do not merge on weak
            # evidence alone.
            candidates = set()
            ambiguous = True

        # No existing entity -> create one.
        if not candidates:
            entity_id = self._create_entity(keys, event)

        # One existing entity -> enrich it.
        elif len(candidates) == 1:
            entity_id = next(iter(candidates))
            self._merge_into(entity_id, keys, event)

        # Multiple entities -> merge them first.
        else:
            entity_id = self._union_all(candidates)
            self._merge_into(entity_id, keys, event)

        # Index every identity key — except in the ambiguous case, where
        # blindly re-indexing every key of this event would silently steal
        # keys away from the unrelated entities they already legitimately
        # point to. There, only keys not already claimed by another entity
        # get attached to the newly created one.
        for key in keys:
            lookup_key = self._build_key(key)
            if ambiguous and lookup_key in self._index:
                continue
            self._index[lookup_key] = entity_id

        event_id = event.get("event_id")

        if event_id:
            self._entity_events.setdefault(entity_id, set()).add(event_id)
            self.entity_id_by_event[event_id] = entity_id

        return entity_id
    
    @staticmethod
    def _fallback_keys(event: dict) -> list[IdentityKey]:
        """
        Generate a weak fallback identity key.

        Fallback keys are scoped by artifact type to prevent
        accidental cross-artifact correlations.

        Preference order is object_path, then object_name -- but a
        candidate value is skipped if it merely names a generic,
        multi-tenant host process (see ``_GENERIC_HOST_MARKERS``)
        rather than the object itself. Such a value carries no
        distinguishing identity: it is shared by design across many
        unrelated legitimate objects (e.g. every "netsvcs" Windows
        service is launched via the same svchost.exe command line),
        so anchoring identity on it manufactures false correlations
        instead of real ones. Falling through to object_name (or, if
        that is also generic, to no fallback key at all) keeps this
        method's contract -- "no fallback key" is safer than "a
        wrong, over-broad one".
        """

        for candidate in (event.get("object_path"), event.get("object_name")):
            if not candidate:
                continue

            normalized = str(candidate).strip().lower()

            if any(marker in normalized for marker in _GENERIC_HOST_MARKERS):
                continue

            artifact_type = str(event.get("artifact_type") or "unknown")

            return [
                IdentityKey(
                    kind=f"fallback_object:{artifact_type}",
                    value=normalized,
                    entity_type=EntityType.FILE,
                    strength=IdentityStrength.WEAK,
                )
            ]

        return []
    
    @staticmethod
    def _by_strength(keys: list[IdentityKey]) -> list[IdentityKey]:
        """
        Return identity keys ordered from strongest
        to weakest.
        """

        return sorted(
            keys,
            key=lambda k: k.strength,
            reverse=True,
        )
    
    @staticmethod
    def _build_key(key: IdentityKey) -> tuple:
        """
        Build the canonical lookup key used by
        the resolver index.
        """

        return (
            key.kind,
            key.entity_type,
            str(key.value).strip().lower(),
        )
    
    def _find(self, entity_id: str) -> str:
        """
        Return the canonical representative (root) of an entity.

        Path compression is applied so that future lookups become
        nearly constant time.
        """

        return self._union_find.find(entity_id)
    
    def _union(self, entity_a: str, entity_b: str) -> str:
        """
        Merge two entities and return the surviving entity id.

        The surviving entity is selected deterministically to ensure
        reproducible forensic results.
        """

        survivor, absorbed = self._union_find.union(entity_a, entity_b)

        if survivor == absorbed:
            return survivor

        survivor_entity = self._entities[survivor]
        absorbed_entity = self._entities.pop(absorbed)

        # Merge entity contents
        self._merge_entity_data(survivor_entity, absorbed_entity)

        # Move event ownership
        absorbed_events = self._entity_events.pop(absorbed, set())

        self._entity_events.setdefault(survivor, set()).update(absorbed_events)

        # Update public event -> entity mapping
        for event_id in absorbed_events:
            self.entity_id_by_event[event_id] = survivor

        return survivor
    
    def _union_all(self, candidates: set[str]) -> str:
        """
        Merge multiple entities into a single canonical entity.

        Returns the surviving entity identifier.
        """

        iterator = iter(candidates)
        survivor = next(iterator)

        for entity_id in iterator:
            survivor = self._union(survivor, entity_id)

        return survivor
    
    def _find_existing(self, key: IdentityKey) -> str | None:
        """
        Return the canonical entity associated with an identity key.

        If the key is unknown, return None.
        """

        lookup_key = self._build_key(key)

        entity_id = self._index.get(lookup_key)

        if entity_id is None:
            return None

        return self._find(entity_id)
    
    def _extract_keys(self, event: dict) -> list[IdentityKey]:
        """
        Return the identity keys associated with an event.

        If no explicit identity keys are available,
        generate scoped fallback keys.
        """

        keys = event.get("identity_keys") or []

        if keys:
            return keys

        return self._fallback_keys(event)
    
    def _generate_entity_id(
        self,
        keys: list[IdentityKey],
    ) -> str:
        """
        Generate a deterministic entity identifier from the
        strongest available identity key.
        """

        if not keys:
            raise ValueError("Cannot generate an entity without identity keys.")

        strongest = sorted(
            keys,
            key=lambda k: (
                -int(k.strength),
                k.kind,
                k.entity_type.value,
                str(k.value).lower(),
            ),
        )[0]

        digest = hashlib.sha256(
            f"{strongest.kind}|"
            f"{strongest.entity_type.value}|"
            f"{str(strongest.value).strip().lower()}".encode("utf-8")
        ).hexdigest()

        return digest
    
    def _create_entity(
            self,
            keys: list[IdentityKey],
            event: dict,
        ) -> str:
            """
            Create a new canonical entity from a normalized event.
            """

            entity_id = self._generate_entity_id(keys)

            strongest = self._strongest_key(keys)

            entity = Entity(
                entity_id=entity_id,
                entity_type=strongest.entity_type,
                name=event.get("object_name"),
                canonical_path=event.get("object_path"),
                identity_strength=strongest.strength,
            )

            self._entities[entity_id] = entity
            self._union_find.make_set(entity_id)
            self._entity_events.setdefault(entity_id, set())

            return entity_id

    def _merge_into(
        self,
        entity_id: str,
        keys: list[IdentityKey],
        event: dict,
    ) -> None:
        """
        Enrich an existing entity with information from a new event.
        """

        entity_id = self._find(entity_id)
        entity = self._entities[entity_id]

        strongest = self._strongest_key(keys)

        if (
            entity.canonical_path is None
            or strongest.strength > entity.identity_strength
        ):
            entity.canonical_path = event.get("object_path")
            entity.name = event.get("object_name")
            entity.identity_strength = strongest.strength
        else:
            name = event.get("object_name")
            path = event.get("object_path")

            if name and name != entity.name:
                entity.aliases.append(name)

            if path and path != entity.canonical_path:
                entity.aliases.append(path)

        entity.aliases = sorted(
            set(filter(None, entity.aliases))
        )

    def _merge_entity_data(
        self,
        survivor: Entity,
        absorbed: Entity,
    ) -> None:
        """
        Merge two canonical entities.
        """

        if absorbed.identity_strength > survivor.identity_strength:
            survivor.canonical_path = absorbed.canonical_path
            survivor.name = absorbed.name
            survivor.identity_strength = absorbed.identity_strength

        else:
            if absorbed.name:
                survivor.aliases.append(absorbed.name)

            if absorbed.canonical_path:
                survivor.aliases.append(absorbed.canonical_path)

        survivor.aliases.extend(absorbed.aliases)
        survivor.aliases = sorted(
            set(filter(None, survivor.aliases))
        )

        for key, value in absorbed.metadata.items():

            if key not in survivor.metadata:
                survivor.metadata[key] = value
                continue

            current = survivor.metadata[key]

            if current == value:
                continue

            if isinstance(current, list):
                merged = current
            else:
                merged = [current]

            if isinstance(value, list):
                merged.extend(value)
            else:
                merged.append(value)

            survivor.metadata[key] = sorted(
                {str(v) for v in merged}
            )

    def _strongest_key(
        self,
        keys: list[IdentityKey],
    ) -> IdentityKey:
        """
        Return the strongest identity key using a deterministic tie-break.
        """

        return sorted(
            keys,
            key=lambda k: (
                -int(k.strength),
                k.kind,
                k.entity_type.value,
                str(k.value).strip().lower(),
            ),
        )[0]