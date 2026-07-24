from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from modules.correlation.models import Entity

@dataclass(slots=True)
class EventContext:
    """
    Enriched context around one normalized event.
    
    Stores direct object references to surrounding and related events
    to prevent downstream lookup overhead in correlation modules.
    """

    event: dict  # TODO: Migrate to Event dataclass when available
    entity_id: str | None = None

    # Temporal neighbors
    previous_event: dict | None = None
    next_event: dict | None = None

    # Relational groupings
    same_entity: list[dict] = field(default_factory=list)
    same_process: list[dict] = field(default_factory=list)
    same_path: list[dict] = field(default_factory=list)
    same_user: list[dict] = field(default_factory=list)
    same_logon: list[dict] = field(default_factory=list)
    same_host: list[dict] = field(default_factory=list)


class ContextBuilder:
    """
    Builds contextual relationship wrappers (EventContext) around normalized timeline events.
    
    Uses an O(N) multi-index pass to group related events without incurring O(N^2) search overhead.
    Stores generated indexes for reuse in downstream correlation rules.
    """

    def __init__(self, entity_map: Mapping[str, str] | None = None):
        """
        :param entity_map: Read-only mapping of event_id -> entity_id.
        """
        self.entity_map: Mapping[str, str] = entity_map or {}

        # Stored indexes for downstream engine/confidence reuse
        self.events_by_entity: dict[str, list[dict]] = {}
        self.events_by_process: dict[str, list[dict]] = {}
        self.events_by_path: dict[str, list[dict]] = {}
        self.events_by_user: dict[str, list[dict]] = {}
        self.events_by_logon: dict[str, list[dict]] = {}
        self.events_by_host: dict[str, list[dict]] = {}

    def build(self, timeline: list[dict]) -> list[EventContext]:
        """
        Enrich a chronologically sorted timeline with contextual relationships.

        :param timeline: Sorted list of normalized event dictionaries.
        :return: List of EventContext objects in the same order as timeline.
        """
        if not timeline:
            return []

        # Reset indexes
        self.events_by_entity = {}
        self.events_by_process = {}
        self.events_by_path = {}
        self.events_by_user = {}
        self.events_by_logon = {}
        self.events_by_host = {}

        # ------------------------------------------------------------------
        # PASS 1: Build indexing tables in O(N) using standardized fields
        # ------------------------------------------------------------------
        for event in timeline:
            event_id = event.get("event_id")

            # Entity Index
            if event_id and event_id in self.entity_map:
                entity_id = self.entity_map[event_id]
                self.events_by_entity.setdefault(entity_id, []).append(event)

            # Process Index
            process_key = self._extract_key(event, "process_id")
            if process_key:
                self.events_by_process.setdefault(process_key, []).append(event)

            # Raw path index (weak fallback — prefer same_entity when an
            # entity_id is available; this only groups by coincidentally
            # identical object_path/object_name strings, with none of the
            # cross-artifact collision protection identity.py provides).
            path_key = self._extract_path_key(event)
            if path_key:
                self.events_by_path.setdefault(path_key, []).append(event)

            # User Index
            user_key = self._extract_key(event, "user")
            if user_key:
                self.events_by_user.setdefault(user_key, []).append(event)

            # Logon ID Index
            logon_key = self._extract_key(event, "logon_id")
            if logon_key:
                self.events_by_logon.setdefault(logon_key, []).append(event)

            # Host Index
            host_key = self._extract_key(event, "host")
            if host_key:
                self.events_by_host.setdefault(host_key, []).append(event)

        # ------------------------------------------------------------------
        # PASS 2: Enrich timeline into EventContext objects
        # ------------------------------------------------------------------
        contexts: list[EventContext] = []
        total_events = len(timeline)

        for i, event in enumerate(timeline):
            event_id = event.get("event_id")
            entity_id = self.entity_map.get(event_id) if event_id else None

            process_key = self._extract_key(event, "process_id")
            path_key = self._extract_path_key(event)
            user_key = self._extract_key(event, "user")
            logon_key = self._extract_key(event, "logon_id")
            host_key = self._extract_key(event, "host")

            context = EventContext(
                event=event,
                entity_id=entity_id,
                previous_event=timeline[i - 1] if i > 0 else None,
                next_event=timeline[i + 1] if i + 1 < total_events else None,
                same_entity=self._related(self.events_by_entity.get(entity_id), event) if entity_id else [],
                same_process=self._related(self.events_by_process.get(process_key), event) if process_key else [],
                same_path=self._related(self.events_by_path.get(path_key), event) if path_key else [],
                same_user=self._related(self.events_by_user.get(user_key), event) if user_key else [],
                same_logon=self._related(self.events_by_logon.get(logon_key), event) if logon_key else [],
                same_host=self._related(self.events_by_host.get(host_key), event) if host_key else [],
            )

            contexts.append(context)

        return contexts

    # ------------------------------------------------------------------
    # Helper routines
    # ------------------------------------------------------------------
    @staticmethod
    def _related(events: list[dict] | None, current: dict) -> list[dict]:
        """Return all events in list except the current event instance."""
        if not events:
            return []
        return [e for e in events if e is not current]

    @staticmethod
    def _extract_key(event: dict, field_name: str) -> str | None:
        """Extract and normalize a single standard field value."""
        val = event.get(field_name)
        return str(val).strip().lower() if val is not None else None

    @staticmethod
    def _extract_path_key(event: dict) -> str | None:
        """Raw object_path/object_name string key — see same_path's warning."""
        val = event.get("object_path") or event.get("object_name")
        return str(val).strip().lower() if val is not None else None
    



@dataclass(slots=True)
class RuleContext:
    """
    Everything a correlation rule needs, bundled behind one argument so
    Rule.run(context) stays true to the single-argument API decided
    early on.

    `timeline` preserves chronological order (same order fed to
    ContextBuilder.build()). `index` is the ContextBuilder itself,
    exposing every events_by_* index built during that pass, so a rule
    can look up "all events for this entity/user/path" in O(1) instead
    of rescanning `timeline`. `entities` is the resolver's output
    (entity_id -> Entity), for rules needing an entity's canonical_path
    or aliases rather than just its member events.
    """

    timeline: list[EventContext]
    index: "ContextBuilder"
    entities: dict[str, Entity]