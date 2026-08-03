"""Extracted artifact context -> deterministic inventory summary.

This module is the second stage of the inventory-enrichment pipeline:

    DiscoveryEngine (unsupported artifacts)
            v
    InventoryContextExtractor.extract()   (per-artifact context dicts)
            v
    InventoryContextBuilder.build()        <- this module
            v
    IncidentAnalysisPromptBuilder.build()

``InventoryContextBuilder`` never reads a file, never inspects artifact
content, and never reasons about what any artifact means. It only
reshapes a list of already-extracted context dicts into a small,
deterministic *summary* of the unsupported-artifact inventory -- not a
verbatim pass-through of every artifact the extractor saw.

This class produces a strictly evidence-oriented summary without any
forensic reasoning or hardcoded semantic classification:

    - artifacts are grouped by the already-computed structural
      ``category`` field (csv, json, xml, sqlite, text, log, markdown,
      binary, unreadable, ...) -- never by filename content or
      forensic meaning,
    - each group is capped to a bounded number of representative
      artifacts so the prompt stays small,
    - each representative artifact keeps real structural context
      (name, path, description, a short content glimpse, column
      names, etc.) the extractor already attached to it, so the
      renderer downstream has real values to print instead of empty
      fields -- but that content is condensed to a bounded size here,
      not passed through at the extractor's full preview length. The
      extractor's job is to capture as much structural evidence as is
      useful for a file of that type; this builder's job is to
      reduce that into something a fixed prompt budget can hold. Both
      docstrings already say this ("concise ... summary" /
      "a concise, deterministic summary") -- the size budget was
      always meant to live here, not in the extractor or the
      renderer (the renderer's own docstring explicitly disclaims
      deciding sizes: "pure formatting").

No path is ever repeated; artifacts are de-duplicated up front.

Output contract
----------------
``build()`` returns ``list[dict]``, one dict per category, each shaped
as::

    {
        "category": <str>,
        "count": <int>,               # total unique artifacts in this category
        "artifacts": [<artifact dict>, ...],  # up to max_representatives_per_category
    }

This is the exact "grouped" shape ``IncidentAnalysisPromptBuilder``
already documents and expects (see its
``_build_inventory_context``/``_is_grouped`` docstrings) -- every
element of the returned list carries an ``"artifacts"`` key, so the
renderer takes its grouped-rendering path instead of falling back to
treating a summary object as if it were a single artifact.

An empty input returns an empty list.
"""

from __future__ import annotations


class InventoryContextBuilder:
    """Reduce per-artifact context dicts (as produced by

    ``InventoryContextExtractor.extract()``) into a concise, fully
    deterministic, per-category summary passed to
    ``IncidentAnalysisPromptBuilder``.

    This class performs no forensic reasoning and creates no normalized
    events. It only deduplicates, groups by the extractor's structural
    ``category`` field, and selects representative artifacts per
    category based on discovery order.
    """

    def __init__(
        self,
        max_representatives_per_category: int = 3,
        max_preview_chars: int = 150,
        max_preview_rows: int = 2,
        max_list_items: int = 6,
    ) -> None:
        """Parameters

        ----------
        max_representatives_per_category:
            Maximum number of representative artifacts retained per
            category to keep the prompt context bounded. Lowered from
            an earlier default of 5: combined with the per-artifact
            content caps below, this is what actually keeps total
            inventory prompt size predictable -- capping only the
            artifact *count* while still passing through each
            artifact's full-length preview/rows/columns still lets a
            handful of categories balloon the prompt (up to
            ~500 chars of preview per artifact, times up to 8
            categories, was previously producing 20K+ character
            inventory sections from a single incident).
        max_preview_chars:
            Maximum characters of any text/JSON/XML preview kept per
            artifact. The extractor may capture up to 500 characters
            (its job: capture enough to be useful for a file of that
            type); this is a further, prompt-specific reduction, not
            a change to what the extractor stores.
        max_preview_rows:
            Maximum CSV preview rows kept per artifact.
        max_list_items:
            Maximum entries kept for list-shaped fields (columns,
            tables, top-level JSON keys).
        """
        self.max_representatives_per_category = max_representatives_per_category
        self.max_preview_chars = max_preview_chars
        self.max_preview_rows = max_preview_rows
        self.max_list_items = max_list_items

    def build(self, extracted_artifacts: list[dict]) -> list[dict]:
        """Parameters

        ----------
        extracted_artifacts:
            A list of dicts, each produced by
            ``InventoryContextExtractor.extract()``. May be empty.

        Returns
        -------
        A list of category-group dicts, shaped as::

            {
                "category": <str>,
                "count": <int>,
                "artifacts": [<artifact dict>, ...],
            }

        Groups are sorted alphabetically by category. Within a
        category, artifacts are selected based on discovery order
        (to preserve high-signal artifacts appearing early), then
        sorted deterministically (by path, falling back to name) for
        stable output. ``count`` is the total number of unique
        artifacts in that category -- not just the number of examples
        shown, which may be fewer once capped at
        ``max_representatives_per_category``.

        An empty input returns an empty list.
        """
        deduplicated = self._deduplicate(extracted_artifacts or [])
        grouped = self._group_by_category(deduplicated)

        return [
            {
                "category": category,
                "count": len(artifacts),
                "artifacts": self._select_representatives(artifacts),
            }
            for category, artifacts in sorted(grouped.items())
        ]

    # ------------------------------------------------------------------
    # De-duplication
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(artifacts: list[dict]) -> list[dict]:
        """Drop exact repeats of the same artifact (identified by path,

        falling back to name when no path is available), keeping the
        first occurrence (preserving discovery order).
        """
        seen_keys: set[str] = set()
        unique: list[dict] = []

        for artifact in artifacts:
            artifact = artifact or {}
            key = artifact.get("path") or artifact.get("name")

            if key is not None:
                if key in seen_keys:
                    continue
                seen_keys.add(key)

            unique.append(artifact)

        return unique

    # ------------------------------------------------------------------
    # Grouping by structural category
    # ------------------------------------------------------------------

    @staticmethod
    def _group_by_category(artifacts: list[dict]) -> dict[str, list[dict]]:
        """Group deduplicated artifact dicts by their ``category`` field,

        preserving discovery order within each group. Uses "unknown"
        for any artifact missing a category, mirroring the previous
        summary's fallback.
        """
        grouped: dict[str, list[dict]] = {}

        for artifact in artifacts:
            art_dict = artifact or {}
            category = art_dict.get("category") or "unknown"
            grouped.setdefault(category, []).append(art_dict)

        return grouped

    # ------------------------------------------------------------------
    # Representative artifacts per category
    # ------------------------------------------------------------------

    def _select_representatives(self, artifacts: list[dict]) -> list[dict]:
        """Select up to ``max_representatives_per_category`` artifacts,

        chosen by discovery order (first N discovered, to preserve
        high-signal artifacts appearing early), then sorted
        deterministically for stable output. Returns condensed copies
        of the extractor's artifact dicts -- real name/path/
        description/preview values, but with content-bearing fields
        (preview text, preview rows, columns, tables, JSON keys)
        trimmed to this builder's bounded caps. See ``_condense`` for
        what is and isn't touched.
        """
        selected = artifacts[: self.max_representatives_per_category]

        ordered = sorted(
            selected,
            key=lambda artifact: (
                str((artifact or {}).get("path") or ""),
                str((artifact or {}).get("name") or ""),
            ),
        )

        return [self._condense(artifact) for artifact in ordered]

    def _condense(self, artifact: dict) -> dict:
        """Return a shallow copy of ``artifact`` with content-bearing

        fields trimmed to this builder's bounded caps. Never mutates
        the extractor's original dict (other consumers of the same
        extracted list, if any, should still see the full-size
        values). Fields the extractor didn't attach for this
        artifact's category are left absent, exactly as before --
        this only ever shortens a field that is already present, it
        never adds one.
        """
        artifact = dict(artifact or {})

        if "preview" in artifact:
            preview = str(artifact.get("preview") or "")
            if len(preview) > self.max_preview_chars:
                artifact["preview"] = preview[: self.max_preview_chars]
                artifact["preview_truncated"] = True

        if "preview_rows" in artifact:
            rows = artifact.get("preview_rows") or []
            if len(rows) > self.max_preview_rows:
                artifact["preview_rows"] = rows[: self.max_preview_rows]

        if "columns" in artifact:
            columns = artifact.get("columns") or []
            if len(columns) > self.max_list_items:
                artifact["columns"] = columns[: self.max_list_items]

        if "tables" in artifact:
            tables = artifact.get("tables") or []
            if len(tables) > self.max_list_items:
                artifact["tables"] = tables[: self.max_list_items]

        if "top_level_keys" in artifact:
            keys = artifact.get("top_level_keys") or []
            if len(keys) > self.max_list_items:
                artifact["top_level_keys"] = keys[: self.max_list_items]

        return artifact
