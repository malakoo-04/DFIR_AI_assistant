"""Extracted artifact context -> deterministic inventory context.

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
reshapes a list of already-extracted context dicts -- sorting them
deterministically, grouping them by category, and removing exact
duplicate entries -- so that IncidentAnalysisPromptBuilder receives a
stable, organized structure to format rather than an arbitrary bag of
dicts in scan order.
"""

from __future__ import annotations


class InventoryContextBuilder:
    """
    Combine per-artifact context dicts (as produced by
    ``InventoryContextExtractor.extract()``) into the final inventory
    context passed to ``IncidentAnalysisPromptBuilder``.

    This class performs no forensic reasoning and creates no normalized
    events. Every preview, structural field (columns, tables, root
    tags, etc.), and metadata value produced by the extractor passes
    through unchanged -- this class only decides where each artifact
    sits relative to the others.
    """

    def build(self, extracted_artifacts: list[dict]) -> list[dict]:
        """
        Parameters
        ----------
        extracted_artifacts:
            A list of dicts, each produced by
            ``InventoryContextExtractor.extract()``. May be empty.

        Returns
        -------
        A list of category groups, each shaped as::

            {
                "category": <str>,
                "count": <int>,
                "artifacts": [<dict>, ...],
            }

        sorted by category name, with the artifacts inside each group
        de-duplicated and sorted deterministically by path/name. An
        empty input returns an empty list.
        """

        deduplicated = self._deduplicate(extracted_artifacts or [])
        grouped = self._group_by_category(deduplicated)

        return self._build_sorted_groups(grouped)

    # ------------------------------------------------------------------
    # De-duplication
    # ------------------------------------------------------------------

    @staticmethod
    def _deduplicate(artifacts: list[dict]) -> list[dict]:
        """
        Drop exact repeats of the same artifact (identified by path,
        falling back to name when no path is available), keeping the
        first occurrence. This only catches the same artifact appearing
        twice in the input -- it never merges or reconciles two
        genuinely different artifacts.
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
    # Grouping
    # ------------------------------------------------------------------

    @staticmethod
    def _group_by_category(artifacts: list[dict]) -> dict[str, list[dict]]:
        groups: dict[str, list[dict]] = {}

        for artifact in artifacts:
            category = (artifact or {}).get("category") or "unknown"
            groups.setdefault(category, []).append(artifact)

        return groups

    @staticmethod
    def _build_sorted_groups(groups: dict[str, list[dict]]) -> list[dict]:
        result = []

        for category in sorted(groups.keys()):
            artifacts = sorted(
                groups[category],
                key=lambda artifact: (
                    str((artifact or {}).get("path") or ""),
                    str((artifact or {}).get("name") or ""),
                ),
            )
            result.append(
                {
                    "category": category,
                    "count": len(artifacts),
                    "artifacts": artifacts,
                }
            )

        return result
