"""Unsupported artifact -> structured AI context.

This module sits next to the deterministic parsers, not inside them. The
parsers in ``modules/parsers`` turn *known* artifact formats into
normalized DFIR events. ``InventoryContextExtractor`` handles everything
that isn't one of those: KAPE summary/console/copy/skip logs, ransom
notes, unsupported artifact types, or any other file the discovery scan
found but no parser understands.

Its only job is to stop that information from being silently lost.
Right now, an unsupported file reaches the LLM as bare filesystem
metadata (name, path, size, timestamps) -- everything about its actual
content is invisible. This module exposes a small amount of *structural*
information about that content -- a short preview, column names, table
names, encoding, line counts -- without ever interpreting what that
content forensically means.

This module must NEVER:
    - parse forensic meaning out of file contents,
    - create normalized events,
    - classify incidents,
    - infer attack activity from a preview, a column name, or a table
      name.

It only answers "what kind of thing is this file, structurally, and
what does a safe sample of it look like" -- nothing more. Every value
returned is JSON-compatible (str, int, bool, list, dict, or None).
"""

from __future__ import annotations

import csv
import json
import sqlite3
import xml.etree.ElementTree as ET
from dataclasses import fields, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


class InventoryContextExtractor:
    """
    Convert one unsupported/unparsed artifact into a structured,
    JSON-compatible context dict.

    Accepts a single artifact description -- a ``modules.discovery``
    ``Artifact`` dataclass, a plain dict shaped like
    ``Inventory.export_json()``'s output, or a bare path -- and always
    returns a plain dict. Reading and inspecting the file never raises
    out of ``extract()``: any failure is recorded in the returned dict's
    ``error`` field instead, since one unreadable artifact should never
    prevent the rest of the inventory from reaching the LLM.
    """

    # Bytes/lines/rows kept in previews. Deliberately small: this is
    # context for an LLM prompt, not a data export.
    PREVIEW_CHARS = 500
    PREVIEW_LINES = 20
    CSV_PREVIEW_ROWS = 5
    JSON_PREVIEW_CHARS = 500

    # Cap on how much of a file is actually read into memory for
    # preview/decoding purposes. Full-file line counts still scan the
    # whole file, but do so as a byte stream (see _count_lines) rather
    # than loading it all at once.
    MAX_PREVIEW_SCAN_BYTES = 2_000_000

    MARKDOWN_EXTENSIONS = {".md", ".markdown"}
    CSV_EXTENSIONS = {".csv", ".tsv"}
    JSON_EXTENSIONS = {".json"}
    XML_EXTENSIONS = {".xml"}
    SQLITE_EXTENSIONS = {".db", ".sqlite", ".sqlite3"}
    TEXT_LIKE_EXTENSIONS = {".txt", ".ini", ".cfg", ".conf", ".md", ".markdown"}

    SQLITE_MAGIC = b"SQLite format 3\x00"

    def extract(self, artifact: Any) -> dict:
        """
        Build the structured context dict for one artifact.

        Never raises: any failure to locate, open, or interpret the
        artifact is captured as ``{"category": "unreadable", "error":
        "..."}`` alongside whatever metadata was available, so a
        single bad file cannot break processing of the rest of the
        inventory.
        """

        try:
            metadata, path = self._normalize(artifact)
        except Exception as error:
            return {
                "name": None,
                "path": None,
                "category": "unreadable",
                "error": f"could not interpret artifact input: {error}",
            }

        result = dict(metadata)

        if path is None or not path.is_file():
            result["category"] = "unreadable"
            result["error"] = "artifact path is missing or is not a readable file"
            return result

        try:
            category = self._detect_category(path)
            result["category"] = category
            result.update(self._extract_by_category(path, category))
        except Exception as error:
            result["category"] = "unreadable"
            result["error"] = f"failed to extract context: {error}"

        return result

    # ------------------------------------------------------------------
    # Input normalization
    # ------------------------------------------------------------------

    @classmethod
    def _normalize(cls, artifact: Any) -> tuple[dict, Path | None]:
        """
        Accept an ``Artifact`` dataclass, a plain dict (as produced by
        ``Inventory.export_json()`` or ``DiscoveryEngine``'s unknown-file
        export), or a bare path/string, and return (metadata, path).
        """

        if isinstance(artifact, (str, Path)):
            path = Path(artifact)
            return (
                {
                    "name": path.name,
                    "path": str(path),
                    "size": None,
                    "created": None,
                    "modified": None,
                    "accessed": None,
                    "description": None,
                },
                path,
            )

        if is_dataclass(artifact) and not isinstance(artifact, type):
            as_dict = {
                field.name: getattr(artifact, field.name) for field in fields(artifact)
            }
            return cls._normalize_dict(as_dict)

        if isinstance(artifact, dict):
            return cls._normalize_dict(artifact)

        raise TypeError(f"unsupported artifact input type: {type(artifact).__name__}")

    @classmethod
    def _normalize_dict(cls, artifact: dict) -> tuple[dict, Path | None]:
        path_value = artifact.get("path")
        path = Path(path_value) if path_value else None

        artifact_type = artifact.get("artifact_type") or artifact.get("type")
        if hasattr(artifact_type, "value"):
            artifact_type = artifact_type.value

        metadata = {
            "name": artifact.get("name") or (path.name if path else None),
            "path": str(path) if path else None,
            "size": artifact.get("size"),
            "created": cls._iso(artifact.get("created")),
            "modified": cls._iso(artifact.get("modified")),
            "accessed": cls._iso(artifact.get("accessed")),
            "description": artifact.get("description"),
        }

        if artifact_type is not None:
            metadata["artifact_type"] = artifact_type

        return metadata, path

    @staticmethod
    def _iso(value: Any) -> Any:
        """Coerce a datetime to ISO-8601; pass through anything else."""
        if isinstance(value, datetime):
            return value.isoformat()
        return value

    # ------------------------------------------------------------------
    # Category detection
    # ------------------------------------------------------------------

    @classmethod
    def _detect_category(cls, path: Path) -> str:
        name_lower = path.name.lower()
        suffix = path.suffix.lower()

        if "readme" in name_lower or suffix in cls.MARKDOWN_EXTENSIONS:
            return "markdown"
        if suffix in cls.CSV_EXTENSIONS:
            return "csv"
        if suffix in cls.JSON_EXTENSIONS:
            return "json"
        if suffix in cls.XML_EXTENSIONS:
            return "xml"
        if suffix in cls.SQLITE_EXTENSIONS or cls._looks_like_sqlite(path):
            return "sqlite"
        if suffix == ".log" or "log" in name_lower:
            return "log"
        if suffix in cls.TEXT_LIKE_EXTENSIONS:
            return "text"
        if cls._looks_like_text(path):
            return "text"

        return "binary"

    @staticmethod
    def _looks_like_sqlite(path: Path) -> bool:
        try:
            with open(path, "rb") as handle:
                header = handle.read(16)
        except OSError:
            return False
        return header.startswith(InventoryContextExtractor.SQLITE_MAGIC)

    @staticmethod
    def _looks_like_text(path: Path) -> bool:
        """
        A cheap, deterministic heuristic: a NUL byte in the first
        sample is treated as a binary signal; otherwise, if the sample
        decodes as UTF-8 or Latin-1, treat it as text. This never reads
        more than one small sample.
        """

        try:
            with open(path, "rb") as handle:
                sample = handle.read(512)
        except OSError:
            return False

        if b"\x00" in sample:
            return False

        for encoding in ("utf-8", "latin-1"):
            try:
                sample.decode(encoding)
                return True
            except UnicodeDecodeError:
                continue

        return False

    # ------------------------------------------------------------------
    # Per-category extraction
    # ------------------------------------------------------------------

    def _extract_by_category(self, path: Path, category: str) -> dict:
        if category in ("text", "log", "markdown"):
            return self._extract_text(path)
        if category == "csv":
            return self._extract_csv(path)
        if category == "json":
            return self._extract_json(path)
        if category == "xml":
            return self._extract_xml(path)
        if category == "sqlite":
            return self._extract_sqlite(path)
        # "binary" and anything else: metadata only, no structured
        # content -- there is nothing safe or meaningful to preview.
        return {}

    def _extract_text(self, path: Path) -> dict:
        """
        Preview + encoding + an exact line count.

        The preview is capped (PREVIEW_LINES / PREVIEW_CHARS) so large
        files never bloat the prompt. The line count is NOT derived
        from that capped preview -- it is a full-file count of newline
        bytes, streamed in fixed-size chunks so memory use stays
        constant regardless of file size. An estimate dressed up as an
        exact count has no place in a forensic tool, so if a number is
        reported here, it is the real count, not a preview-based guess.
        """

        with open(path, "rb") as handle:
            head = handle.read(self.MAX_PREVIEW_SCAN_BYTES)

        text, encoding = self._decode_best_effort(head)
        preview_lines = text.splitlines()[: self.PREVIEW_LINES]
        preview = "\n".join(preview_lines)
        preview_truncated = len(preview) > self.PREVIEW_CHARS or len(
            text.splitlines()
        ) > self.PREVIEW_LINES

        if len(preview) > self.PREVIEW_CHARS:
            preview = preview[: self.PREVIEW_CHARS]

        return {
            "preview": preview,
            "preview_truncated": preview_truncated,
            "encoding": encoding,
            "lines": self._count_lines(path),
        }

    @staticmethod
    def _count_lines(path: Path) -> int:
        count = 0
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                count += chunk.count(b"\n")
        return count

    def _extract_csv(self, path: Path) -> dict:
        """Column names + a small row preview. Never the full file."""

        for encoding in ("utf-8", "latin-1"):
            try:
                rows = self._read_csv_rows(path, encoding)
                break
            except UnicodeDecodeError:
                continue
        else:
            return {"error": "could not decode CSV with a supported encoding"}

        columns = rows[0] if rows else []
        preview_rows = rows[1:] if len(rows) > 1 else []

        return {
            "columns": columns,
            "preview_rows": preview_rows,
            "encoding": encoding,
        }

    def _read_csv_rows(self, path: Path, encoding: str) -> list[list[str]]:
        rows: list[list[str]] = []
        with open(path, "r", encoding=encoding, newline="") as handle:
            reader = csv.reader(handle)
            for _ in range(self.CSV_PREVIEW_ROWS + 1):  # header + preview rows
                try:
                    rows.append(next(reader))
                except StopIteration:
                    break
        return rows

    def _extract_json(self, path: Path) -> dict:
        """
        A short raw preview, plus structural facts (is it valid JSON,
        is the top level an object or array, what are its top-level
        keys / how many items) -- never the interpreted meaning of the
        data.
        """

        raw = path.read_text(encoding="utf-8", errors="replace")
        preview = raw[: self.JSON_PREVIEW_CHARS]
        result = {
            "preview": preview,
            "preview_truncated": len(raw) > self.JSON_PREVIEW_CHARS,
        }

        try:
            parsed = json.loads(raw)
        except (json.JSONDecodeError, ValueError) as error:
            result["json_valid"] = False
            result["error"] = f"invalid JSON: {error}"
            return result

        result["json_valid"] = True

        if isinstance(parsed, dict):
            result["json_type"] = "object"
            result["top_level_keys"] = sorted(str(key) for key in parsed.keys())
        elif isinstance(parsed, list):
            result["json_type"] = "array"
            result["item_count"] = len(parsed)
        else:
            result["json_type"] = type(parsed).__name__

        return result

    def _extract_xml(self, path: Path) -> dict:
        """A short raw preview, plus the root tag name if parseable."""

        with open(path, "rb") as handle:
            head = handle.read(self.MAX_PREVIEW_SCAN_BYTES)

        text, encoding = self._decode_best_effort(head)
        preview = text[: self.PREVIEW_CHARS]

        result = {
            "preview": preview,
            "preview_truncated": len(text) > self.PREVIEW_CHARS,
            "encoding": encoding,
        }

        try:
            root = ET.fromstring(path.read_bytes())
            result["xml_valid"] = True
            result["root_tag"] = root.tag
        except ET.ParseError as error:
            result["xml_valid"] = False
            result["error"] = f"invalid XML: {error}"

        return result

    @staticmethod
    def _extract_sqlite(path: Path) -> dict:
        """Table names only -- no row data, no row counts, no content."""

        try:
            uri = f"{path.resolve().as_uri()}?mode=ro"
            connection = sqlite3.connect(uri, uri=True)
        except sqlite3.Error as error:
            return {"error": f"failed to open sqlite database: {error}"}

        try:
            cursor = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
            tables = [row[0] for row in cursor.fetchall()]
        except sqlite3.Error as error:
            return {"error": f"failed to read sqlite schema: {error}"}
        finally:
            connection.close()

        return {"tables": tables}

    # ------------------------------------------------------------------
    # Shared decoding helper
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_best_effort(chunk: bytes) -> tuple[str, str]:
        """
        Try a short list of common encodings before falling back to a
        lossy decode. The returned encoding name is honest: if nothing
        decoded cleanly, it says so rather than silently mislabeling
        the result as a specific encoding it never actually matched.
        """

        for encoding in ("utf-8", "utf-16", "cp1252"):
            try:
                return chunk.decode(encoding), encoding
            except UnicodeDecodeError:
                continue

        return chunk.decode("utf-8", errors="replace"), "unknown (best-effort decode)"
