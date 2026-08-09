"""Raw model text -> validated IOCReport boundary.

Mirrors QwenValidator's role for the incident-validation agent: this
class makes no forensic decisions and does not judge whether an IOC
is "right". It only checks that the model's response is well-formed
JSON matching the required contract, attempts a small, well-defined
set of mechanical repairs when it is not, and converts a valid
payload into an IOCReport. Anything it cannot confidently repair is
reported back via IOCValidationError so the caller (IOCExtractionAgent)
can decide whether to re-ask the model.
"""

from __future__ import annotations

import json
import re
from typing import Any

from modules.llm.ioc_models import IOC, IOC_REQUIRED_FIELDS, IOCConfidence, IOCReport, IOCType


class IOCValidationError(Exception):
    """Raised when the model's response cannot be parsed/repaired into
    a valid IOCReport."""


class QwenIOCValidator:
    """Parse, repair, and validate the IOC Extraction Agent's raw
    response into an IOCReport."""

    def validate(self, raw_response: str) -> IOCReport:
        """Parse `raw_response` into an IOCReport.

        Raises IOCValidationError if the response cannot be parsed as
        JSON (even after mechanical repair attempts) or does not match
        the required top-level shape (`{"iocs": [...]}`).

        Individual malformed IOC entries inside an otherwise valid
        payload are dropped rather than failing the whole batch --
        see `_build_report` -- since one bad entry should not discard
        every other genuinely valid IOC in the same response.
        """

        parsed = self._parse_json(raw_response)
        self._validate_top_level(parsed)
        return self._build_report(parsed)

    # ------------------------------------------------------------------
    # Parsing + mechanical repair
    # ------------------------------------------------------------------

    _CODE_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE | re.MULTILINE)
    _TRAILING_COMMA = re.compile(r",\s*([}\]])")

    @classmethod
    def _parse_json(cls, raw_response: str) -> Any:
        candidates = [raw_response]

        stripped = cls._CODE_FENCE.sub("", raw_response).strip()
        if stripped != raw_response:
            candidates.append(stripped)

        extracted = cls._extract_balanced_object(stripped)
        if extracted is not None:
            candidates.append(extracted)

        for candidate in list(candidates):
            no_trailing_commas = cls._TRAILING_COMMA.sub(r"\1", candidate)
            if no_trailing_commas != candidate:
                candidates.append(no_trailing_commas)

        last_error: json.JSONDecodeError | None = None
        for candidate in candidates:
            try:
                return json.loads(candidate)
            except json.JSONDecodeError as error:
                last_error = error
                continue

        raise IOCValidationError(
            f"Model response is not valid JSON, even after repair attempts: {last_error}"
        )

    @staticmethod
    def _extract_balanced_object(text: str) -> str | None:
        """Extract the first top-level, brace-balanced `{...}` substring.

        Handles the common case of the model wrapping valid JSON with
        stray prose before/after it, without attempting to fix
        genuinely malformed JSON inside the braces.
        """

        start = text.find("{")
        if start == -1:
            return None

        depth = 0
        in_string = False
        escape = False

        for index in range(start, len(text)):
            char = text[index]

            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == '"':
                    in_string = False
                continue

            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start : index + 1]

        return None

    # ------------------------------------------------------------------
    # Structural validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_top_level(parsed: Any) -> None:
        if not isinstance(parsed, dict):
            raise IOCValidationError(
                f"Model response must be a JSON object, got {type(parsed).__name__}"
            )

        if "iocs" not in parsed:
            raise IOCValidationError("Model response is missing the required 'iocs' key")

        if not isinstance(parsed["iocs"], list):
            raise IOCValidationError(
                f"'iocs' must be a JSON array, got {type(parsed['iocs']).__name__}"
            )

    def _build_report(self, parsed: dict) -> IOCReport:
        iocs: list[IOC] = []

        for entry in parsed["iocs"]:
            ioc = self._build_one_ioc(entry)
            if ioc is not None:
                iocs.append(ioc)

        return IOCReport(iocs=self._deduplicate(iocs))

    def _build_one_ioc(self, entry: Any) -> IOC | None:
        if not isinstance(entry, dict):
            return None

        missing = [f for f in IOC_REQUIRED_FIELDS if f not in entry]
        if missing:
            return None

        value = entry.get("value")
        source = entry.get("source")
        reason = entry.get("reason")

        if not isinstance(value, str) or not value.strip():
            return None
        if not isinstance(source, str) or not source.strip():
            return None
        if not isinstance(reason, str) or not reason.strip():
            return None

        ioc_type, original_type = IOCType.coerce(entry.get("type"))
        if original_type is not None:
            reason = f"[reported type: {original_type}] {reason}"

        confidence = IOCConfidence.coerce(entry.get("confidence"))

        return IOC(
            type=ioc_type,
            value=value.strip(),
            confidence=confidence,
            source=source.strip(),
            reason=reason.strip(),
        )

    @staticmethod
    def _deduplicate(iocs: list[IOC]) -> list[IOC]:
        seen: set[tuple[str, str]] = set()
        deduplicated: list[IOC] = []
        for ioc in iocs:
            key = (ioc.type.value, ioc.value)
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(ioc)
        return deduplicated
