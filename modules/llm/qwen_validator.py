"""Prompt -> ValidationResult boundary for the future Qwen integration.

This module sends a prompt to the model and turns its response into a
structured Python object. It makes no forensic decisions of its own: it
does not compare the model's opinion against the deterministic engine,
does not merge anything, and does not compute severity or confidence.
It only validates that the model answered in the required shape and
converts that answer into ``ValidationResult``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ValidationVerdict(str, Enum):
    """
    The model's overall verdict on whether the supplied correlations
    belong to a single incident.
    """

    AGREE = "AGREE"
    PARTIALLY_AGREE = "PARTIALLY_AGREE"
    DISAGREE = "DISAGREE"


@dataclass(slots=True)
class ValidationResult:
    """
    The structured result of validating one incident with the model.
    """

    verdict: ValidationVerdict
    confidence: float
    reasoning: str
    suggested_additions: list[str] = field(default_factory=list)
    suggested_removals: list[str] = field(default_factory=list)


class QwenValidationError(Exception):
    """
    Raised when the model's response does not conform to the required
    JSON contract. Malformed responses are never silently ignored.
    """


class QwenValidator:
    """
    Send a prompt to the model and convert its response into a
    ValidationResult.

    This class only transforms Prompt -> ValidationResult. It does not
    decide whether the model is "right", does not compare its output
    against the deterministic engine's conclusions, and does not touch
    any incident, correlation, or graph data directly.
    """

    _REQUIRED_FIELDS = (
        "verdict",
        "confidence",
        "reasoning",
        "suggested_additions",
        "suggested_removals",
    )

    def validate(self, prompt: str) -> ValidationResult:
        """
        Send `prompt` to the model, validate its response, and return
        a ValidationResult.

        Raises QwenValidationError if the response is not valid JSON
        or does not conform to the required structure.
        """

        raw_response = self._call_model(prompt)
        parsed = self._parse_json(raw_response)
        self._validate_json(parsed)

        return self._build_result(parsed)

    @staticmethod
    def _call_model(prompt: str) -> str:
        """
        Send `prompt` to the local model backend and return its raw
        text response.

        PLACEHOLDER: real model communication (Ollama, llama.cpp, or
        otherwise) is intentionally NOT implemented in this PR. This
        method is the single, isolated seam where that integration
        will be added later, so swapping backends only ever means
        changing the body of this one method -- nothing else in
        QwenValidator depends on how the model is actually reached.

        For now this returns a mock JSON response matching the
        contract IncidentPromptBuilder instructs the model to use, so
        the rest of the pipeline (parsing, validation, and result
        construction) can be built and tested end-to-end today.
        """

        # Temporary mock implementation.
        # This method will later call the local Qwen backend
        # through Ollama.
        return json.dumps(
            {
                "verdict": "AGREE",
                "confidence": 0.75,
                "reasoning": (
                    "Placeholder response: no model backend is connected yet. "
                    "This mock exists only to exercise the parsing and "
                    "validation path."
                ),
                "suggested_additions": [],
                "suggested_removals": [],
            }
        )

    @staticmethod
    def _parse_json(raw_response: str) -> Any:
        """
        Parse the model's raw text response as JSON.

        Raises QwenValidationError if the response is not valid JSON.
        """

        try:
            return json.loads(raw_response)
        except (TypeError, json.JSONDecodeError) as error:
            raise QwenValidationError(
                f"Model response is not valid JSON: {error}"
            ) from error

    @classmethod
    def _validate_json(cls, parsed: Any) -> None:
        """
        Validate that the parsed response conforms to the required
        structure.

        Raises QwenValidationError on any violation.
        """

        if not isinstance(parsed, dict):
            raise QwenValidationError(
                f"Model response must be a JSON object, got {type(parsed).__name__}"
            )

        missing_fields = [
            field_name for field_name in cls._REQUIRED_FIELDS if field_name not in parsed
        ]

        if missing_fields:
            raise QwenValidationError(
                f"Model response is missing required fields: {sorted(missing_fields)}"
            )

        verdict = parsed["verdict"]
        valid_verdicts = {member.value for member in ValidationVerdict}

        if verdict not in valid_verdicts:
            raise QwenValidationError(
                f"Model response has an invalid verdict: {verdict!r}. "
                f"Expected one of {sorted(valid_verdicts)}"
            )

        confidence = parsed["confidence"]

        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise QwenValidationError(
                f"Model response 'confidence' must be numeric, got {type(confidence).__name__}"
            )

        if not isinstance(parsed["reasoning"], str):
            raise QwenValidationError(
                "Model response 'reasoning' must be a string, got "
                f"{type(parsed['reasoning']).__name__}"
            )

        for field_name in ("suggested_additions", "suggested_removals"):
            value = parsed[field_name]

            if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value
            ):
                raise QwenValidationError(
                    f"Model response '{field_name}' must be a list of strings"
                )

    @staticmethod
    def _build_result(parsed: dict) -> ValidationResult:
        """
        Convert a validated JSON payload into a ValidationResult.
        """

        return ValidationResult(
            verdict=ValidationVerdict(parsed["verdict"]),
            confidence=float(parsed["confidence"]),
            reasoning=parsed["reasoning"],
            suggested_additions=list(parsed["suggested_additions"]),
            suggested_removals=list(parsed["suggested_removals"]),
        )
