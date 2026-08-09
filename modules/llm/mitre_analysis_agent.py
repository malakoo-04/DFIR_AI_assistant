from __future__ import annotations

import os
import time
from dataclasses import dataclass

from dotenv import load_dotenv
from google import genai

from modules.llm.mitre_analysis_prompt_builder import (
    MitreAnalysisPromptBuilder,
)
from modules.llm.mitre_models import MitreReport
from modules.llm.mitre_validator import (
    GeminiMitreValidator,
    MitreValidationError,
)

load_dotenv()


# ---------------------------------------------------------
# Result
# ---------------------------------------------------------

@dataclass(slots=True, frozen=True)
class MitreAnalysisResult:

    report: MitreReport
    raw_response: str
    prompt: str
    model_name: str
    temperature: float
    duration_seconds: float
    attempts: int
    incident_count: int


# ---------------------------------------------------------
# Exceptions
# ---------------------------------------------------------

class MitreAnalysisError(Exception):
    pass


class MitrePromptError(MitreAnalysisError):
    pass


class MitreModelError(MitreAnalysisError):
    pass


class MitreValidationFailure(MitreAnalysisError):
    pass


# ---------------------------------------------------------
# Agent
# ---------------------------------------------------------

class MitreAnalysisAgent:

    def __init__(

        self,

        prompt_builder: MitreAnalysisPromptBuilder | None = None,

        validator: GeminiMitreValidator | None = None,

        model_name: str = "gemini-3.5-flash",

        temperature: float = 0.0,

        max_retries: int = 2,

    ):

        self._prompt_builder = (
            prompt_builder
            or MitreAnalysisPromptBuilder()
        )

        self._validator = (
            validator
            or GeminiMitreValidator()
        )

        self._model_name = model_name
        self._temperature = temperature
        self._max_retries = max_retries

    # -----------------------------------------------------

    def extract(
        self,
        prioritized_incidents: list[dict],
    ) -> MitreAnalysisResult:

        prompt = self._build_prompt(
            prioritized_incidents
        )

        start = time.perf_counter()

        raw_response, attempts = (
            self._call_with_retries(prompt)
        )

        duration = time.perf_counter() - start

        try:

            report = self._validator.validate(
                raw_response
            )

        except MitreValidationError as error:

            raise MitreValidationFailure(
                str(error)
            ) from error

        return MitreAnalysisResult(

            report=report,

            raw_response=raw_response,

            prompt=prompt,

            model_name=self._model_name,

            temperature=self._temperature,

            duration_seconds=duration,

            attempts=attempts,

            incident_count=len(
                prioritized_incidents
            ),
        )

    # -----------------------------------------------------

    def _build_prompt(
        self,
        prioritized_incidents,
    ):

        try:

            return self._prompt_builder.build(
                prioritized_incidents
            )

        except Exception as error:

            raise MitrePromptError(
                f"Prompt construction failed: {error}"
            )

    # -----------------------------------------------------

    def _call_with_retries(
        self,
        prompt: str,
    ):

        current_prompt = prompt

        last_response = ""

        for attempt in range(
            1,
            self._max_retries + 2,
        ):

            response = self._call_model(
                current_prompt
            )

            last_response = response

            try:

                self._validator.validate(
                    response
                )

                return response, attempt

            except MitreValidationError as error:

                if attempt == self._max_retries + 1:
                    break

                current_prompt = (
                    self._retry_prompt(
                        prompt,
                        response,
                        error,
                    )
                )

        return last_response, self._max_retries + 1

    # -----------------------------------------------------

    @staticmethod
    def _retry_prompt(
        original_prompt,
        previous_response,
        error,
    ):

        return "\n\n".join(

            [

                original_prompt,

                "# CORRECTION REQUIRED",

                str(error),

                "",

                "Return ONLY valid JSON.",

                previous_response,

            ]
        )

    # -----------------------------------------------------

    def _call_model(
        self,
        prompt: str,
    ) -> str:

        api_key = os.getenv(
            "GEMINI_API_KEY"
        )

        if not api_key:

            raise MitreModelError(
                "Missing GEMINI_API_KEY."
            )

        client = genai.Client(
            api_key=api_key
        )

        try:

            response = (
                client.models.generate_content(
                    model=self._model_name,
                    contents=prompt,
                )
            )

            if not response.text:

                raise MitreModelError(
                    "Gemini returned an empty response."
                )

            return response.text

        except Exception as error:

            raise MitreModelError(
                f"Gemini API error: {error}"
            ) from error