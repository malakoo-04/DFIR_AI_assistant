"""Prompt -> local/cloud model boundary for the Investigation Analysis Agent."""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass

from dotenv import load_dotenv
from google import genai

load_dotenv()
from modules.llm.investigation_analysis_prompt_builder import (
    InvestigationAnalysisPromptBuilder,
)


@dataclass(slots=True, frozen=True)
class InvestigationLLMResponse:
    """The complete result of the single, whole-investigation model call."""

    text: str
    prompt: str
    model_name: str
    temperature: float
    duration_seconds: float
    incident_count: int
    detailed_incident_count: int


class InvestigationAnalysisError(Exception):
    """Base class for every error raised by InvestigationAnalysisAgent."""


class InvestigationAnalysisInputError(InvestigationAnalysisError):
    """Raised when the input context is not of the expected shape."""


class InvestigationAnalysisPromptError(InvestigationAnalysisError):
    """Raised when InvestigationAnalysisPromptBuilder fails to build a prompt."""


class InvestigationAnalysisModelError(InvestigationAnalysisError):
    """Raised when the model backend fails to produce a response."""


class InvestigationAnalysisAgent:
    """Send ONE deterministic, whole-investigation prompt to the model."""

    def __init__(
        self,
        prompt_builder: InvestigationAnalysisPromptBuilder | None = None,
        model_name: str ="gemini-3.5-flash",
        temperature: float = 0.0,
    ):
        self._prompt_builder = prompt_builder or InvestigationAnalysisPromptBuilder()
        self._model_name = model_name
        self._temperature = temperature

    def analyze(
        self,
        prioritized_incidents: list[dict],
        timeline: list[dict],
        inventory_context: list[dict],
        attack_chain: list[dict] | dict | None = None,
    ) -> InvestigationLLMResponse:
        self._validate_inputs(prioritized_incidents, timeline, inventory_context)

        prompt = self._build_prompt(
            prioritized_incidents, timeline, inventory_context, attack_chain
        )

        response = self._execute_model(prompt)

        detailed, _summarized, _noise = self._prompt_builder._tier(prioritized_incidents)

        return InvestigationLLMResponse(
            text=response.text,
            prompt=response.prompt,
            model_name=response.model_name,
            temperature=response.temperature,
            duration_seconds=response.duration_seconds,
            incident_count=len(prioritized_incidents),
            detailed_incident_count=len(detailed),
        )

    @staticmethod
    def _validate_inputs(
        prioritized_incidents: list[dict],
        timeline: list[dict],
        inventory_context: list[dict],
    ) -> None:
        if not isinstance(prioritized_incidents, list):
            raise InvestigationAnalysisInputError("prioritized_incidents must be a list")
        if not isinstance(timeline, list):
            raise InvestigationAnalysisInputError("timeline must be a list")
        if not isinstance(inventory_context, list):
            raise InvestigationAnalysisInputError("inventory_context must be a list")

    def _build_prompt(
        self,
        prioritized_incidents: list[dict],
        timeline: list[dict],
        inventory_context: list[dict],
        attack_chain: list[dict] | dict | None = None,
    ) -> str:
        try:
            return self._prompt_builder.build(
                prioritized_incidents, timeline, inventory_context, attack_chain
            )
        except Exception as error:
            raise InvestigationAnalysisPromptError(
                f"Failed to build prompt: {error}"
            ) from error

    @dataclass(slots=True, frozen=True)
    class _RawResponse:
        text: str
        prompt: str
        model_name: str
        temperature: float
        duration_seconds: float

    def _execute_model(self, prompt: str) -> "_RawResponse":
        with open("investigation_prompt.txt", "w", encoding="utf-8") as file:
            file.write(prompt)

        start = time.perf_counter()
        text = self._call_model(prompt)
        duration_seconds = time.perf_counter() - start

        return self._RawResponse(
            text=text,
            prompt=prompt,
            model_name=self._model_name,
            temperature=self._temperature,
            duration_seconds=duration_seconds,
        )

    def _call_model(self, prompt: str) -> str:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise InvestigationAnalysisModelError("GEMINI_API_KEY not found in .env")

        model = os.getenv("GEMINI_MODEL", self._model_name)
        client = genai.Client(api_key=api_key)

        for attempt in range(5):
            try:
                response = client.models.generate_content(
                    model=model,
                    contents=prompt,
                )

                if not response.text:
                    raise InvestigationAnalysisModelError("Gemini returned an empty response.")

                return response.text

            except Exception as error:
                error_str = str(error)
                if "503" in error_str or "UNAVAILABLE" in error_str.upper():
                    if attempt < 4:
                        time.sleep(15)
                        continue
                raise InvestigationAnalysisModelError(
                    f"Gemini API error: {error}"
                ) from error

        raise InvestigationAnalysisModelError("Gemini API call failed after max retries.")