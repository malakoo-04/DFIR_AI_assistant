"""Prompt -> local model boundary for the Investigation Analysis Agent."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

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
    """Raised when the local model backend fails to produce a response."""


class InvestigationAnalysisAgent:
    """Send ONE deterministic, whole-investigation prompt to the local

    model and return its raw response, wrapped with call metadata.
    """

    def __init__(
        self,
        prompt_builder: InvestigationAnalysisPromptBuilder | None = None,
        model_name: str = "qwen2.5:14b",
        temperature: float = 0.0,
        ollama_host: str = "http://localhost:11434",
        timeout_seconds: float = 600.0,
        keep_alive: str | int = "30m",
    ):
        self._prompt_builder = prompt_builder or InvestigationAnalysisPromptBuilder()
        self._model_name = model_name
        self._temperature = temperature
        self._ollama_host = ollama_host
        self._timeout_seconds = timeout_seconds
        self._keep_alive = keep_alive

    def analyze(
        self,
        prioritized_incidents: list[dict],
        timeline: list[dict],
        inventory_context: list[dict],
        attack_chain: list[dict] | dict | None = None,
    ) -> InvestigationLLMResponse:
        """Build the investigation-wide prompt and return the model's response."""
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

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_inputs(
        prioritized_incidents: list[dict],
        timeline: list[dict],
        inventory_context: list[dict],
    ) -> None:
        if not isinstance(prioritized_incidents, list):
            raise InvestigationAnalysisInputError(
                "prioritized_incidents must be a list, got "
                f"{type(prioritized_incidents).__name__}"
            )

        if not isinstance(timeline, list):
            raise InvestigationAnalysisInputError(
                f"timeline must be a list, got {type(timeline).__name__}"
            )

        if not isinstance(inventory_context, list):
            raise InvestigationAnalysisInputError(
                "inventory_context must be a list, got "
                f"{type(inventory_context).__name__}"
            )

    # ------------------------------------------------------------------
    # Prompt construction
    # ------------------------------------------------------------------

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
        except InvestigationAnalysisError:
            raise
        except Exception as error:
            raise InvestigationAnalysisPromptError(
                f"Failed to build investigation analysis prompt: {error}"
            ) from error

    # ------------------------------------------------------------------
    # Model invocation
    # ------------------------------------------------------------------

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
        payload = json.dumps(
            {
                "model": self._model_name,
                "prompt": prompt,
                "stream": True,
                "keep_alive": self._keep_alive,
                "options": {
                    "temperature": self._temperature,
                },
            }
        ).encode("utf-8")

        request = urllib.request.Request(
            f"{self._ollama_host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request, timeout=self._timeout_seconds
            ) as response:
                return self._consume_stream(response)
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            raise InvestigationAnalysisModelError(
                f"HTTP {error.code}\n\n{body}"
            ) from error
        except urllib.error.URLError as error:
            raise InvestigationAnalysisModelError(
                f"Could not reach Ollama at {self._ollama_host}: {error}"
            ) from error
        except TimeoutError as error:
            raise InvestigationAnalysisModelError(
                f"Ollama produced no new output for over "
                f"{self._timeout_seconds:.0f}s (idle timeout): {error}"
            ) from error
        except Exception as error:
            raise InvestigationAnalysisModelError(
                f"Failed during request to Ollama: {error}"
            ) from error

    def _consume_stream(self, response) -> str:
        chunks: list[str] = []
        saw_done = False

        for raw_line in response:
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue

            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as error:
                raise InvestigationAnalysisModelError(
                    f"Ollama streamed a non-JSON line: {error}"
                ) from error

            if "error" in parsed:
                raise InvestigationAnalysisModelError(
                    f"Ollama returned an error for model '{self._model_name}': "
                    f"{parsed['error']} (is it pulled? try `ollama pull {self._model_name}`)"
                )

            chunks.append(parsed.get("response", ""))

            if parsed.get("done"):
                saw_done = True
                break

        if not saw_done:
            raise InvestigationAnalysisModelError(
                "Ollama's stream ended without a final done=true message -- "
                "the connection was likely closed early."
            )

        return "".join(chunks)